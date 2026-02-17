package crypto_test

import (
	"testing"

	"github.com/larsenclose/genesis/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateAgeKeypair(t *testing.T) {
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)
	assert.NotEmpty(t, kp.PrivateKey)
	assert.NotEmpty(t, kp.PublicKey)
	assert.True(t, crypto.IsValidAgePrivateKey(kp.PrivateKey))
	assert.True(t, crypto.IsValidAgePublicKey(kp.PublicKey))
}

func TestAgeKeypairFormat(t *testing.T) {
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)
	assert.Contains(t, kp.PrivateKey, "AGE-SECRET-KEY-1")
	assert.Contains(t, kp.PublicKey, "age1")
}

func TestAgeEncryptDecrypt(t *testing.T) {
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	plaintext := []byte("secret data for testing")
	ciphertext, err := crypto.AgeEncrypt(plaintext, kp.PublicKey)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := crypto.AgeDecrypt(ciphertext, kp.PrivateKey)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAgeEncryptWithInvalidPublicKey(t *testing.T) {
	_, err := crypto.AgeEncrypt([]byte("test"), "invalid-key")
	assert.Error(t, err)
}

func TestAgeDecryptWithInvalidPrivateKey(t *testing.T) {
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	ciphertext, err := crypto.AgeEncrypt([]byte("test"), kp.PublicKey)
	require.NoError(t, err)

	_, err = crypto.AgeDecrypt(ciphertext, "invalid-key")
	assert.Error(t, err)
}

func TestAgeDecryptWithWrongKey(t *testing.T) {
	kp1, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)
	kp2, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	ciphertext, err := crypto.AgeEncrypt([]byte("test"), kp1.PublicKey)
	require.NoError(t, err)

	_, err = crypto.AgeDecrypt(ciphertext, kp2.PrivateKey)
	assert.Error(t, err)
}

func TestIsValidAgePrivateKey(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		valid bool
	}{
		{"valid key", "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ", false},
		{"empty", "", false},
		{"wrong prefix", "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", false},
	}

	kp, _ := crypto.GenerateAgeKeypair()
	tests = append(tests, struct {
		name  string
		key   string
		valid bool
	}{"generated key", kp.PrivateKey, true})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, crypto.IsValidAgePrivateKey(tt.key))
		})
	}
}

func TestIsValidAgePublicKey(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		valid bool
	}{
		{"empty", "", false},
		{"wrong prefix", "AGE-SECRET-KEY-1QQQQQ", false},
	}

	kp, _ := crypto.GenerateAgeKeypair()
	tests = append(tests, struct {
		name  string
		key   string
		valid bool
	}{"generated key", kp.PublicKey, true})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, crypto.IsValidAgePublicKey(tt.key))
		})
	}
}

func TestParseAgeKeypair(t *testing.T) {
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	parsed, err := crypto.ParseAgeKeypair(kp.PrivateKey)
	require.NoError(t, err)
	assert.Equal(t, kp.PrivateKey, parsed.PrivateKey)
	assert.Equal(t, kp.PublicKey, parsed.PublicKey)
}

func TestParseAgeKeypairInvalid(t *testing.T) {
	_, err := crypto.ParseAgeKeypair("invalid")
	assert.Error(t, err)
}
