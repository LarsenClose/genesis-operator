package envelope_test

import (
	"context"
	"testing"

	"github.com/larsenclose/genesis/internal/crypto"
	"github.com/larsenclose/genesis/internal/envelope"
	"github.com/larsenclose/genesis/internal/kms/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvelopeCreateAndOpen(t *testing.T) {
	ctx := context.Background()
	provider := mock.NewProvider()
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	env, err := envelope.Create(ctx, provider, kp.PrivateKey)
	require.NoError(t, err)
	assert.NotEmpty(t, env.Ciphertext)
	assert.Equal(t, kp.PublicKey, env.PublicKey)
	assert.Equal(t, provider.Name(), env.Provider)

	privateKey, err := envelope.Open(ctx, provider, env)
	require.NoError(t, err)
	assert.Equal(t, kp.PrivateKey, privateKey)
}

func TestEnvelopeOpenWithWrongProvider(t *testing.T) {
	ctx := context.Background()
	// Use different keys to simulate different providers (must be exactly 32 bytes)
	key1 := []byte("provider1-key-for-testing-32!abc")
	key2 := []byte("provider2-key-for-testing-32!xyz")
	provider1, err := mock.NewProviderWithKey(key1)
	require.NoError(t, err)
	provider2, err := mock.NewProviderWithKey(key2)
	require.NoError(t, err)
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	env, err := envelope.Create(ctx, provider1, kp.PrivateKey)
	require.NoError(t, err)

	_, err = envelope.Open(ctx, provider2, env)
	assert.Error(t, err)
}

func TestEnvelopeOpenWithInvalidCiphertext(t *testing.T) {
	ctx := context.Background()
	provider := mock.NewProvider()

	env := &envelope.Envelope{
		Ciphertext: []byte("invalid"),
		Provider:   provider.Name(),
	}

	_, err := envelope.Open(ctx, provider, env)
	assert.Error(t, err)
}

func TestEnvelopeCreateWithFailingProvider(t *testing.T) {
	ctx := context.Background()
	provider := mock.NewFailingProvider(assert.AnError, nil)
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	_, err = envelope.Create(ctx, provider, kp.PrivateKey)
	assert.Error(t, err)
}

func TestEnvelopeOpenWithFailingProvider(t *testing.T) {
	ctx := context.Background()
	createProvider := mock.NewProvider()
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	env, err := envelope.Create(ctx, createProvider, kp.PrivateKey)
	require.NoError(t, err)

	failProvider := mock.NewFailingProvider(nil, assert.AnError)
	_, err = envelope.Open(ctx, failProvider, env)
	assert.Error(t, err)
}

func TestEnvelopeSerializeDeserialize(t *testing.T) {
	ctx := context.Background()
	provider := mock.NewProvider()
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	env, err := envelope.Create(ctx, provider, kp.PrivateKey)
	require.NoError(t, err)

	data, err := env.MarshalYAML()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	var restored envelope.Envelope
	err = restored.UnmarshalYAML(data)
	require.NoError(t, err)
	assert.Equal(t, env.PublicKey, restored.PublicKey)
	assert.Equal(t, env.Provider, restored.Provider)
	assert.Equal(t, env.Ciphertext, restored.Ciphertext)
}

func TestEnvelopeWithInvalidPrivateKey(t *testing.T) {
	ctx := context.Background()
	provider := mock.NewProvider()

	_, err := envelope.Create(ctx, provider, "invalid-private-key")
	assert.Error(t, err)
}

// Test Open with CiphertextB64 path (when Ciphertext is empty but CiphertextB64 is set)
func TestEnvelopeOpenWithCiphertextB64(t *testing.T) {
	ctx := context.Background()
	provider := mock.NewProvider()
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	// Create envelope normally
	env, err := envelope.Create(ctx, provider, kp.PrivateKey)
	require.NoError(t, err)

	// Create new envelope with only CiphertextB64 set (simulate loaded from file)
	envFromB64 := &envelope.Envelope{
		Provider:      env.Provider,
		PublicKey:     env.PublicKey,
		CiphertextB64: env.CiphertextB64,
		Ciphertext:    nil, // Empty ciphertext, should use B64
	}

	// Open should still work
	privateKey, err := envelope.Open(ctx, provider, envFromB64)
	require.NoError(t, err)
	assert.Equal(t, kp.PrivateKey, privateKey)
}

// Test Open with invalid base64 in CiphertextB64
func TestEnvelopeOpenWithInvalidBase64(t *testing.T) {
	ctx := context.Background()
	provider := mock.NewProvider()

	env := &envelope.Envelope{
		Provider:      provider.Name(),
		PublicKey:     "age1test",
		CiphertextB64: "not-valid-base64!!!",
		Ciphertext:    nil,
	}

	_, err := envelope.Open(ctx, provider, env)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode ciphertext")
}

// Test Open with decrypted content that is not a valid age key
func TestEnvelopeOpenWithInvalidDecryptedContent(t *testing.T) {
	ctx := context.Background()
	provider := mock.NewProvider()

	// Encrypt something that is NOT a valid age key
	invalidContent := "this-is-not-an-age-key"
	ciphertext, err := provider.Encrypt(ctx, []byte(invalidContent))
	require.NoError(t, err)

	env := &envelope.Envelope{
		Provider:   provider.Name(),
		PublicKey:  "age1test",
		Ciphertext: ciphertext,
	}

	_, err = envelope.Open(ctx, provider, env)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a valid age private key")
}

// Test UnmarshalYAML with invalid YAML
func TestEnvelopeUnmarshalYAMLInvalid(t *testing.T) {
	var env envelope.Envelope
	err := env.UnmarshalYAML([]byte("not: valid: yaml: ["))
	assert.Error(t, err)
}

// Test UnmarshalYAML with invalid base64 ciphertext
func TestEnvelopeUnmarshalYAMLInvalidBase64(t *testing.T) {
	var env envelope.Envelope
	yamlData := `provider: mock
publicKey: age1test
ciphertext: "not-valid-base64!!!"`

	err := env.UnmarshalYAML([]byte(yamlData))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode ciphertext")
}

// Test MarshalYAML updates CiphertextB64 from Ciphertext
func TestEnvelopeMarshalYAMLUpdatesCiphertextB64(t *testing.T) {
	ctx := context.Background()
	provider := mock.NewProvider()
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	env, err := envelope.Create(ctx, provider, kp.PrivateKey)
	require.NoError(t, err)

	// Clear CiphertextB64 to verify MarshalYAML regenerates it
	originalB64 := env.CiphertextB64
	env.CiphertextB64 = ""

	data, err := env.MarshalYAML()
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	// After marshal, CiphertextB64 should be populated again
	assert.Equal(t, originalB64, env.CiphertextB64)
}

// Test Envelope with empty Ciphertext and empty CiphertextB64
func TestEnvelopeOpenWithEmptyCiphertext(t *testing.T) {
	ctx := context.Background()
	provider := mock.NewProvider()

	env := &envelope.Envelope{
		Provider:      provider.Name(),
		PublicKey:     "age1test",
		Ciphertext:    nil,
		CiphertextB64: "",
	}

	_, err := envelope.Open(ctx, provider, env)
	assert.Error(t, err)
}

// Test Envelope round-trip through MarshalYAML and UnmarshalYAML
func TestEnvelopeYAMLRoundTrip(t *testing.T) {
	ctx := context.Background()
	provider := mock.NewProvider()
	kp, err := crypto.GenerateAgeKeypair()
	require.NoError(t, err)

	original, err := envelope.Create(ctx, provider, kp.PrivateKey)
	require.NoError(t, err)

	// Marshal
	data, err := original.MarshalYAML()
	require.NoError(t, err)

	// Unmarshal
	var restored envelope.Envelope
	err = restored.UnmarshalYAML(data)
	require.NoError(t, err)

	// Verify all fields match
	assert.Equal(t, original.Provider, restored.Provider)
	assert.Equal(t, original.PublicKey, restored.PublicKey)
	assert.Equal(t, original.CiphertextB64, restored.CiphertextB64)
	assert.Equal(t, original.Ciphertext, restored.Ciphertext)

	// Verify we can still decrypt
	privateKey, err := envelope.Open(ctx, provider, &restored)
	require.NoError(t, err)
	assert.Equal(t, kp.PrivateKey, privateKey)
}
