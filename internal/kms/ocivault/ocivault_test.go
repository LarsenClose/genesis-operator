package ocivault_test

import (
	"context"
	"testing"

	"github.com/larsenclose/genesis/internal/kms"
	"github.com/larsenclose/genesis/internal/kms/ocivault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProvider(t *testing.T) {
	tests := []struct {
		name    string
		opts    ocivault.Options
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid options with crypto endpoint",
			opts: ocivault.Options{
				KeyOCID:        "ocid1.key.oc1.us-phoenix-1.abcdefghijk",
				CryptoEndpoint: "https://abc123-crypto.kms.us-phoenix-1.oraclecloud.com",
			},
			wantErr: false,
		},
		{
			name: "missing key OCID",
			opts: ocivault.Options{
				CryptoEndpoint: "https://abc123-crypto.kms.us-phoenix-1.oraclecloud.com",
			},
			wantErr: true,
			errMsg:  "key OCID is required",
		},
		{
			name: "missing crypto endpoint with invalid OCID",
			opts: ocivault.Options{
				KeyOCID: "invalid-ocid",
			},
			wantErr: true,
			errMsg:  "crypto endpoint is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := ocivault.NewProvider(tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
			}
		})
	}
}

func TestProviderName(t *testing.T) {
	mockClient := ocivault.NewMockKMSClient()
	provider, err := ocivault.NewProviderWithClient(ocivault.Options{
		KeyOCID:        "ocid1.key.oc1.us-phoenix-1.abcdefghijk",
		CryptoEndpoint: "https://test-crypto.kms.us-phoenix-1.oraclecloud.com",
	}, mockClient)
	require.NoError(t, err)

	assert.Equal(t, kms.ProviderOCIVault, provider.Name())
}

func TestProviderKeyOCID(t *testing.T) {
	keyOCID := "ocid1.key.oc1.us-phoenix-1.abcdefghijk"
	mockClient := ocivault.NewMockKMSClient()
	provider, err := ocivault.NewProviderWithClient(ocivault.Options{
		KeyOCID:        keyOCID,
		CryptoEndpoint: "https://test-crypto.kms.us-phoenix-1.oraclecloud.com",
	}, mockClient)
	require.NoError(t, err)

	assert.Equal(t, keyOCID, provider.KeyOCID())
}

func TestProviderCryptoEndpoint(t *testing.T) {
	endpoint := "https://test-crypto.kms.us-phoenix-1.oraclecloud.com"
	mockClient := ocivault.NewMockKMSClient()
	provider, err := ocivault.NewProviderWithClient(ocivault.Options{
		KeyOCID:        "ocid1.key.oc1.us-phoenix-1.abcdefghijk",
		CryptoEndpoint: endpoint,
	}, mockClient)
	require.NoError(t, err)

	assert.Equal(t, endpoint, provider.CryptoEndpoint())
}

func TestEncryptDecrypt(t *testing.T) {
	ctx := context.Background()
	mockClient := ocivault.NewMockKMSClient()

	provider, err := ocivault.NewProviderWithClient(ocivault.Options{
		KeyOCID:        "ocid1.key.oc1.us-phoenix-1.abcdefghijk",
		CryptoEndpoint: "https://test-crypto.kms.us-phoenix-1.oraclecloud.com",
	}, mockClient)
	require.NoError(t, err)

	plaintext := []byte("secret age private key data for testing")

	// Encrypt
	ciphertext, err := provider.Encrypt(ctx, plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
	assert.NotEqual(t, plaintext, ciphertext)

	// Decrypt
	decrypted, err := provider.Decrypt(ctx, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestDecryptInvalidCiphertext(t *testing.T) {
	ctx := context.Background()
	mockClient := ocivault.NewMockKMSClient()

	provider, err := ocivault.NewProviderWithClient(ocivault.Options{
		KeyOCID:        "ocid1.key.oc1.us-phoenix-1.abcdefghijk",
		CryptoEndpoint: "https://test-crypto.kms.us-phoenix-1.oraclecloud.com",
	}, mockClient)
	require.NoError(t, err)

	// Try to decrypt invalid ciphertext
	_, err = provider.Decrypt(ctx, []byte("invalid ciphertext"))
	assert.Error(t, err)
}

func TestEncryptLargePayload(t *testing.T) {
	ctx := context.Background()
	mockClient := ocivault.NewMockKMSClient()

	provider, err := ocivault.NewProviderWithClient(ocivault.Options{
		KeyOCID:        "ocid1.key.oc1.us-phoenix-1.abcdefghijk",
		CryptoEndpoint: "https://test-crypto.kms.us-phoenix-1.oraclecloud.com",
	}, mockClient)
	require.NoError(t, err)

	// Age private keys are typically around 70-80 bytes, but test with larger payload
	plaintext := make([]byte, 1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := provider.Encrypt(ctx, plaintext)
	require.NoError(t, err)

	decrypted, err := provider.Decrypt(ctx, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestNewProviderWithClientNilClient(t *testing.T) {
	// Should still work - client will be nil until first operation
	provider, err := ocivault.NewProviderWithClient(ocivault.Options{
		KeyOCID:        "ocid1.key.oc1.us-phoenix-1.abcdefghijk",
		CryptoEndpoint: "https://test-crypto.kms.us-phoenix-1.oraclecloud.com",
	}, nil)
	require.NoError(t, err)
	assert.NotNil(t, provider)
}
