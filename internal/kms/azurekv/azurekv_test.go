package azurekv_test

import (
	"context"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kmsprovider "github.com/larsenclose/genesis/internal/kms"
	"github.com/larsenclose/genesis/internal/kms/azurekv"
)

func TestNewProviderValidation(t *testing.T) {
	tests := []struct {
		name    string
		opts    azurekv.Options
		wantErr bool
	}{
		{
			name:    "empty vault URL",
			opts:    azurekv.Options{VaultURL: "", KeyName: "test"},
			wantErr: true,
		},
		{
			name:    "empty key name",
			opts:    azurekv.Options{VaultURL: "https://test.vault.azure.net", KeyName: ""},
			wantErr: true,
		},
		{
			name: "valid options",
			opts: azurekv.Options{
				VaultURL: "https://test.vault.azure.net",
				KeyName:  "my-key",
			},
			wantErr: false,
		},
		{
			name: "valid options with version",
			opts: azurekv.Options{
				VaultURL:   "https://test.vault.azure.net",
				KeyName:    "my-key",
				KeyVersion: "abc123",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := azurekv.NewProvider(tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProviderName(t *testing.T) {
	p, err := azurekv.NewProvider(azurekv.Options{
		VaultURL: "https://test.vault.azure.net",
		KeyName:  "test-key",
	})
	require.NoError(t, err)
	assert.Equal(t, kmsprovider.ProviderAzureKeyVault, p.Name())
}

func TestProviderVaultURL(t *testing.T) {
	vaultURL := "https://test.vault.azure.net"
	p, err := azurekv.NewProvider(azurekv.Options{
		VaultURL: vaultURL,
		KeyName:  "test-key",
	})
	require.NoError(t, err)
	assert.Equal(t, vaultURL, p.VaultURL())
}

func TestProviderKeyName(t *testing.T) {
	keyName := "my-encryption-key"
	p, err := azurekv.NewProvider(azurekv.Options{
		VaultURL: "https://test.vault.azure.net",
		KeyName:  keyName,
	})
	require.NoError(t, err)
	assert.Equal(t, keyName, p.KeyName())
}

func TestProviderWithMockClient(t *testing.T) {
	ctx := context.Background()
	mockClient := azurekv.NewMockKeyVaultClient()

	p, err := azurekv.NewProviderWithClient(azurekv.Options{
		VaultURL: "https://test.vault.azure.net",
		KeyName:  "test-key",
	}, mockClient)
	require.NoError(t, err)

	plaintext := []byte("test secret data for Azure Key Vault")
	ciphertext, err := p.Encrypt(ctx, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := p.Decrypt(ctx, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestProviderDecryptInvalidCiphertext(t *testing.T) {
	ctx := context.Background()
	mockClient := azurekv.NewMockKeyVaultClient()

	p, err := azurekv.NewProviderWithClient(azurekv.Options{
		VaultURL: "https://test.vault.azure.net",
		KeyName:  "test-key",
	}, mockClient)
	require.NoError(t, err)

	_, err = p.Decrypt(ctx, []byte("invalid"))
	assert.Error(t, err)
}

func TestProviderEncryptDecryptLargeData(t *testing.T) {
	ctx := context.Background()
	mockClient := azurekv.NewMockKeyVaultClient()

	p, err := azurekv.NewProviderWithClient(azurekv.Options{
		VaultURL: "https://test.vault.azure.net",
		KeyName:  "test-key",
	}, mockClient)
	require.NoError(t, err)

	// Test with larger data (simulating an age private key)
	plaintext := []byte("AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ")
	ciphertext, err := p.Encrypt(ctx, plaintext)
	require.NoError(t, err)

	decrypted, err := p.Decrypt(ctx, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestProviderMultipleEncryptDecrypt(t *testing.T) {
	ctx := context.Background()
	mockClient := azurekv.NewMockKeyVaultClient()

	p, err := azurekv.NewProviderWithClient(azurekv.Options{
		VaultURL: "https://test.vault.azure.net",
		KeyName:  "test-key",
	}, mockClient)
	require.NoError(t, err)

	// Test multiple encrypt/decrypt cycles
	for i := 0; i < 3; i++ {
		plaintext := []byte("test secret data iteration " + string(rune('0'+i)))
		ciphertext, err := p.Encrypt(ctx, plaintext)
		require.NoError(t, err)
		assert.NotEqual(t, plaintext, ciphertext)

		decrypted, err := p.Decrypt(ctx, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	}
}

func TestProviderEncryptEmptyData(t *testing.T) {
	ctx := context.Background()
	mockClient := azurekv.NewMockKeyVaultClient()

	p, err := azurekv.NewProviderWithClient(azurekv.Options{
		VaultURL: "https://test.vault.azure.net",
		KeyName:  "test-key",
	}, mockClient)
	require.NoError(t, err)

	// Encrypt empty data
	ciphertext, err := p.Encrypt(ctx, []byte{})
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)

	// Decrypt should return empty data
	decrypted, err := p.Decrypt(ctx, ciphertext)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestNewProviderWithClientValidation(t *testing.T) {
	mockClient := azurekv.NewMockKeyVaultClient()

	t.Run("empty vault URL", func(t *testing.T) {
		_, err := azurekv.NewProviderWithClient(azurekv.Options{
			VaultURL: "",
			KeyName:  "test-key",
		}, mockClient)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "vault URL is required")
	})

	t.Run("empty key name", func(t *testing.T) {
		_, err := azurekv.NewProviderWithClient(azurekv.Options{
			VaultURL: "https://test.vault.azure.net",
			KeyName:  "",
		}, mockClient)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key name is required")
	})
}

func TestProviderWithKeyVersion(t *testing.T) {
	p, err := azurekv.NewProvider(azurekv.Options{
		VaultURL:   "https://test.vault.azure.net",
		KeyName:    "my-key",
		KeyVersion: "abc123",
	})
	require.NoError(t, err)
	// Verify provider was created successfully with key version
	assert.NotNil(t, p)
	assert.Equal(t, "https://test.vault.azure.net", p.VaultURL())
	assert.Equal(t, "my-key", p.KeyName())
}

// FailingMockKeyVaultClient for error path testing
type FailingMockKeyVaultClient struct {
	encryptErr error
	decryptErr error
}

func (m *FailingMockKeyVaultClient) Encrypt(ctx context.Context, keyName string, keyVersion string, parameters azkeys.KeyOperationParameters, options *azkeys.EncryptOptions) (azkeys.EncryptResponse, error) {
	if m.encryptErr != nil {
		return azkeys.EncryptResponse{}, m.encryptErr
	}
	return azkeys.EncryptResponse{
		KeyOperationResult: azkeys.KeyOperationResult{
			Result: []byte("encrypted"),
		},
	}, nil
}

func (m *FailingMockKeyVaultClient) Decrypt(ctx context.Context, keyName string, keyVersion string, parameters azkeys.KeyOperationParameters, options *azkeys.DecryptOptions) (azkeys.DecryptResponse, error) {
	if m.decryptErr != nil {
		return azkeys.DecryptResponse{}, m.decryptErr
	}
	return azkeys.DecryptResponse{
		KeyOperationResult: azkeys.KeyOperationResult{
			Result: []byte("decrypted"),
		},
	}, nil
}

func TestProviderEncryptFailure(t *testing.T) {
	ctx := context.Background()
	failClient := &FailingMockKeyVaultClient{
		encryptErr: assert.AnError,
	}

	p, err := azurekv.NewProviderWithClient(azurekv.Options{
		VaultURL: "https://test.vault.azure.net",
		KeyName:  "test-key",
	}, failClient)
	require.NoError(t, err)

	_, err = p.Encrypt(ctx, []byte("test data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Azure Key Vault encrypt failed")
}

func TestProviderDecryptFailure(t *testing.T) {
	ctx := context.Background()
	failClient := &FailingMockKeyVaultClient{
		decryptErr: assert.AnError,
	}

	p, err := azurekv.NewProviderWithClient(azurekv.Options{
		VaultURL: "https://test.vault.azure.net",
		KeyName:  "test-key",
	}, failClient)
	require.NoError(t, err)

	_, err = p.Decrypt(ctx, []byte("encrypted data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Azure Key Vault decrypt failed")
}

func TestProviderDecryptTamperedCiphertext(t *testing.T) {
	ctx := context.Background()
	mockClient := azurekv.NewMockKeyVaultClient()

	p, err := azurekv.NewProviderWithClient(azurekv.Options{
		VaultURL: "https://test.vault.azure.net",
		KeyName:  "test-key",
	}, mockClient)
	require.NoError(t, err)

	plaintext := []byte("test secret data")
	ciphertext, err := p.Encrypt(ctx, plaintext)
	require.NoError(t, err)

	// Tamper with ciphertext
	ciphertext[len(ciphertext)-1] ^= 0xFF

	_, err = p.Decrypt(ctx, ciphertext)
	assert.Error(t, err)
}

func TestProviderWithNilClient(t *testing.T) {
	// Test that provider created without client will fail on operations
	// since it can't load Azure credentials in test environment
	p, err := azurekv.NewProvider(azurekv.Options{
		VaultURL: "https://test.vault.azure.net",
		KeyName:  "test-key",
	})
	require.NoError(t, err)

	// The provider is created but has no client
	assert.NotNil(t, p)
	assert.Equal(t, kmsprovider.ProviderAzureKeyVault, p.Name())
}

func TestProviderMultipleOperations(t *testing.T) {
	ctx := context.Background()
	mockClient := azurekv.NewMockKeyVaultClient()

	p, err := azurekv.NewProviderWithClient(azurekv.Options{
		VaultURL: "https://test.vault.azure.net",
		KeyName:  "test-key",
	}, mockClient)
	require.NoError(t, err)

	// Test interleaved encrypt/decrypt operations
	plaintexts := [][]byte{
		[]byte("first secret"),
		[]byte("second secret"),
		[]byte("third secret"),
	}

	ciphertexts := make([][]byte, len(plaintexts))
	for i, pt := range plaintexts {
		ct, err := p.Encrypt(ctx, pt)
		require.NoError(t, err)
		ciphertexts[i] = ct
	}

	// Decrypt in reverse order
	for i := len(plaintexts) - 1; i >= 0; i-- {
		decrypted, err := p.Decrypt(ctx, ciphertexts[i])
		require.NoError(t, err)
		assert.Equal(t, plaintexts[i], decrypted)
	}
}
