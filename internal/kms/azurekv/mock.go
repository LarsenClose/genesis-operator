package azurekv

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// MockKeyVaultClient is a mock implementation of KeyVaultClient for testing
type MockKeyVaultClient struct {
	key []byte
}

// mockFallbackKey is used if random generation fails (extremely rare, only in tests).
var mockFallbackKey = []byte("azure-kv-mock-fallback-key-32b!")

// NewMockKeyVaultClient creates a new mock Key Vault client
func NewMockKeyVaultClient() *MockKeyVaultClient {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		// Use deterministic fallback key for testing; random failure is extremely rare
		copy(key, mockFallbackKey)
	}
	return &MockKeyVaultClient{key: key}
}

// Encrypt implements the KeyVaultClient interface
func (m *MockKeyVaultClient) Encrypt(ctx context.Context, keyName string, keyVersion string, parameters azkeys.KeyOperationParameters, options *azkeys.EncryptOptions) (azkeys.EncryptResponse, error) {
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return azkeys.EncryptResponse{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return azkeys.EncryptResponse{}, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return azkeys.EncryptResponse{}, err
	}

	ciphertext := gcm.Seal(nonce, nonce, parameters.Value, nil)

	return azkeys.EncryptResponse{
		KeyOperationResult: azkeys.KeyOperationResult{
			Result: ciphertext,
		},
	}, nil
}

// Decrypt implements the KeyVaultClient interface
func (m *MockKeyVaultClient) Decrypt(ctx context.Context, keyName string, keyVersion string, parameters azkeys.KeyOperationParameters, options *azkeys.DecryptOptions) (azkeys.DecryptResponse, error) {
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return azkeys.DecryptResponse{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return azkeys.DecryptResponse{}, err
	}

	if len(parameters.Value) < gcm.NonceSize() {
		return azkeys.DecryptResponse{}, errors.New("ciphertext too short")
	}

	nonce := parameters.Value[:gcm.NonceSize()]
	ciphertext := parameters.Value[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return azkeys.DecryptResponse{}, fmt.Errorf("decryption failed: %w", err)
	}

	return azkeys.DecryptResponse{
		KeyOperationResult: azkeys.KeyOperationResult{
			Result: plaintext,
		},
	}, nil
}
