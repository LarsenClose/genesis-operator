package ocivault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
)

// mockFallbackKey is used if random generation fails (extremely rare, only in tests).
var mockFallbackKey = []byte("oci-vault-mock-fallback-key-32b!")

// MockKMSClient is a mock implementation of KMSClient for testing
type MockKMSClient struct {
	key []byte
}

// NewMockKMSClient creates a new mock KMS client
func NewMockKMSClient() *MockKMSClient {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		// Use deterministic fallback key for testing; random failure is extremely rare
		copy(key, mockFallbackKey)
	}
	return &MockKMSClient{key: key}
}

// Encrypt implements the KMSClient interface
func (m *MockKMSClient) Encrypt(ctx context.Context, request keymanagement.EncryptRequest) (keymanagement.EncryptResponse, error) {
	if request.Plaintext == nil {
		return keymanagement.EncryptResponse{}, errors.New("plaintext is required")
	}

	// Decode the base64 plaintext (OCI SDK sends base64-encoded data)
	plaintext, err := base64.StdEncoding.DecodeString(*request.Plaintext)
	if err != nil {
		return keymanagement.EncryptResponse{}, fmt.Errorf("failed to decode plaintext: %w", err)
	}

	block, err := aes.NewCipher(m.key)
	if err != nil {
		return keymanagement.EncryptResponse{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return keymanagement.EncryptResponse{}, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return keymanagement.EncryptResponse{}, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	// OCI returns base64-encoded ciphertext
	encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)

	return keymanagement.EncryptResponse{
		EncryptedData: keymanagement.EncryptedData{
			Ciphertext: common.String(encodedCiphertext),
		},
	}, nil
}

// Decrypt implements the KMSClient interface
func (m *MockKMSClient) Decrypt(ctx context.Context, request keymanagement.DecryptRequest) (keymanagement.DecryptResponse, error) {
	if request.Ciphertext == nil {
		return keymanagement.DecryptResponse{}, errors.New("ciphertext is required")
	}

	// Decode the base64 ciphertext (OCI SDK sends base64-encoded data)
	ciphertext, err := base64.StdEncoding.DecodeString(*request.Ciphertext)
	if err != nil {
		return keymanagement.DecryptResponse{}, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(m.key)
	if err != nil {
		return keymanagement.DecryptResponse{}, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return keymanagement.DecryptResponse{}, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return keymanagement.DecryptResponse{}, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertextData := ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertextData, nil)
	if err != nil {
		return keymanagement.DecryptResponse{}, fmt.Errorf("decryption failed: %w", err)
	}

	// OCI returns base64-encoded plaintext
	encodedPlaintext := base64.StdEncoding.EncodeToString(plaintext)

	return keymanagement.DecryptResponse{
		DecryptedData: keymanagement.DecryptedData{
			Plaintext: common.String(encodedPlaintext),
		},
	}, nil
}
