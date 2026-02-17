package gcpkms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// MockKMSClient is a mock implementation of KMSClient for testing
type MockKMSClient struct {
	key []byte
}

// mockFallbackKey is used if random generation fails (extremely rare, only in tests).
var mockFallbackKey = []byte("gcp-kms-mock-fallback-key-32-by!")

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
func (m *MockKMSClient) Encrypt(ctx context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, req.Plaintext, nil)
	ciphertextCRC32C := CRC32Checksum(ciphertext)

	return &kmspb.EncryptResponse{
		Ciphertext:              ciphertext,
		CiphertextCrc32C:        wrapperspb.Int64(int64(ciphertextCRC32C)),
		VerifiedPlaintextCrc32C: true,
	}, nil
}

// Decrypt implements the KMSClient interface
func (m *MockKMSClient) Decrypt(ctx context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(req.Ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := req.Ciphertext[:gcm.NonceSize()]
	ciphertext := req.Ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	plaintextCRC32C := CRC32Checksum(plaintext)

	return &kmspb.DecryptResponse{
		Plaintext:       plaintext,
		PlaintextCrc32C: wrapperspb.Int64(int64(plaintextCRC32C)),
	}, nil
}

// Close implements the KMSClient interface
func (m *MockKMSClient) Close() error {
	return nil
}
