package yubikey

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// MockPIVClient is a mock implementation of PIVClient for testing
type MockPIVClient struct {
	key         []byte
	fingerprint string
}

// mockFallbackKey is used if random generation fails (extremely rare, only in tests).
var mockFallbackKey = []byte("yubikey-mock-fallback-key-32b!!")

// NewMockPIVClient creates a new mock PIV client
func NewMockPIVClient() *MockPIVClient {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		// Use deterministic fallback key for testing; random failure is extremely rare
		copy(key, mockFallbackKey)
	}

	// Generate a mock fingerprint
	hash := sha256.Sum256(key)
	fingerprint := "SHA256:" + hex.EncodeToString(hash[:])

	return &MockPIVClient{
		key:         key,
		fingerprint: fingerprint,
	}
}

// NewMockPIVClientWithFingerprint creates a mock PIV client with a specific fingerprint
func NewMockPIVClientWithFingerprint(fingerprint string) *MockPIVClient {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		// Use deterministic fallback key for testing; random failure is extremely rare
		copy(key, mockFallbackKey)
	}

	return &MockPIVClient{
		key:         key,
		fingerprint: fingerprint,
	}
}

// Encrypt implements the PIVClient interface
func (m *MockPIVClient) Encrypt(ctx context.Context, slot PIVSlot, plaintext []byte) ([]byte, error) {
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

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt implements the PIVClient interface
func (m *MockPIVClient) Decrypt(ctx context.Context, slot PIVSlot, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// GetPublicKeyFingerprint implements the PIVClient interface
func (m *MockPIVClient) GetPublicKeyFingerprint(ctx context.Context, slot PIVSlot) (string, error) {
	return m.fingerprint, nil
}

// Close implements the PIVClient interface
func (m *MockPIVClient) Close() error {
	return nil
}
