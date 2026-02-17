package tpm

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// MockTPMClient is a mock implementation of TPMClient for testing
type MockTPMClient struct {
	key       []byte
	pcrValues map[int][]byte
}

// mockFallbackKey is used if random generation fails (extremely rare, only in tests).
var mockFallbackKey = []byte("tpm-mock-fallback-key-32-bytes!")

// NewMockTPMClient creates a new mock TPM client
func NewMockTPMClient() *MockTPMClient {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		// Use deterministic fallback key for testing; random failure is extremely rare
		copy(key, mockFallbackKey)
	}

	// Generate mock PCR values
	pcrValues := make(map[int][]byte)
	for i := 0; i <= 23; i++ {
		hash := sha256.Sum256([]byte(fmt.Sprintf("pcr-%d", i)))
		pcrValues[i] = hash[:]
	}

	return &MockTPMClient{
		key:       key,
		pcrValues: pcrValues,
	}
}

// NewMockTPMClientWithPCRs creates a mock TPM client with specific PCR values
func NewMockTPMClientWithPCRs(pcrValues map[int][]byte) *MockTPMClient {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		// Use deterministic fallback key for testing; random failure is extremely rare
		copy(key, mockFallbackKey)
	}

	return &MockTPMClient{
		key:       key,
		pcrValues: pcrValues,
	}
}

// Seal implements the TPMClient interface
func (m *MockTPMClient) Seal(ctx context.Context, plaintext []byte, pcrSelection *PCRSelection) ([]byte, error) {
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

	// In a real TPM, the PCR values would be part of the sealing policy
	// For the mock, we just encrypt the data
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Unseal implements the TPMClient interface
func (m *MockTPMClient) Unseal(ctx context.Context, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("sealed data too short")
	}

	nonce := sealed[:gcm.NonceSize()]
	ciphertext := sealed[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("unseal failed: %w", err)
	}

	return plaintext, nil
}

// GetPCRValues implements the TPMClient interface
func (m *MockTPMClient) GetPCRValues(ctx context.Context, pcrSelection *PCRSelection) (map[int][]byte, error) {
	result := make(map[int][]byte)
	for _, pcr := range pcrSelection.PCRs {
		if val, ok := m.pcrValues[pcr]; ok {
			result[pcr] = val
		} else {
			return nil, fmt.Errorf("PCR %d not found", pcr)
		}
	}
	return result, nil
}

// Close implements the TPMClient interface
func (m *MockTPMClient) Close() error {
	return nil
}
