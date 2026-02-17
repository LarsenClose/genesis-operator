package awskms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type MockKMSClient struct {
	key []byte
}

// mockFallbackKey is used if random generation fails (extremely rare, only in tests).
var mockFallbackKey = []byte("aws-kms-mock-fallback-key-32-by!")

func NewMockKMSClient() *MockKMSClient {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		// Use deterministic fallback key for testing; random failure is extremely rare
		copy(key, mockFallbackKey)
	}
	return &MockKMSClient{key: key}
}

func (m *MockKMSClient) Encrypt(ctx context.Context, input *kms.EncryptInput, opts ...func(*kms.Options)) (*kms.EncryptOutput, error) {
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

	ciphertext := gcm.Seal(nonce, nonce, input.Plaintext, nil)
	return &kms.EncryptOutput{
		CiphertextBlob: ciphertext,
	}, nil
}

func (m *MockKMSClient) Decrypt(ctx context.Context, input *kms.DecryptInput, opts ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(input.CiphertextBlob) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := input.CiphertextBlob[:gcm.NonceSize()]
	ciphertext := input.CiphertextBlob[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return &kms.DecryptOutput{
		Plaintext: plaintext,
	}, nil
}
