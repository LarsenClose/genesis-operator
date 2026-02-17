package mock

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/larsenclose/genesis/internal/kms"
)

// Note: crypto/rand is still used by Encrypt() for nonce generation

type Provider struct {
	key        []byte
	encryptErr error
	decryptErr error
}

// DefaultMockKey is a fixed key used for deterministic mock encryption.
// This is intentionally NOT random to allow integration tests to work
// where the provider is created multiple times independently.
var DefaultMockKey = []byte("genesis-mock-provider-fixed-key!")

func NewProvider() *Provider {
	keyCopy := make([]byte, 32)
	copy(keyCopy, DefaultMockKey)
	return &Provider{key: keyCopy}
}

// NewProviderWithKey creates a provider with a specific key.
// Returns an error if the key is not exactly 32 bytes (AES-256 requirement).
func NewProviderWithKey(key []byte) (*Provider, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes for AES-256, got %d", len(key))
	}
	keyCopy := make([]byte, 32)
	copy(keyCopy, key)
	return &Provider{key: keyCopy}, nil
}

func NewFailingProvider(encryptErr, decryptErr error) *Provider {
	p := NewProvider()
	p.encryptErr = encryptErr
	p.decryptErr = decryptErr
	return p
}

func (p *Provider) Name() kms.ProviderName {
	return kms.ProviderMock
}

func (p *Provider) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	if p.encryptErr != nil {
		return nil, p.encryptErr
	}

	block, err := aes.NewCipher(p.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (p *Provider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if p.decryptErr != nil {
		return nil, p.decryptErr
	}

	block, err := aes.NewCipher(p.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}
