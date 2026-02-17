package kms_test

import (
	"context"
	"testing"

	"github.com/larsenclose/genesis/internal/kms"
	"github.com/larsenclose/genesis/internal/kms/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockProviderEncryptDecrypt(t *testing.T) {
	ctx := context.Background()
	provider := mock.NewProvider()

	plaintext := []byte("secret master key data")
	ciphertext, err := provider.Encrypt(ctx, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := provider.Decrypt(ctx, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestMockProviderDecryptInvalid(t *testing.T) {
	ctx := context.Background()
	provider := mock.NewProvider()

	_, err := provider.Decrypt(ctx, []byte("invalid ciphertext"))
	assert.Error(t, err)
}

func TestMockProviderName(t *testing.T) {
	provider := mock.NewProvider()
	assert.Equal(t, kms.ProviderMock, provider.Name())
}

func TestMockProviderWithInjectedKey(t *testing.T) {
	ctx := context.Background()
	key := []byte("0123456789abcdef0123456789abcdef")
	provider, err := mock.NewProviderWithKey(key)
	require.NoError(t, err)

	plaintext := []byte("test data")
	ciphertext, err := provider.Encrypt(ctx, plaintext)
	require.NoError(t, err)

	decrypted, err := provider.Decrypt(ctx, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestMockProviderFailingEncrypt(t *testing.T) {
	ctx := context.Background()
	provider := mock.NewFailingProvider(assert.AnError, nil)

	_, err := provider.Encrypt(ctx, []byte("test"))
	assert.Error(t, err)
}

func TestMockProviderFailingDecrypt(t *testing.T) {
	ctx := context.Background()
	provider := mock.NewFailingProvider(nil, assert.AnError)

	ciphertext, err := provider.Encrypt(ctx, []byte("test"))
	require.NoError(t, err)

	_, err = provider.Decrypt(ctx, ciphertext)
	assert.Error(t, err)
}

func TestMockProviderWithInvalidKeyLength(t *testing.T) {
	// Test keys that are not 32 bytes
	_, err := mock.NewProviderWithKey([]byte("short"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be 32 bytes")

	_, err = mock.NewProviderWithKey([]byte("this-key-is-too-long-for-aes-256-and-should-fail"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be 32 bytes")
}

func TestProviderRegistry(t *testing.T) {
	registry := kms.NewRegistry()

	assert.Nil(t, registry.Get(kms.ProviderMock))

	mockProvider := mock.NewProvider()
	registry.Register(mockProvider)

	got := registry.Get(kms.ProviderMock)
	assert.NotNil(t, got)
	assert.Equal(t, kms.ProviderMock, got.Name())
}

func TestProviderRegistryList(t *testing.T) {
	registry := kms.NewRegistry()
	assert.Empty(t, registry.List())

	registry.Register(mock.NewProvider())
	providers := registry.List()
	assert.Len(t, providers, 1)
	assert.Contains(t, providers, kms.ProviderMock)
}
