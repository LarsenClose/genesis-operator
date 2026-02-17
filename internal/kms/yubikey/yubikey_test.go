package yubikey_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kmsprovider "github.com/larsenclose/genesis/internal/kms"
	"github.com/larsenclose/genesis/internal/kms/yubikey"
)

func TestNewProviderValidation(t *testing.T) {
	tests := []struct {
		name    string
		opts    yubikey.Options
		wantErr bool
	}{
		{
			name:    "default slot",
			opts:    yubikey.Options{},
			wantErr: false,
		},
		{
			name:    "valid slot 9a",
			opts:    yubikey.Options{Slot: "9a"},
			wantErr: false,
		},
		{
			name:    "valid slot 9c",
			opts:    yubikey.Options{Slot: "9c"},
			wantErr: false,
		},
		{
			name:    "valid slot 9d",
			opts:    yubikey.Options{Slot: "9d"},
			wantErr: false,
		},
		{
			name:    "valid slot 9e",
			opts:    yubikey.Options{Slot: "9e"},
			wantErr: false,
		},
		{
			name:    "invalid slot",
			opts:    yubikey.Options{Slot: "invalid"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := yubikey.NewProvider(tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProviderName(t *testing.T) {
	p, err := yubikey.NewProvider(yubikey.Options{})
	require.NoError(t, err)
	assert.Equal(t, kmsprovider.ProviderYubiKey, p.Name())
}

func TestProviderSlot(t *testing.T) {
	p, err := yubikey.NewProvider(yubikey.Options{Slot: "9c"})
	require.NoError(t, err)
	assert.Equal(t, yubikey.PIVSlot("9c"), p.Slot())
}

func TestProviderDefaultSlot(t *testing.T) {
	p, err := yubikey.NewProvider(yubikey.Options{})
	require.NoError(t, err)
	assert.Equal(t, yubikey.SlotAuthentication, p.Slot())
}

func TestProviderWithMockClient(t *testing.T) {
	ctx := context.Background()
	mockClient := yubikey.NewMockPIVClient()

	p, err := yubikey.NewProviderWithClient(yubikey.Options{
		Slot: "9a",
	}, mockClient)
	require.NoError(t, err)

	plaintext := []byte("test secret data for YubiKey PIV")
	ciphertext, err := p.Encrypt(ctx, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := p.Decrypt(ctx, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestProviderDecryptInvalidCiphertext(t *testing.T) {
	ctx := context.Background()
	mockClient := yubikey.NewMockPIVClient()

	p, err := yubikey.NewProviderWithClient(yubikey.Options{
		Slot: "9a",
	}, mockClient)
	require.NoError(t, err)

	_, err = p.Decrypt(ctx, []byte("invalid"))
	assert.Error(t, err)
}

func TestProviderWithFingerprintVerification(t *testing.T) {
	ctx := context.Background()
	expectedFingerprint := "SHA256:abc123"
	mockClient := yubikey.NewMockPIVClientWithFingerprint(expectedFingerprint)

	p, err := yubikey.NewProviderWithClient(yubikey.Options{
		Slot:                 "9a",
		PublicKeyFingerprint: expectedFingerprint,
	}, mockClient)
	require.NoError(t, err)

	plaintext := []byte("test data")
	ciphertext, err := p.Encrypt(ctx, plaintext)
	require.NoError(t, err)

	decrypted, err := p.Decrypt(ctx, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestProviderWithFingerprintMismatch(t *testing.T) {
	ctx := context.Background()
	mockClient := yubikey.NewMockPIVClientWithFingerprint("SHA256:actual")

	p, err := yubikey.NewProviderWithClient(yubikey.Options{
		Slot:                 "9a",
		PublicKeyFingerprint: "SHA256:expected",
	}, mockClient)
	require.NoError(t, err)

	_, err = p.Encrypt(ctx, []byte("test"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "fingerprint mismatch")
}

func TestProviderClose(t *testing.T) {
	mockClient := yubikey.NewMockPIVClient()

	p, err := yubikey.NewProviderWithClient(yubikey.Options{
		Slot: "9a",
	}, mockClient)
	require.NoError(t, err)

	err = p.Close()
	assert.NoError(t, err)
}

func TestSlotConstants(t *testing.T) {
	assert.Equal(t, yubikey.PIVSlot("9a"), yubikey.SlotAuthentication)
	assert.Equal(t, yubikey.PIVSlot("9c"), yubikey.SlotSignature)
	assert.Equal(t, yubikey.PIVSlot("9d"), yubikey.SlotKeyManagement)
	assert.Equal(t, yubikey.PIVSlot("9e"), yubikey.SlotCardAuth)
}

// FailingMockPIVClient for error path testing
type FailingMockPIVClient struct {
	encryptErr     error
	decryptErr     error
	fingerprintErr error
	closeErr       error
	fingerprint    string
}

func (m *FailingMockPIVClient) Encrypt(ctx context.Context, slot yubikey.PIVSlot, plaintext []byte) ([]byte, error) {
	if m.encryptErr != nil {
		return nil, m.encryptErr
	}
	return []byte("encrypted"), nil
}

func (m *FailingMockPIVClient) Decrypt(ctx context.Context, slot yubikey.PIVSlot, ciphertext []byte) ([]byte, error) {
	if m.decryptErr != nil {
		return nil, m.decryptErr
	}
	return []byte("decrypted"), nil
}

func (m *FailingMockPIVClient) GetPublicKeyFingerprint(ctx context.Context, slot yubikey.PIVSlot) (string, error) {
	if m.fingerprintErr != nil {
		return "", m.fingerprintErr
	}
	return m.fingerprint, nil
}

func (m *FailingMockPIVClient) Close() error {
	return m.closeErr
}

func TestProviderEncryptFailure(t *testing.T) {
	ctx := context.Background()
	failClient := &FailingMockPIVClient{
		encryptErr: assert.AnError,
	}

	p, err := yubikey.NewProviderWithClient(yubikey.Options{
		Slot: "9a",
	}, failClient)
	require.NoError(t, err)

	_, err = p.Encrypt(ctx, []byte("test data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "YubiKey encrypt failed")
}

func TestProviderDecryptFailure(t *testing.T) {
	ctx := context.Background()
	failClient := &FailingMockPIVClient{
		decryptErr: assert.AnError,
	}

	p, err := yubikey.NewProviderWithClient(yubikey.Options{
		Slot: "9a",
	}, failClient)
	require.NoError(t, err)

	_, err = p.Decrypt(ctx, []byte("encrypted data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "YubiKey decrypt failed")
}

func TestProviderGetFingerprintFailure(t *testing.T) {
	ctx := context.Background()
	failClient := &FailingMockPIVClient{
		fingerprintErr: assert.AnError,
		fingerprint:    "SHA256:test",
	}

	p, err := yubikey.NewProviderWithClient(yubikey.Options{
		Slot:                 "9a",
		PublicKeyFingerprint: "SHA256:expected",
	}, failClient)
	require.NoError(t, err)

	_, err = p.Encrypt(ctx, []byte("test data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get public key fingerprint")
}

func TestProviderCloseFailure(t *testing.T) {
	failClient := &FailingMockPIVClient{
		closeErr: assert.AnError,
	}

	p, err := yubikey.NewProviderWithClient(yubikey.Options{
		Slot: "9a",
	}, failClient)
	require.NoError(t, err)

	err = p.Close()
	assert.Error(t, err)
}

func TestProviderCloseNilClient(t *testing.T) {
	p, err := yubikey.NewProvider(yubikey.Options{})
	require.NoError(t, err)

	// Close should not panic with nil client
	err = p.Close()
	assert.NoError(t, err)
}

func TestProviderWithNilClient(t *testing.T) {
	// Test that provider created without client will fail on operations
	p, err := yubikey.NewProvider(yubikey.Options{})
	require.NoError(t, err)

	// The provider is created but has no client
	assert.NotNil(t, p)
	assert.Equal(t, kmsprovider.ProviderYubiKey, p.Name())
}

func TestProviderDecryptTamperedCiphertext(t *testing.T) {
	ctx := context.Background()
	mockClient := yubikey.NewMockPIVClient()

	p, err := yubikey.NewProviderWithClient(yubikey.Options{
		Slot: "9a",
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

func TestProviderMultipleOperations(t *testing.T) {
	ctx := context.Background()
	mockClient := yubikey.NewMockPIVClient()

	p, err := yubikey.NewProviderWithClient(yubikey.Options{
		Slot: "9a",
	}, mockClient)
	require.NoError(t, err)

	// Test multiple encrypt/decrypt operations
	for i := 0; i < 5; i++ {
		plaintext := []byte("test secret data")
		ciphertext, err := p.Encrypt(ctx, plaintext)
		require.NoError(t, err)

		decrypted, err := p.Decrypt(ctx, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	}
}

func TestNewProviderWithClientValidation(t *testing.T) {
	mockClient := yubikey.NewMockPIVClient()

	t.Run("invalid slot", func(t *testing.T) {
		_, err := yubikey.NewProviderWithClient(yubikey.Options{
			Slot: "invalid",
		}, mockClient)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid PIV slot")
	})

	t.Run("valid slot 9c", func(t *testing.T) {
		p, err := yubikey.NewProviderWithClient(yubikey.Options{
			Slot: "9c",
		}, mockClient)
		require.NoError(t, err)
		assert.Equal(t, yubikey.SlotSignature, p.Slot())
	})

	t.Run("valid slot 9d", func(t *testing.T) {
		p, err := yubikey.NewProviderWithClient(yubikey.Options{
			Slot: "9d",
		}, mockClient)
		require.NoError(t, err)
		assert.Equal(t, yubikey.SlotKeyManagement, p.Slot())
	})

	t.Run("valid slot 9e", func(t *testing.T) {
		p, err := yubikey.NewProviderWithClient(yubikey.Options{
			Slot: "9e",
		}, mockClient)
		require.NoError(t, err)
		assert.Equal(t, yubikey.SlotCardAuth, p.Slot())
	})

	t.Run("empty slot uses default", func(t *testing.T) {
		p, err := yubikey.NewProviderWithClient(yubikey.Options{}, mockClient)
		require.NoError(t, err)
		assert.Equal(t, yubikey.SlotAuthentication, p.Slot())
	})
}

func TestProviderEnsureClientWithoutClient(t *testing.T) {
	ctx := context.Background()
	p, err := yubikey.NewProvider(yubikey.Options{})
	require.NoError(t, err)

	// Encrypt should fail because no PIV client
	_, err = p.Encrypt(ctx, []byte("test"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "piv-go library")

	// Decrypt should fail because no PIV client
	_, err = p.Decrypt(ctx, []byte("test"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "piv-go library")
}

func TestProviderWithEncryptNoFingerprintCheck(t *testing.T) {
	ctx := context.Background()
	mockClient := yubikey.NewMockPIVClient()

	// Create provider without fingerprint verification
	p, err := yubikey.NewProviderWithClient(yubikey.Options{
		Slot: "9a",
		// No PublicKeyFingerprint set
	}, mockClient)
	require.NoError(t, err)

	// Should succeed without fingerprint check
	plaintext := []byte("test data")
	ciphertext, err := p.Encrypt(ctx, plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)
}

func TestProviderAllSlots(t *testing.T) {
	ctx := context.Background()
	slots := []yubikey.PIVSlot{
		yubikey.SlotAuthentication,
		yubikey.SlotSignature,
		yubikey.SlotKeyManagement,
		yubikey.SlotCardAuth,
	}

	for _, slot := range slots {
		t.Run(string(slot), func(t *testing.T) {
			mockClient := yubikey.NewMockPIVClient()
			p, err := yubikey.NewProviderWithClient(yubikey.Options{
				Slot: slot,
			}, mockClient)
			require.NoError(t, err)
			assert.Equal(t, slot, p.Slot())

			plaintext := []byte("test data for " + string(slot))
			ciphertext, err := p.Encrypt(ctx, plaintext)
			require.NoError(t, err)

			decrypted, err := p.Decrypt(ctx, ciphertext)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted)
		})
	}
}
