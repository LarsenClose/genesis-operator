package tpm_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kmsprovider "github.com/larsenclose/genesis/internal/kms"
	"github.com/larsenclose/genesis/internal/kms/tpm"
)

func TestNewProviderValidation(t *testing.T) {
	tests := []struct {
		name    string
		opts    tpm.Options
		wantErr bool
	}{
		{
			name:    "default options",
			opts:    tpm.Options{},
			wantErr: false,
		},
		{
			name: "custom device path",
			opts: tpm.Options{
				DevicePath: "/dev/tpm0",
			},
			wantErr: false,
		},
		{
			name: "custom PCR selection",
			opts: tpm.Options{
				PCRSelection: &tpm.PCRSelection{
					Hash: tpm.HashSHA256,
					PCRs: []int{0, 7},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid hash algorithm",
			opts: tpm.Options{
				PCRSelection: &tpm.PCRSelection{
					Hash: "invalid",
					PCRs: []int{0},
				},
			},
			wantErr: true,
		},
		{
			name: "empty PCRs",
			opts: tpm.Options{
				PCRSelection: &tpm.PCRSelection{
					Hash: tpm.HashSHA256,
					PCRs: []int{},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid PCR index",
			opts: tpm.Options{
				PCRSelection: &tpm.PCRSelection{
					Hash: tpm.HashSHA256,
					PCRs: []int{24},
				},
			},
			wantErr: true,
		},
		{
			name: "negative PCR index",
			opts: tpm.Options{
				PCRSelection: &tpm.PCRSelection{
					Hash: tpm.HashSHA256,
					PCRs: []int{-1},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tpm.NewProvider(tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProviderName(t *testing.T) {
	p, err := tpm.NewProvider(tpm.Options{})
	require.NoError(t, err)
	assert.Equal(t, kmsprovider.ProviderTPM, p.Name())
}

func TestProviderDevicePath(t *testing.T) {
	p, err := tpm.NewProvider(tpm.Options{
		DevicePath: "/dev/tpm0",
	})
	require.NoError(t, err)
	assert.Equal(t, "/dev/tpm0", p.DevicePath())
}

func TestProviderDefaultDevicePath(t *testing.T) {
	p, err := tpm.NewProvider(tpm.Options{})
	require.NoError(t, err)
	assert.Equal(t, "/dev/tpmrm0", p.DevicePath())
}

func TestProviderPCRSelection(t *testing.T) {
	pcrSel := &tpm.PCRSelection{
		Hash: tpm.HashSHA384,
		PCRs: []int{0, 1, 7},
	}
	p, err := tpm.NewProvider(tpm.Options{
		PCRSelection: pcrSel,
	})
	require.NoError(t, err)
	assert.Equal(t, pcrSel, p.PCRSelection())
}

func TestProviderDefaultPCRSelection(t *testing.T) {
	p, err := tpm.NewProvider(tpm.Options{})
	require.NoError(t, err)
	sel := p.PCRSelection()
	assert.Equal(t, tpm.HashSHA256, sel.Hash)
	assert.Equal(t, []int{0, 1, 2, 3, 7}, sel.PCRs)
}

func TestProviderWithMockClient(t *testing.T) {
	ctx := context.Background()
	mockClient := tpm.NewMockTPMClient()

	p, err := tpm.NewProviderWithClient(tpm.Options{}, mockClient)
	require.NoError(t, err)

	plaintext := []byte("test secret data for TPM 2.0")
	ciphertext, err := p.Encrypt(ctx, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := p.Decrypt(ctx, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestProviderDecryptInvalidCiphertext(t *testing.T) {
	ctx := context.Background()
	mockClient := tpm.NewMockTPMClient()

	p, err := tpm.NewProviderWithClient(tpm.Options{}, mockClient)
	require.NoError(t, err)

	_, err = p.Decrypt(ctx, []byte("invalid"))
	assert.Error(t, err)
}

func TestProviderGetPCRValues(t *testing.T) {
	ctx := context.Background()
	mockClient := tpm.NewMockTPMClient()

	p, err := tpm.NewProviderWithClient(tpm.Options{
		PCRSelection: &tpm.PCRSelection{
			Hash: tpm.HashSHA256,
			PCRs: []int{0, 7},
		},
	}, mockClient)
	require.NoError(t, err)

	values, err := p.GetPCRValues(ctx)
	require.NoError(t, err)
	assert.Len(t, values, 2)
	assert.Contains(t, values, 0)
	assert.Contains(t, values, 7)
}

func TestProviderClose(t *testing.T) {
	mockClient := tpm.NewMockTPMClient()

	p, err := tpm.NewProviderWithClient(tpm.Options{}, mockClient)
	require.NoError(t, err)

	err = p.Close()
	assert.NoError(t, err)
}

func TestHashAlgorithmConstants(t *testing.T) {
	assert.Equal(t, tpm.HashAlgorithm("sha256"), tpm.HashSHA256)
	assert.Equal(t, tpm.HashAlgorithm("sha384"), tpm.HashSHA384)
	assert.Equal(t, tpm.HashAlgorithm("sha512"), tpm.HashSHA512)
}

// FailingMockTPMClient for error path testing
type FailingMockTPMClient struct {
	sealErr   error
	unsealErr error
	getPCRErr error
	closeErr  error
}

func (m *FailingMockTPMClient) Seal(ctx context.Context, plaintext []byte, pcrSelection *tpm.PCRSelection) ([]byte, error) {
	if m.sealErr != nil {
		return nil, m.sealErr
	}
	return []byte("sealed"), nil
}

func (m *FailingMockTPMClient) Unseal(ctx context.Context, sealed []byte) ([]byte, error) {
	if m.unsealErr != nil {
		return nil, m.unsealErr
	}
	return []byte("unsealed"), nil
}

func (m *FailingMockTPMClient) GetPCRValues(ctx context.Context, pcrSelection *tpm.PCRSelection) (map[int][]byte, error) {
	if m.getPCRErr != nil {
		return nil, m.getPCRErr
	}
	return map[int][]byte{0: []byte("pcr0")}, nil
}

func (m *FailingMockTPMClient) Close() error {
	return m.closeErr
}

func TestProviderEncryptFailure(t *testing.T) {
	ctx := context.Background()
	failClient := &FailingMockTPMClient{
		sealErr: assert.AnError,
	}

	p, err := tpm.NewProviderWithClient(tpm.Options{}, failClient)
	require.NoError(t, err)

	_, err = p.Encrypt(ctx, []byte("test data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "TPM seal failed")
}

func TestProviderDecryptFailure(t *testing.T) {
	ctx := context.Background()
	failClient := &FailingMockTPMClient{
		unsealErr: assert.AnError,
	}

	p, err := tpm.NewProviderWithClient(tpm.Options{}, failClient)
	require.NoError(t, err)

	_, err = p.Decrypt(ctx, []byte("sealed data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "TPM unseal failed")
}

func TestProviderGetPCRValuesFailure(t *testing.T) {
	ctx := context.Background()
	failClient := &FailingMockTPMClient{
		getPCRErr: assert.AnError,
	}

	p, err := tpm.NewProviderWithClient(tpm.Options{
		PCRSelection: &tpm.PCRSelection{
			Hash: tpm.HashSHA256,
			PCRs: []int{0, 7},
		},
	}, failClient)
	require.NoError(t, err)

	_, err = p.GetPCRValues(ctx)
	assert.Error(t, err)
}

func TestProviderCloseFailure(t *testing.T) {
	failClient := &FailingMockTPMClient{
		closeErr: assert.AnError,
	}

	p, err := tpm.NewProviderWithClient(tpm.Options{}, failClient)
	require.NoError(t, err)

	err = p.Close()
	assert.Error(t, err)
}

func TestProviderCloseNilClient(t *testing.T) {
	p, err := tpm.NewProvider(tpm.Options{})
	require.NoError(t, err)

	// Close should not panic with nil client
	err = p.Close()
	assert.NoError(t, err)
}

func TestProviderWithNilClient(t *testing.T) {
	// Test that provider created without client will fail on operations
	p, err := tpm.NewProvider(tpm.Options{})
	require.NoError(t, err)

	// The provider is created but has no client
	assert.NotNil(t, p)
	assert.Equal(t, kmsprovider.ProviderTPM, p.Name())
}

func TestProviderDecryptTamperedCiphertext(t *testing.T) {
	ctx := context.Background()
	mockClient := tpm.NewMockTPMClient()

	p, err := tpm.NewProviderWithClient(tpm.Options{}, mockClient)
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
	mockClient := tpm.NewMockTPMClient()

	p, err := tpm.NewProviderWithClient(tpm.Options{}, mockClient)
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
	mockClient := tpm.NewMockTPMClient()

	t.Run("invalid hash algorithm", func(t *testing.T) {
		_, err := tpm.NewProviderWithClient(tpm.Options{
			PCRSelection: &tpm.PCRSelection{
				Hash: "invalid",
				PCRs: []int{0},
			},
		}, mockClient)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid hash algorithm")
	})

	t.Run("empty PCRs", func(t *testing.T) {
		_, err := tpm.NewProviderWithClient(tpm.Options{
			PCRSelection: &tpm.PCRSelection{
				Hash: tpm.HashSHA256,
				PCRs: []int{},
			},
		}, mockClient)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one PCR must be selected")
	})

	t.Run("PCR index too high", func(t *testing.T) {
		_, err := tpm.NewProviderWithClient(tpm.Options{
			PCRSelection: &tpm.PCRSelection{
				Hash: tpm.HashSHA256,
				PCRs: []int{24},
			},
		}, mockClient)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid PCR index")
	})

	t.Run("negative PCR index", func(t *testing.T) {
		_, err := tpm.NewProviderWithClient(tpm.Options{
			PCRSelection: &tpm.PCRSelection{
				Hash: tpm.HashSHA256,
				PCRs: []int{-1},
			},
		}, mockClient)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid PCR index")
	})
}

func TestProviderEnsureClientWithoutClient(t *testing.T) {
	ctx := context.Background()
	p, err := tpm.NewProvider(tpm.Options{})
	require.NoError(t, err)

	// Encrypt should fail because no TPM client
	_, err = p.Encrypt(ctx, []byte("test"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "go-tpm library")

	// Decrypt should fail because no TPM client
	_, err = p.Decrypt(ctx, []byte("test"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "go-tpm library")

	// GetPCRValues should fail because no TPM client
	_, err = p.GetPCRValues(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "go-tpm library")
}
