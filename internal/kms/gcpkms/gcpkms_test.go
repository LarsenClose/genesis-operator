package gcpkms_test

import (
	"context"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	kmsprovider "github.com/larsenclose/genesis/internal/kms"
	"github.com/larsenclose/genesis/internal/kms/gcpkms"
)

func TestNewProviderValidation(t *testing.T) {
	tests := []struct {
		name    string
		opts    gcpkms.Options
		wantErr bool
	}{
		{
			name:    "empty key name",
			opts:    gcpkms.Options{KeyName: ""},
			wantErr: true,
		},
		{
			name: "valid options",
			opts: gcpkms.Options{
				KeyName: "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := gcpkms.NewProvider(tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProviderName(t *testing.T) {
	p, err := gcpkms.NewProvider(gcpkms.Options{
		KeyName: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	})
	require.NoError(t, err)
	assert.Equal(t, kmsprovider.ProviderGCPKMS, p.Name())
}

func TestProviderKeyName(t *testing.T) {
	keyName := "projects/test/locations/global/keyRings/test/cryptoKeys/test"
	p, err := gcpkms.NewProvider(gcpkms.Options{
		KeyName: keyName,
	})
	require.NoError(t, err)
	assert.Equal(t, keyName, p.KeyName())
}

func TestProviderWithMockClient(t *testing.T) {
	ctx := context.Background()
	mockClient := gcpkms.NewMockKMSClient()

	p, err := gcpkms.NewProviderWithClient(gcpkms.Options{
		KeyName: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	}, mockClient)
	require.NoError(t, err)

	plaintext := []byte("test secret data for GCP KMS")
	ciphertext, err := p.Encrypt(ctx, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := p.Decrypt(ctx, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestProviderDecryptInvalidCiphertext(t *testing.T) {
	ctx := context.Background()
	mockClient := gcpkms.NewMockKMSClient()

	p, err := gcpkms.NewProviderWithClient(gcpkms.Options{
		KeyName: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	}, mockClient)
	require.NoError(t, err)

	_, err = p.Decrypt(ctx, []byte("invalid"))
	assert.Error(t, err)
}

func TestProviderEncryptDecryptLargeData(t *testing.T) {
	ctx := context.Background()
	mockClient := gcpkms.NewMockKMSClient()

	p, err := gcpkms.NewProviderWithClient(gcpkms.Options{
		KeyName: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	}, mockClient)
	require.NoError(t, err)

	// Test with larger data (simulating an age private key)
	plaintext := []byte("AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ")
	ciphertext, err := p.Encrypt(ctx, plaintext)
	require.NoError(t, err)

	decrypted, err := p.Decrypt(ctx, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestProviderClose(t *testing.T) {
	mockClient := gcpkms.NewMockKMSClient()

	p, err := gcpkms.NewProviderWithClient(gcpkms.Options{
		KeyName: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	}, mockClient)
	require.NoError(t, err)

	err = p.Close()
	assert.NoError(t, err)
}

func TestProviderCloseNilClient(t *testing.T) {
	// Create provider without client injection (nil client)
	p, err := gcpkms.NewProvider(gcpkms.Options{
		KeyName: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	})
	require.NoError(t, err)

	// Close should not panic with nil client
	err = p.Close()
	assert.NoError(t, err)
}

func TestProviderMultipleEncryptDecrypt(t *testing.T) {
	ctx := context.Background()
	mockClient := gcpkms.NewMockKMSClient()

	p, err := gcpkms.NewProviderWithClient(gcpkms.Options{
		KeyName: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	}, mockClient)
	require.NoError(t, err)

	// Test multiple encrypt/decrypt cycles
	for i := 0; i < 3; i++ {
		plaintext := []byte("test secret data iteration " + string(rune('0'+i)))
		ciphertext, err := p.Encrypt(ctx, plaintext)
		require.NoError(t, err)
		assert.NotEqual(t, plaintext, ciphertext)

		decrypted, err := p.Decrypt(ctx, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	}
}

func TestProviderEncryptEmptyData(t *testing.T) {
	ctx := context.Background()
	mockClient := gcpkms.NewMockKMSClient()

	p, err := gcpkms.NewProviderWithClient(gcpkms.Options{
		KeyName: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	}, mockClient)
	require.NoError(t, err)

	// Encrypt empty data
	ciphertext, err := p.Encrypt(ctx, []byte{})
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)

	// Decrypt should return empty data
	decrypted, err := p.Decrypt(ctx, ciphertext)
	require.NoError(t, err)
	assert.Empty(t, decrypted)
}

func TestNewProviderWithClientEmptyKeyName(t *testing.T) {
	mockClient := gcpkms.NewMockKMSClient()

	_, err := gcpkms.NewProviderWithClient(gcpkms.Options{
		KeyName: "",
	}, mockClient)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key name is required")
}

// FailingMockKMSClient for error path testing
type FailingMockKMSClient struct {
	encryptErr error
	decryptErr error
	closeErr   error
}

func (m *FailingMockKMSClient) Encrypt(ctx context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	if m.encryptErr != nil {
		return nil, m.encryptErr
	}
	// Return a valid response with correct CRC32 checksums
	ciphertext := []byte("encrypted")
	return &kmspb.EncryptResponse{
		Ciphertext:              ciphertext,
		CiphertextCrc32C:        wrapperspb.Int64(int64(gcpkms.CRC32Checksum(ciphertext))),
		VerifiedPlaintextCrc32C: true,
	}, nil
}

func (m *FailingMockKMSClient) Decrypt(ctx context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	if m.decryptErr != nil {
		return nil, m.decryptErr
	}
	plaintext := []byte("decrypted")
	return &kmspb.DecryptResponse{
		Plaintext:       plaintext,
		PlaintextCrc32C: wrapperspb.Int64(int64(gcpkms.CRC32Checksum(plaintext))),
	}, nil
}

func (m *FailingMockKMSClient) Close() error {
	return m.closeErr
}

func TestProviderEncryptFailure(t *testing.T) {
	ctx := context.Background()
	failClient := &FailingMockKMSClient{
		encryptErr: assert.AnError,
	}

	p, err := gcpkms.NewProviderWithClient(gcpkms.Options{
		KeyName: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	}, failClient)
	require.NoError(t, err)

	_, err = p.Encrypt(ctx, []byte("test data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "GCP KMS encrypt failed")
}

func TestProviderDecryptFailure(t *testing.T) {
	ctx := context.Background()
	failClient := &FailingMockKMSClient{
		decryptErr: assert.AnError,
	}

	p, err := gcpkms.NewProviderWithClient(gcpkms.Options{
		KeyName: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	}, failClient)
	require.NoError(t, err)

	_, err = p.Decrypt(ctx, []byte("encrypted data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "GCP KMS decrypt failed")
}

func TestProviderCloseFailure(t *testing.T) {
	failClient := &FailingMockKMSClient{
		closeErr: assert.AnError,
	}

	p, err := gcpkms.NewProviderWithClient(gcpkms.Options{
		KeyName: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	}, failClient)
	require.NoError(t, err)

	err = p.Close()
	assert.Error(t, err)
}

func TestProviderDecryptTamperedCiphertext(t *testing.T) {
	ctx := context.Background()
	mockClient := gcpkms.NewMockKMSClient()

	p, err := gcpkms.NewProviderWithClient(gcpkms.Options{
		KeyName: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
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

func TestProviderWithNilClient(t *testing.T) {
	// Test that provider created without client will fail on operations
	// since it can't load GCP credentials in test environment
	p, err := gcpkms.NewProvider(gcpkms.Options{
		KeyName: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	})
	require.NoError(t, err)

	// The provider is created but has no client
	assert.NotNil(t, p)
	assert.Equal(t, kmsprovider.ProviderGCPKMS, p.Name())
}

func TestProviderMultipleOperations(t *testing.T) {
	ctx := context.Background()
	mockClient := gcpkms.NewMockKMSClient()

	p, err := gcpkms.NewProviderWithClient(gcpkms.Options{
		KeyName: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	}, mockClient)
	require.NoError(t, err)

	// Test interleaved encrypt/decrypt operations
	plaintexts := [][]byte{
		[]byte("first secret"),
		[]byte("second secret"),
		[]byte("third secret"),
	}

	ciphertexts := make([][]byte, len(plaintexts))
	for i, pt := range plaintexts {
		ct, err := p.Encrypt(ctx, pt)
		require.NoError(t, err)
		ciphertexts[i] = ct
	}

	// Decrypt in reverse order
	for i := len(plaintexts) - 1; i >= 0; i-- {
		decrypted, err := p.Decrypt(ctx, ciphertexts[i])
		require.NoError(t, err)
		assert.Equal(t, plaintexts[i], decrypted)
	}
}

// CRC verification failure mocks
type CRCFailMockKMSClient struct {
	failVerifiedPlaintext bool
	failCiphertextCRC     bool
	failDecryptCRC        bool
}

func (m *CRCFailMockKMSClient) Encrypt(ctx context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	ciphertext := []byte("encrypted-data")
	ciphertextCRC := gcpkms.CRC32Checksum(ciphertext)
	if m.failCiphertextCRC {
		ciphertextCRC = ciphertextCRC ^ 0xFFFFFFFF // Corrupt CRC
	}
	return &kmspb.EncryptResponse{
		Ciphertext:              ciphertext,
		CiphertextCrc32C:        wrapperspb.Int64(int64(ciphertextCRC)),
		VerifiedPlaintextCrc32C: !m.failVerifiedPlaintext,
	}, nil
}

func (m *CRCFailMockKMSClient) Decrypt(ctx context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	plaintext := []byte("decrypted-data")
	plaintextCRC := gcpkms.CRC32Checksum(plaintext)
	if m.failDecryptCRC {
		plaintextCRC = plaintextCRC ^ 0xFFFFFFFF // Corrupt CRC
	}
	return &kmspb.DecryptResponse{
		Plaintext:       plaintext,
		PlaintextCrc32C: wrapperspb.Int64(int64(plaintextCRC)),
	}, nil
}

func (m *CRCFailMockKMSClient) Close() error {
	return nil
}

func TestProviderEncryptVerifiedPlaintextCRCFailure(t *testing.T) {
	ctx := context.Background()
	failClient := &CRCFailMockKMSClient{
		failVerifiedPlaintext: true,
	}

	p, err := gcpkms.NewProviderWithClient(gcpkms.Options{
		KeyName: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	}, failClient)
	require.NoError(t, err)

	_, err = p.Encrypt(ctx, []byte("test data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request corrupted in transit")
}

func TestProviderEncryptCiphertextCRCFailure(t *testing.T) {
	ctx := context.Background()
	failClient := &CRCFailMockKMSClient{
		failCiphertextCRC: true,
	}

	p, err := gcpkms.NewProviderWithClient(gcpkms.Options{
		KeyName: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	}, failClient)
	require.NoError(t, err)

	_, err = p.Encrypt(ctx, []byte("test data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "response corrupted in transit")
}

func TestProviderDecryptPlaintextCRCFailure(t *testing.T) {
	ctx := context.Background()
	failClient := &CRCFailMockKMSClient{
		failDecryptCRC: true,
	}

	p, err := gcpkms.NewProviderWithClient(gcpkms.Options{
		KeyName: "projects/test/locations/global/keyRings/test/cryptoKeys/test",
	}, failClient)
	require.NoError(t, err)

	_, err = p.Decrypt(ctx, []byte("encrypted data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "response corrupted in transit")
}
