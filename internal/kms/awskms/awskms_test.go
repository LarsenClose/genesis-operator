package awskms_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmsprovider "github.com/larsenclose/genesis/internal/kms"
	"github.com/larsenclose/genesis/internal/kms/awskms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProviderValidation(t *testing.T) {
	tests := []struct {
		name    string
		opts    awskms.Options
		wantErr bool
	}{
		{
			name:    "empty key arn",
			opts:    awskms.Options{KeyArn: ""},
			wantErr: true,
		},
		{
			name: "valid options",
			opts: awskms.Options{
				KeyArn: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
				Region: "us-west-2",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := awskms.NewProvider(tt.opts)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProviderName(t *testing.T) {
	p, err := awskms.NewProvider(awskms.Options{
		KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test",
	})
	require.NoError(t, err)
	assert.Equal(t, kmsprovider.ProviderAWSKMS, p.Name())
}

func TestProviderWithMockClient(t *testing.T) {
	ctx := context.Background()
	mockClient := awskms.NewMockKMSClient()

	p, err := awskms.NewProviderWithClient(awskms.Options{
		KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test",
	}, mockClient)
	require.NoError(t, err)

	plaintext := []byte("test secret data")
	ciphertext, err := p.Encrypt(ctx, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := p.Decrypt(ctx, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestProviderDecryptInvalidCiphertext(t *testing.T) {
	ctx := context.Background()
	mockClient := awskms.NewMockKMSClient()

	p, err := awskms.NewProviderWithClient(awskms.Options{
		KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test",
	}, mockClient)
	require.NoError(t, err)

	_, err = p.Decrypt(ctx, []byte("invalid"))
	assert.Error(t, err)
}

func TestProviderKeyArnExtraction(t *testing.T) {
	p, err := awskms.NewProvider(awskms.Options{
		KeyArn: "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
	})
	require.NoError(t, err)
	assert.Equal(t, "us-west-2", p.Region())
}

func TestProviderKeyArnExtractionWithExplicitRegion(t *testing.T) {
	p, err := awskms.NewProvider(awskms.Options{
		KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test",
		Region: "eu-west-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "eu-west-1", p.Region())
}

// Failing mock client for error path testing
type FailingMockKMSClient struct {
	encryptErr error
	decryptErr error
}

func (m *FailingMockKMSClient) Encrypt(ctx context.Context, input *kms.EncryptInput, opts ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	if m.encryptErr != nil {
		return nil, m.encryptErr
	}
	return &kms.EncryptOutput{CiphertextBlob: []byte("encrypted")}, nil
}

func (m *FailingMockKMSClient) Decrypt(ctx context.Context, input *kms.DecryptInput, opts ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if m.decryptErr != nil {
		return nil, m.decryptErr
	}
	return &kms.DecryptOutput{Plaintext: []byte("decrypted")}, nil
}

func TestProviderEncryptFailure(t *testing.T) {
	ctx := context.Background()
	failClient := &FailingMockKMSClient{
		encryptErr: assert.AnError,
	}

	p, err := awskms.NewProviderWithClient(awskms.Options{
		KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test",
	}, failClient)
	require.NoError(t, err)

	_, err = p.Encrypt(ctx, []byte("test data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "KMS encrypt failed")
}

func TestProviderDecryptFailure(t *testing.T) {
	ctx := context.Background()
	failClient := &FailingMockKMSClient{
		decryptErr: assert.AnError,
	}

	p, err := awskms.NewProviderWithClient(awskms.Options{
		KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test",
	}, failClient)
	require.NoError(t, err)

	_, err = p.Decrypt(ctx, []byte("encrypted data"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "KMS decrypt failed")
}

func TestProviderWithShortArn(t *testing.T) {
	// Test ARN with less than 4 parts - should still create provider
	p, err := awskms.NewProvider(awskms.Options{
		KeyArn: "arn:aws:kms",
	})
	require.NoError(t, err)
	// Region should be empty string when not enough ARN parts
	assert.Equal(t, "", p.Region())
}

func TestProviderMultipleEncryptDecrypt(t *testing.T) {
	ctx := context.Background()
	mockClient := awskms.NewMockKMSClient()

	p, err := awskms.NewProviderWithClient(awskms.Options{
		KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test",
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
	mockClient := awskms.NewMockKMSClient()

	p, err := awskms.NewProviderWithClient(awskms.Options{
		KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test",
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

func TestProviderEncryptLargeData(t *testing.T) {
	ctx := context.Background()
	mockClient := awskms.NewMockKMSClient()

	p, err := awskms.NewProviderWithClient(awskms.Options{
		KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test",
	}, mockClient)
	require.NoError(t, err)

	// Test with larger data (4KB)
	plaintext := make([]byte, 4096)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	ciphertext, err := p.Encrypt(ctx, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := p.Decrypt(ctx, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestProviderWithNilClient(t *testing.T) {
	// Test that provider created without client will return error on operations
	// since it can't load AWS config in test environment
	p, err := awskms.NewProvider(awskms.Options{
		KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test",
	})
	require.NoError(t, err)

	// The provider is created but has no client
	// In a real test environment without AWS config, ensureClient would fail
	// We verify provider was created successfully
	assert.NotNil(t, p)
	assert.Equal(t, kmsprovider.ProviderAWSKMS, p.Name())
}

func TestNewProviderWithClientEmptyKeyArn(t *testing.T) {
	mockClient := awskms.NewMockKMSClient()
	_, err := awskms.NewProviderWithClient(awskms.Options{
		KeyArn: "",
	}, mockClient)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key ARN is required")
}

func TestProviderDecryptTamperedCiphertext(t *testing.T) {
	ctx := context.Background()
	mockClient := awskms.NewMockKMSClient()

	p, err := awskms.NewProviderWithClient(awskms.Options{
		KeyArn: "arn:aws:kms:us-west-2:123456789012:key/test",
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

func TestProviderRegionExtraction(t *testing.T) {
	tests := []struct {
		name           string
		arn            string
		explicitRegion string
		expectedRegion string
	}{
		{
			name:           "extract from arn",
			arn:            "arn:aws:kms:ap-northeast-1:123456789012:key/test",
			expectedRegion: "ap-northeast-1",
		},
		{
			name:           "explicit region overrides arn",
			arn:            "arn:aws:kms:us-west-2:123456789012:key/test",
			explicitRegion: "ap-southeast-1",
			expectedRegion: "ap-southeast-1",
		},
		{
			name:           "very short arn",
			arn:            "arn",
			expectedRegion: "",
		},
		{
			name:           "arn with two parts",
			arn:            "arn:aws",
			expectedRegion: "",
		},
		{
			name:           "arn with three parts",
			arn:            "arn:aws:kms",
			expectedRegion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := awskms.NewProvider(awskms.Options{
				KeyArn: tt.arn,
				Region: tt.explicitRegion,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.expectedRegion, p.Region())
		})
	}
}
