package gcpkms

import (
	"context"
	"fmt"
	"hash/crc32"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	kmsprovider "github.com/larsenclose/genesis/internal/kms"
)

// KMSClient defines the interface for GCP KMS operations
type KMSClient interface {
	Encrypt(ctx context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error)
	Decrypt(ctx context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error)
	Close() error
}

// kmsClientWrapper wraps the actual GCP KMS client
type kmsClientWrapper struct {
	client *kms.KeyManagementClient
}

func (w *kmsClientWrapper) Encrypt(ctx context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	return w.client.Encrypt(ctx, req)
}

func (w *kmsClientWrapper) Decrypt(ctx context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	return w.client.Decrypt(ctx, req)
}

func (w *kmsClientWrapper) Close() error {
	return w.client.Close()
}

// Options configures the GCP KMS provider
type Options struct {
	// KeyName is the full resource name of the KMS key
	// Format: projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{key}
	KeyName string
}

// Provider implements the KMS provider interface for GCP KMS
type Provider struct {
	keyName string
	client  KMSClient
}

// NewProvider creates a new GCP KMS provider
func NewProvider(opts Options) (*Provider, error) {
	if opts.KeyName == "" {
		return nil, fmt.Errorf("key name is required")
	}

	return &Provider{
		keyName: opts.KeyName,
		client:  nil, // Lazy initialization
	}, nil
}

// NewProviderWithClient creates a new GCP KMS provider with a custom client (for testing)
func NewProviderWithClient(opts Options, client KMSClient) (*Provider, error) {
	if opts.KeyName == "" {
		return nil, fmt.Errorf("key name is required")
	}

	return &Provider{
		keyName: opts.KeyName,
		client:  client,
	}, nil
}

func (p *Provider) ensureClient(ctx context.Context) error {
	if p.client != nil {
		return nil
	}

	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create GCP KMS client: %w", err)
	}

	p.client = &kmsClientWrapper{client: client}
	return nil
}

// Name returns the provider name
func (p *Provider) Name() kmsprovider.ProviderName {
	return kmsprovider.ProviderGCPKMS
}

// KeyName returns the configured key name
func (p *Provider) KeyName() string {
	return p.keyName
}

// Encrypt encrypts plaintext using GCP KMS
func (p *Provider) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	if err := p.ensureClient(ctx); err != nil {
		return nil, err
	}

	// Calculate CRC32C checksum for integrity verification
	plaintextCRC32C := CRC32Checksum(plaintext)

	req := &kmspb.EncryptRequest{
		Name:            p.keyName,
		Plaintext:       plaintext,
		PlaintextCrc32C: wrapperspb.Int64(int64(plaintextCRC32C)),
	}

	resp, err := p.client.Encrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("GCP KMS encrypt failed: %w", err)
	}

	// Verify the integrity of the response
	if !resp.VerifiedPlaintextCrc32C {
		return nil, fmt.Errorf("GCP KMS encrypt: request corrupted in transit")
	}

	if int64(CRC32Checksum(resp.Ciphertext)) != resp.CiphertextCrc32C.Value {
		return nil, fmt.Errorf("GCP KMS encrypt: response corrupted in transit")
	}

	return resp.Ciphertext, nil
}

// Decrypt decrypts ciphertext using GCP KMS
func (p *Provider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if err := p.ensureClient(ctx); err != nil {
		return nil, err
	}

	// Calculate CRC32C checksum for integrity verification
	ciphertextCRC32C := CRC32Checksum(ciphertext)

	req := &kmspb.DecryptRequest{
		Name:             p.keyName,
		Ciphertext:       ciphertext,
		CiphertextCrc32C: wrapperspb.Int64(int64(ciphertextCRC32C)),
	}

	resp, err := p.client.Decrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("GCP KMS decrypt failed: %w", err)
	}

	// Verify the integrity of the response
	if int64(CRC32Checksum(resp.Plaintext)) != resp.PlaintextCrc32C.Value {
		return nil, fmt.Errorf("GCP KMS decrypt: response corrupted in transit")
	}

	return resp.Plaintext, nil
}

// Close closes the underlying client connection
func (p *Provider) Close() error {
	if p.client != nil {
		return p.client.Close()
	}
	return nil
}

// CRC32Checksum calculates the CRC32C checksum of data
func CRC32Checksum(data []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, t)
}
