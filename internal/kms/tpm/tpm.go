package tpm

import (
	"context"
	"fmt"

	kmsprovider "github.com/larsenclose/genesis/internal/kms"
)

// HashAlgorithm represents a TPM hash algorithm
type HashAlgorithm string

const (
	// HashSHA256 is SHA-256
	HashSHA256 HashAlgorithm = "sha256"
	// HashSHA384 is SHA-384
	HashSHA384 HashAlgorithm = "sha384"
	// HashSHA512 is SHA-512
	HashSHA512 HashAlgorithm = "sha512"
)

// PCRSelection defines which PCRs to use for sealing
type PCRSelection struct {
	// Hash is the hash algorithm to use
	Hash HashAlgorithm

	// PCRs is the list of PCR indices to include in the policy
	PCRs []int
}

// TPMClient defines the interface for TPM 2.0 operations
type TPMClient interface {
	// Seal seals data to the TPM with the specified PCR policy
	Seal(ctx context.Context, plaintext []byte, pcrSelection *PCRSelection) ([]byte, error)
	// Unseal unseals data from the TPM (PCRs must match)
	Unseal(ctx context.Context, sealed []byte) ([]byte, error)
	// GetPCRValues returns the current PCR values
	GetPCRValues(ctx context.Context, pcrSelection *PCRSelection) (map[int][]byte, error)
	// Close releases any resources
	Close() error
}

// Options configures the TPM 2.0 provider
type Options struct {
	// DevicePath is the path to the TPM device (default: /dev/tpmrm0)
	DevicePath string

	// PCRSelection defines which PCRs to use for sealing
	PCRSelection *PCRSelection
}

// Provider implements the KMS provider interface for TPM 2.0
type Provider struct {
	devicePath   string
	pcrSelection *PCRSelection
	client       TPMClient
}

// NewProvider creates a new TPM 2.0 provider
// Note: Real TPM support requires the go-tpm library
func NewProvider(opts Options) (*Provider, error) {
	devicePath := opts.DevicePath
	if devicePath == "" {
		devicePath = "/dev/tpmrm0"
	}

	pcrSelection := opts.PCRSelection
	if pcrSelection == nil {
		// Default PCR selection for secure boot validation
		pcrSelection = &PCRSelection{
			Hash: HashSHA256,
			PCRs: []int{0, 1, 2, 3, 7},
		}
	}

	if err := validatePCRSelection(pcrSelection); err != nil {
		return nil, err
	}

	return &Provider{
		devicePath:   devicePath,
		pcrSelection: pcrSelection,
		client:       nil, // Real implementation requires go-tpm
	}, nil
}

// NewProviderWithClient creates a new TPM 2.0 provider with a custom client (for testing)
func NewProviderWithClient(opts Options, client TPMClient) (*Provider, error) {
	devicePath := opts.DevicePath
	if devicePath == "" {
		devicePath = "/dev/tpmrm0"
	}

	pcrSelection := opts.PCRSelection
	if pcrSelection == nil {
		pcrSelection = &PCRSelection{
			Hash: HashSHA256,
			PCRs: []int{0, 1, 2, 3, 7},
		}
	}

	if err := validatePCRSelection(pcrSelection); err != nil {
		return nil, err
	}

	return &Provider{
		devicePath:   devicePath,
		pcrSelection: pcrSelection,
		client:       client,
	}, nil
}

func (p *Provider) ensureClient(ctx context.Context) error {
	if p.client != nil {
		return nil
	}

	// Real implementation would initialize go-tpm client here
	return fmt.Errorf("TPM support requires the go-tpm library; please use NewProviderWithClient for testing")
}

// Name returns the provider name
func (p *Provider) Name() kmsprovider.ProviderName {
	return kmsprovider.ProviderTPM
}

// DevicePath returns the configured device path
func (p *Provider) DevicePath() string {
	return p.devicePath
}

// PCRSelection returns the configured PCR selection
func (p *Provider) PCRSelection() *PCRSelection {
	return p.pcrSelection
}

// Encrypt seals plaintext to the TPM
func (p *Provider) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	if err := p.ensureClient(ctx); err != nil {
		return nil, err
	}

	sealed, err := p.client.Seal(ctx, plaintext, p.pcrSelection)
	if err != nil {
		return nil, fmt.Errorf("TPM seal failed: %w", err)
	}

	return sealed, nil
}

// Decrypt unseals ciphertext from the TPM
func (p *Provider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if err := p.ensureClient(ctx); err != nil {
		return nil, err
	}

	plaintext, err := p.client.Unseal(ctx, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("TPM unseal failed: %w", err)
	}

	return plaintext, nil
}

// Close releases any resources
func (p *Provider) Close() error {
	if p.client != nil {
		return p.client.Close()
	}
	return nil
}

// GetPCRValues returns the current PCR values
func (p *Provider) GetPCRValues(ctx context.Context) (map[int][]byte, error) {
	if err := p.ensureClient(ctx); err != nil {
		return nil, err
	}

	return p.client.GetPCRValues(ctx, p.pcrSelection)
}

func validatePCRSelection(sel *PCRSelection) error {
	if sel == nil {
		return fmt.Errorf("PCR selection is required")
	}

	switch sel.Hash {
	case HashSHA256, HashSHA384, HashSHA512:
		// Valid
	default:
		return fmt.Errorf("invalid hash algorithm: %s", sel.Hash)
	}

	if len(sel.PCRs) == 0 {
		return fmt.Errorf("at least one PCR must be selected")
	}

	for _, pcr := range sel.PCRs {
		if pcr < 0 || pcr > 23 {
			return fmt.Errorf("invalid PCR index: %d (must be 0-23)", pcr)
		}
	}

	return nil
}
