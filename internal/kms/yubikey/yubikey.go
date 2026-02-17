package yubikey

import (
	"context"
	"fmt"

	kmsprovider "github.com/larsenclose/genesis/internal/kms"
)

// PIVSlot represents a YubiKey PIV slot
type PIVSlot string

const (
	// SlotAuthentication is the PIV authentication slot (9a)
	SlotAuthentication PIVSlot = "9a"
	// SlotSignature is the PIV signature slot (9c)
	SlotSignature PIVSlot = "9c"
	// SlotKeyManagement is the PIV key management slot (9d)
	SlotKeyManagement PIVSlot = "9d"
	// SlotCardAuth is the PIV card authentication slot (9e)
	SlotCardAuth PIVSlot = "9e"
)

// PIVClient defines the interface for YubiKey PIV operations
type PIVClient interface {
	// Encrypt encrypts data using the public key in the specified slot
	Encrypt(ctx context.Context, slot PIVSlot, plaintext []byte) ([]byte, error)
	// Decrypt decrypts data using the private key in the specified slot
	Decrypt(ctx context.Context, slot PIVSlot, ciphertext []byte) ([]byte, error)
	// GetPublicKeyFingerprint returns the SHA256 fingerprint of the public key
	GetPublicKeyFingerprint(ctx context.Context, slot PIVSlot) (string, error)
	// Close releases any resources
	Close() error
}

// Options configures the YubiKey PIV provider
type Options struct {
	// Slot is the PIV slot to use (default: 9a)
	Slot PIVSlot

	// PublicKeyFingerprint is the expected SHA256 fingerprint of the public key
	// Used to verify the correct YubiKey is being used
	PublicKeyFingerprint string

	// PIN is the PIV PIN (optional, may prompt user if not provided)
	PIN string
}

// Provider implements the KMS provider interface for YubiKey PIV
type Provider struct {
	slot                 PIVSlot
	publicKeyFingerprint string
	pin                  string
	client               PIVClient
}

// NewProvider creates a new YubiKey PIV provider
// Note: Real YubiKey support requires the piv-go library and CGO
func NewProvider(opts Options) (*Provider, error) {
	slot := opts.Slot
	if slot == "" {
		slot = SlotAuthentication
	}

	if !isValidSlot(slot) {
		return nil, fmt.Errorf("invalid PIV slot: %s", slot)
	}

	return &Provider{
		slot:                 slot,
		publicKeyFingerprint: opts.PublicKeyFingerprint,
		pin:                  opts.PIN,
		client:               nil, // Real implementation requires piv-go
	}, nil
}

// NewProviderWithClient creates a new YubiKey PIV provider with a custom client (for testing)
func NewProviderWithClient(opts Options, client PIVClient) (*Provider, error) {
	slot := opts.Slot
	if slot == "" {
		slot = SlotAuthentication
	}

	if !isValidSlot(slot) {
		return nil, fmt.Errorf("invalid PIV slot: %s", slot)
	}

	return &Provider{
		slot:                 slot,
		publicKeyFingerprint: opts.PublicKeyFingerprint,
		pin:                  opts.PIN,
		client:               client,
	}, nil
}

func (p *Provider) ensureClient(ctx context.Context) error {
	if p.client != nil {
		return nil
	}

	// Real implementation would initialize piv-go client here
	// For now, return an error indicating YubiKey support requires additional setup
	return fmt.Errorf("YubiKey support requires the piv-go library; please use NewProviderWithClient for testing")
}

// Name returns the provider name
func (p *Provider) Name() kmsprovider.ProviderName {
	return kmsprovider.ProviderYubiKey
}

// Slot returns the configured PIV slot
func (p *Provider) Slot() PIVSlot {
	return p.slot
}

// Encrypt encrypts plaintext using the YubiKey PIV slot
func (p *Provider) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	if err := p.ensureClient(ctx); err != nil {
		return nil, err
	}

	// Verify public key fingerprint if configured
	if p.publicKeyFingerprint != "" {
		fingerprint, err := p.client.GetPublicKeyFingerprint(ctx, p.slot)
		if err != nil {
			return nil, fmt.Errorf("failed to get public key fingerprint: %w", err)
		}
		if fingerprint != p.publicKeyFingerprint {
			return nil, fmt.Errorf("public key fingerprint mismatch: expected %s, got %s",
				p.publicKeyFingerprint, fingerprint)
		}
	}

	ciphertext, err := p.client.Encrypt(ctx, p.slot, plaintext)
	if err != nil {
		return nil, fmt.Errorf("YubiKey encrypt failed: %w", err)
	}

	return ciphertext, nil
}

// Decrypt decrypts ciphertext using the YubiKey PIV slot
func (p *Provider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if err := p.ensureClient(ctx); err != nil {
		return nil, err
	}

	plaintext, err := p.client.Decrypt(ctx, p.slot, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("YubiKey decrypt failed: %w", err)
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

func isValidSlot(slot PIVSlot) bool {
	switch slot {
	case SlotAuthentication, SlotSignature, SlotKeyManagement, SlotCardAuth:
		return true
	default:
		return false
	}
}
