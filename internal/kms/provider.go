// Package kms provides the KMS provider abstraction for Genesis envelope encryption.
// It defines a common interface for all KMS providers (AWS KMS, GCP KMS, Azure Key Vault,
// YubiKey PIV, TPM 2.0) and a thread-safe registry for managing provider instances.
package kms

import (
	"context"
	"sync"
)

// ProviderName identifies a KMS provider type.
type ProviderName string

// Supported KMS provider types.
const (
	ProviderMock          ProviderName = "mock"
	ProviderAWSKMS        ProviderName = "aws-kms"
	ProviderGCPKMS        ProviderName = "gcp-kms"
	ProviderAzureKeyVault ProviderName = "azure-keyvault"
	ProviderOCIVault      ProviderName = "oci-vault"
	ProviderYubiKey       ProviderName = "yubikey"
	ProviderTPM           ProviderName = "tpm"
)

// Provider defines the interface that all KMS providers must implement.
// Implementations are responsible for encrypting and decrypting the age private key
// using their respective KMS backends.
type Provider interface {
	// Name returns the unique identifier for this provider type.
	Name() ProviderName

	// Encrypt encrypts the plaintext using the KMS backend.
	// The returned ciphertext can only be decrypted by the same KMS key.
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)

	// Decrypt decrypts the ciphertext using the KMS backend.
	// Returns the original plaintext if the ciphertext was encrypted with the same key.
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
}

// Registry manages a collection of KMS providers.
// It is safe for concurrent use by multiple goroutines.
type Registry struct {
	mu        sync.RWMutex
	providers map[ProviderName]Provider
}

// NewRegistry creates a new empty provider registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[ProviderName]Provider),
	}
}

// Register adds a provider to the registry.
// If a provider with the same name already exists, it is replaced.
func (r *Registry) Register(p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.Name()] = p
}

// Get retrieves a provider by name from the registry.
// Returns nil if no provider with the given name is registered.
// Callers should check the return value before use.
func (r *Registry) Get(name ProviderName) Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.providers[name]
}

// List returns the names of all registered providers.
// The order of names is not guaranteed.
func (r *Registry) List() []ProviderName {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]ProviderName, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	return names
}
