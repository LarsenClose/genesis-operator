package azurekv

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	kmsprovider "github.com/larsenclose/genesis/internal/kms"
)

// KeyVaultClient defines the interface for Azure Key Vault operations
type KeyVaultClient interface {
	Encrypt(ctx context.Context, keyName string, keyVersion string, parameters azkeys.KeyOperationParameters, options *azkeys.EncryptOptions) (azkeys.EncryptResponse, error)
	Decrypt(ctx context.Context, keyName string, keyVersion string, parameters azkeys.KeyOperationParameters, options *azkeys.DecryptOptions) (azkeys.DecryptResponse, error)
}

// Options configures the Azure Key Vault provider
type Options struct {
	// VaultURL is the URL of the Azure Key Vault
	// Format: https://{vault-name}.vault.azure.net
	VaultURL string

	// KeyName is the name of the key in the vault
	KeyName string

	// KeyVersion is the specific version of the key (optional, uses latest if empty)
	KeyVersion string
}

// Provider implements the KMS provider interface for Azure Key Vault
type Provider struct {
	vaultURL   string
	keyName    string
	keyVersion string
	client     KeyVaultClient
}

// NewProvider creates a new Azure Key Vault provider
func NewProvider(opts Options) (*Provider, error) {
	if opts.VaultURL == "" {
		return nil, fmt.Errorf("vault URL is required")
	}
	if opts.KeyName == "" {
		return nil, fmt.Errorf("key name is required")
	}

	return &Provider{
		vaultURL:   opts.VaultURL,
		keyName:    opts.KeyName,
		keyVersion: opts.KeyVersion,
		client:     nil, // Lazy initialization
	}, nil
}

// NewProviderWithClient creates a new Azure Key Vault provider with a custom client (for testing)
func NewProviderWithClient(opts Options, client KeyVaultClient) (*Provider, error) {
	if opts.VaultURL == "" {
		return nil, fmt.Errorf("vault URL is required")
	}
	if opts.KeyName == "" {
		return nil, fmt.Errorf("key name is required")
	}

	return &Provider{
		vaultURL:   opts.VaultURL,
		keyName:    opts.KeyName,
		keyVersion: opts.KeyVersion,
		client:     client,
	}, nil
}

func (p *Provider) ensureClient(ctx context.Context) error {
	if p.client != nil {
		return nil
	}

	// Use DefaultAzureCredential which supports multiple authentication methods:
	// - Environment variables
	// - Managed Identity
	// - Azure CLI
	// - etc.
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to create Azure credential: %w", err)
	}

	client, err := azkeys.NewClient(p.vaultURL, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create Azure Key Vault client: %w", err)
	}

	p.client = client
	return nil
}

// Name returns the provider name
func (p *Provider) Name() kmsprovider.ProviderName {
	return kmsprovider.ProviderAzureKeyVault
}

// VaultURL returns the configured vault URL
func (p *Provider) VaultURL() string {
	return p.vaultURL
}

// KeyName returns the configured key name
func (p *Provider) KeyName() string {
	return p.keyName
}

// Encrypt encrypts plaintext using Azure Key Vault
func (p *Provider) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	if err := p.ensureClient(ctx); err != nil {
		return nil, err
	}

	// Use RSA-OAEP algorithm for encryption
	algorithm := azkeys.EncryptionAlgorithmRSAOAEP256

	params := azkeys.KeyOperationParameters{
		Algorithm: &algorithm,
		Value:     plaintext,
	}

	resp, err := p.client.Encrypt(ctx, p.keyName, p.keyVersion, params, nil)
	if err != nil {
		return nil, fmt.Errorf("Azure Key Vault encrypt failed: %w", err)
	}

	return resp.Result, nil
}

// Decrypt decrypts ciphertext using Azure Key Vault
func (p *Provider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if err := p.ensureClient(ctx); err != nil {
		return nil, err
	}

	// Use RSA-OAEP algorithm for decryption
	algorithm := azkeys.EncryptionAlgorithmRSAOAEP256

	params := azkeys.KeyOperationParameters{
		Algorithm: &algorithm,
		Value:     ciphertext,
	}

	resp, err := p.client.Decrypt(ctx, p.keyName, p.keyVersion, params, nil)
	if err != nil {
		return nil, fmt.Errorf("Azure Key Vault decrypt failed: %w", err)
	}

	return resp.Result, nil
}
