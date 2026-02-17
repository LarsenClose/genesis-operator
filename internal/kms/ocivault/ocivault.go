// Package ocivault implements the KMS provider interface for Oracle Cloud Infrastructure Vault.
package ocivault

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"

	kmsprovider "github.com/larsenclose/genesis/internal/kms"
)

// KMSClient defines the interface for OCI KMS operations
type KMSClient interface {
	Encrypt(ctx context.Context, request keymanagement.EncryptRequest) (keymanagement.EncryptResponse, error)
	Decrypt(ctx context.Context, request keymanagement.DecryptRequest) (keymanagement.DecryptResponse, error)
}

// Options configures the OCI Vault provider
type Options struct {
	// KeyOCID is the OCID of the master encryption key
	// Format: ocid1.key.oc1.<region>.<unique_id>
	KeyOCID string

	// CryptoEndpoint is the cryptographic endpoint for the vault
	// Format: https://<vault_crypto_endpoint>
	// If not provided, it will be derived from the key OCID region
	CryptoEndpoint string

	// ConfigProvider is an optional custom OCI configuration provider
	// If not provided, the default config provider chain will be used
	ConfigProvider common.ConfigurationProvider
}

// Provider implements the KMS provider interface for OCI Vault
type Provider struct {
	keyOCID        string
	cryptoEndpoint string
	configProvider common.ConfigurationProvider
	client         KMSClient
}

// NewProvider creates a new OCI Vault provider
func NewProvider(opts Options) (*Provider, error) {
	if opts.KeyOCID == "" {
		return nil, fmt.Errorf("key OCID is required")
	}

	cryptoEndpoint := opts.CryptoEndpoint
	if cryptoEndpoint == "" {
		// Try to derive the crypto endpoint from the key OCID
		region := extractRegionFromOCID(opts.KeyOCID)
		if region == "" {
			return nil, fmt.Errorf("crypto endpoint is required (could not derive from key OCID)")
		}
		// OCI Vault crypto endpoints follow this pattern
		cryptoEndpoint = fmt.Sprintf("https://%s-crypto.kms.%s.oraclecloud.com", extractVaultID(opts.KeyOCID), region)
	}

	configProvider := opts.ConfigProvider
	if configProvider == nil {
		// Use the default config provider chain (reads from ~/.oci/config)
		configProvider = common.DefaultConfigProvider()
	}

	return &Provider{
		keyOCID:        opts.KeyOCID,
		cryptoEndpoint: cryptoEndpoint,
		configProvider: configProvider,
		client:         nil, // Lazy initialization
	}, nil
}

// NewProviderWithClient creates a new OCI Vault provider with a custom client (for testing)
func NewProviderWithClient(opts Options, client KMSClient) (*Provider, error) {
	if opts.KeyOCID == "" {
		return nil, fmt.Errorf("key OCID is required")
	}

	return &Provider{
		keyOCID:        opts.KeyOCID,
		cryptoEndpoint: opts.CryptoEndpoint,
		configProvider: opts.ConfigProvider,
		client:         client,
	}, nil
}

func (p *Provider) ensureClient(ctx context.Context) error {
	if p.client != nil {
		return nil
	}

	client, err := keymanagement.NewKmsCryptoClientWithConfigurationProvider(p.configProvider, p.cryptoEndpoint)
	if err != nil {
		return fmt.Errorf("failed to create OCI KMS client: %w", err)
	}

	p.client = &client
	return nil
}

// Name returns the provider name
func (p *Provider) Name() kmsprovider.ProviderName {
	return kmsprovider.ProviderOCIVault
}

// KeyOCID returns the configured key OCID
func (p *Provider) KeyOCID() string {
	return p.keyOCID
}

// CryptoEndpoint returns the configured crypto endpoint
func (p *Provider) CryptoEndpoint() string {
	return p.cryptoEndpoint
}

// Encrypt encrypts plaintext using OCI Vault KMS
func (p *Provider) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	if err := p.ensureClient(ctx); err != nil {
		return nil, err
	}

	// OCI KMS expects base64-encoded plaintext
	encodedPlaintext := base64.StdEncoding.EncodeToString(plaintext)

	request := keymanagement.EncryptRequest{
		EncryptDataDetails: keymanagement.EncryptDataDetails{
			KeyId:     common.String(p.keyOCID),
			Plaintext: common.String(encodedPlaintext),
		},
	}

	response, err := p.client.Encrypt(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("OCI KMS encrypt failed: %w", err)
	}

	if response.Ciphertext == nil {
		return nil, fmt.Errorf("OCI KMS encrypt: empty ciphertext in response")
	}

	// The ciphertext is already base64-encoded by OCI, decode it for storage
	ciphertext, err := base64.StdEncoding.DecodeString(*response.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("OCI KMS encrypt: failed to decode ciphertext: %w", err)
	}

	return ciphertext, nil
}

// Decrypt decrypts ciphertext using OCI Vault KMS
func (p *Provider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if err := p.ensureClient(ctx); err != nil {
		return nil, err
	}

	// OCI KMS expects base64-encoded ciphertext
	encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)

	request := keymanagement.DecryptRequest{
		DecryptDataDetails: keymanagement.DecryptDataDetails{
			KeyId:      common.String(p.keyOCID),
			Ciphertext: common.String(encodedCiphertext),
		},
	}

	response, err := p.client.Decrypt(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("OCI KMS decrypt failed: %w", err)
	}

	if response.Plaintext == nil {
		return nil, fmt.Errorf("OCI KMS decrypt: empty plaintext in response")
	}

	// The plaintext is base64-encoded, decode it
	plaintext, err := base64.StdEncoding.DecodeString(*response.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("OCI KMS decrypt: failed to decode plaintext: %w", err)
	}

	return plaintext, nil
}

// extractRegionFromOCID extracts the region from an OCI resource OCID
// OCIDs have the format: ocid1.<resource_type>.oc1.<region>.<unique_id>
func extractRegionFromOCID(ocid string) string {
	parts := strings.Split(ocid, ".")
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}

// extractVaultID extracts a vault identifier hint from the key OCID
// This is used to construct the crypto endpoint when not explicitly provided
func extractVaultID(keyOCID string) string {
	parts := strings.Split(keyOCID, ".")
	if len(parts) >= 5 {
		// Use first 8 chars of the unique ID as vault identifier
		uniqueID := parts[4]
		if len(uniqueID) > 8 {
			return uniqueID[:8]
		}
		return uniqueID
	}
	return "default"
}
