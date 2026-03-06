// Package bridge -- KMS config JSON builder for the Rust FFI boundary.
//
// BuildKmsConfigJSON constructs the JSON payload that the Rust genesis-core
// KmsConfig expects: {"provider_type":"...", "settings":{...}}.
//
// The Go side resolves credentials (from env vars, cloud SDK, or CRD spec)
// and packs them into the settings object so Rust providers can use
// from_config() without needing access to the process environment.
package bridge

import (
	"encoding/json"
	"fmt"
	"os"

	genesisv1alpha1 "github.com/larsenclose/genesis/pkg/api/v1alpha1"
)

// KmsConfig mirrors the Rust genesis_core::kms::config::KmsConfig struct.
type KmsConfig struct {
	ProviderType string                 `json:"provider_type"`
	Settings     map[string]interface{} `json:"settings"`
}

// BuildKmsConfigJSON constructs a KmsConfig JSON string from a GenesisBootstrap
// spec. It resolves credentials from the CRD spec fields and environment
// variables, packing everything into the settings map so Rust providers can
// construct themselves via from_config().
func BuildKmsConfigJSON(envelope *genesisv1alpha1.EnvelopeSpec) (string, error) {
	if envelope == nil {
		return "", fmt.Errorf("envelope spec is nil")
	}

	config := KmsConfig{
		ProviderType: mapProviderName(envelope.Provider),
		Settings:     make(map[string]interface{}),
	}

	switch envelope.Provider {
	case "aws-kms":
		if err := buildAWSSettings(envelope.AWSKms, config.Settings); err != nil {
			return "", fmt.Errorf("aws-kms: %w", err)
		}
	case "gcp-kms":
		if err := buildGCPSettings(envelope.GCPKms, config.Settings); err != nil {
			return "", fmt.Errorf("gcp-kms: %w", err)
		}
	case "azure-keyvault":
		if err := buildAzureSettings(envelope.AzureKeyVault, config.Settings); err != nil {
			return "", fmt.Errorf("azure-keyvault: %w", err)
		}
	case "mock":
		// No settings needed for mock provider.
	default:
		return "", fmt.Errorf("unsupported provider for Rust bridge: %s", envelope.Provider)
	}

	data, err := json.Marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal KmsConfig: %w", err)
	}
	return string(data), nil
}

// mapProviderName converts CRD provider names to Rust provider_type strings.
func mapProviderName(provider string) string {
	switch provider {
	case "aws-kms":
		return "aws"
	case "gcp-kms":
		return "gcp"
	case "azure-keyvault":
		return "azure"
	default:
		return provider
	}
}

func buildAWSSettings(spec *genesisv1alpha1.AWSKmsSpec, settings map[string]interface{}) error {
	if spec == nil {
		return fmt.Errorf("awsKms configuration required")
	}

	settings["key_arn"] = spec.KeyArn

	if spec.Region != "" {
		settings["region"] = spec.Region
	} else if r := os.Getenv("AWS_DEFAULT_REGION"); r != "" {
		settings["region"] = r
	}

	// Resolve credentials from environment.
	if ak := os.Getenv("AWS_ACCESS_KEY_ID"); ak != "" {
		settings["access_key_id"] = ak
	}
	if sk := os.Getenv("AWS_SECRET_ACCESS_KEY"); sk != "" {
		settings["secret_access_key"] = sk
	}
	if st := os.Getenv("AWS_SESSION_TOKEN"); st != "" {
		settings["session_token"] = st
	}

	return nil
}

func buildGCPSettings(spec *genesisv1alpha1.GCPKmsSpec, settings map[string]interface{}) error {
	if spec == nil {
		return fmt.Errorf("gcpKms configuration required")
	}

	settings["key_resource_name"] = spec.KeyName

	// Resolve access token from environment.
	if token := os.Getenv("GENESIS_GCP_ACCESS_TOKEN"); token != "" {
		settings["access_token"] = token
	}

	return nil
}

func buildAzureSettings(spec *genesisv1alpha1.AzureKeyVaultSpec, settings map[string]interface{}) error {
	if spec == nil {
		return fmt.Errorf("azureKeyVault configuration required")
	}

	settings["vault_url"] = spec.VaultUrl
	settings["key_name"] = spec.KeyName

	if spec.KeyVersion != "" {
		settings["key_version"] = spec.KeyVersion
	}

	// Resolve access token from environment.
	if token := os.Getenv("AZURE_ACCESS_TOKEN"); token != "" {
		settings["access_token"] = token
	}

	return nil
}
