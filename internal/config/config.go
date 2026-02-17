package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/larsenclose/genesis/internal/kms"
	"gopkg.in/yaml.v3"
)

const (
	APIVersion    = "genesis.io/v1alpha1"
	KindBootstrap = "GenesisBootstrap"
)

type BootstrapConfig struct {
	APIVersion string        `yaml:"apiVersion"`
	Kind       string        `yaml:"kind"`
	Metadata   Metadata      `yaml:"metadata"`
	Spec       BootstrapSpec `yaml:"spec"`
}

type Metadata struct {
	Name      string `yaml:"name,omitempty"`
	Namespace string `yaml:"namespace,omitempty"`
}

type BootstrapSpec struct {
	Envelope EnvelopeSpec `yaml:"envelope"`
	Output   OutputSpec   `yaml:"output"`
}

type EnvelopeSpec struct {
	Provider      kms.ProviderName `yaml:"provider"`
	PublicKey     string           `yaml:"publicKey,omitempty"`
	AWSKMS        *AWSKMSSpec      `yaml:"awsKms,omitempty"`
	GCPKMS        *GCPKMSSpec      `yaml:"gcpKms,omitempty"`
	AzureKeyVault *AzureKVSpec     `yaml:"azureKeyVault,omitempty"`
	OCIVault      *OCIVaultSpec    `yaml:"ociVault,omitempty"`
	YubiKey       *YubiKeySpec     `yaml:"yubikey,omitempty"`
	TPM           *TPMSpec         `yaml:"tpm,omitempty"`
	Ciphertext    string           `yaml:"ciphertext"`
}

type AWSKMSSpec struct {
	KeyArn string `yaml:"keyArn"`
	Region string `yaml:"region"`
}

type GCPKMSSpec struct {
	KeyName string `yaml:"keyName"`
}

type AzureKVSpec struct {
	VaultURL   string `yaml:"vaultUrl"`
	KeyName    string `yaml:"keyName"`
	KeyVersion string `yaml:"keyVersion,omitempty"`
}

type OCIVaultSpec struct {
	KeyOCID        string `yaml:"keyOcid"`
	CryptoEndpoint string `yaml:"cryptoEndpoint"`
}

type YubiKeySpec struct {
	Slot                 string `yaml:"slot,omitempty"`
	PublicKeyFingerprint string `yaml:"publicKeyFingerprint,omitempty"`
}

type TPMSpec struct {
	DevicePath   string            `yaml:"devicePath,omitempty"`
	PCRSelection *PCRSelectionSpec `yaml:"pcrSelection,omitempty"`
}

type PCRSelectionSpec struct {
	Hash string `yaml:"hash,omitempty"`
	PCRs []int  `yaml:"pcrs,omitempty"`
}

type OutputSpec struct {
	SecretName           string   `yaml:"secretName"`
	SecretNamespace      string   `yaml:"secretNamespace"`
	SecretKey            string   `yaml:"secretKey"`
	AdditionalNamespaces []string `yaml:"additionalNamespaces,omitempty"`
}

func (c *BootstrapConfig) Validate() error {
	if c.APIVersion != APIVersion {
		return fmt.Errorf("invalid apiVersion: expected %s, got %s", APIVersion, c.APIVersion)
	}
	if c.Kind != KindBootstrap {
		return fmt.Errorf("invalid kind: expected %s, got %s", KindBootstrap, c.Kind)
	}
	if c.Spec.Envelope.Provider == "" {
		return errors.New("envelope.provider is required")
	}
	if c.Spec.Envelope.Ciphertext == "" {
		return errors.New("envelope.ciphertext is required")
	}

	switch c.Spec.Envelope.Provider {
	case kms.ProviderAWSKMS:
		if c.Spec.Envelope.AWSKMS == nil || c.Spec.Envelope.AWSKMS.KeyArn == "" {
			return errors.New("awsKms.keyArn is required for aws-kms provider")
		}
	case kms.ProviderGCPKMS:
		if c.Spec.Envelope.GCPKMS == nil || c.Spec.Envelope.GCPKMS.KeyName == "" {
			return errors.New("gcpKms.keyName is required for gcp-kms provider")
		}
	case kms.ProviderAzureKeyVault:
		if c.Spec.Envelope.AzureKeyVault == nil || c.Spec.Envelope.AzureKeyVault.VaultURL == "" {
			return errors.New("azureKeyVault.vaultUrl is required for azure-keyvault provider")
		}
	case kms.ProviderOCIVault:
		if c.Spec.Envelope.OCIVault == nil || c.Spec.Envelope.OCIVault.KeyOCID == "" {
			return errors.New("ociVault.keyOcid is required for oci-vault provider")
		}
		if c.Spec.Envelope.OCIVault.CryptoEndpoint == "" {
			return errors.New("ociVault.cryptoEndpoint is required for oci-vault provider")
		}
	case kms.ProviderYubiKey:
		// YubiKey config is optional (uses defaults)
	case kms.ProviderTPM:
		// TPM config is optional (uses defaults)
	case kms.ProviderMock:
	default:
		return fmt.Errorf("unsupported provider: %s", c.Spec.Envelope.Provider)
	}

	return nil
}

func Load(path string) (*BootstrapConfig, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is from user-specified config
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg BootstrapConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &cfg, nil
}

func Save(path string, cfg *BootstrapConfig) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil { // #nosec G306 -- config files are non-sensitive and must be readable
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
