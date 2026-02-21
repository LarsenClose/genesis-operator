package main

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/larsenclose/genesis/internal/config"
	"github.com/larsenclose/genesis/internal/envelope"
	"github.com/larsenclose/genesis/internal/kms"
	"github.com/larsenclose/genesis/internal/kms/awskms"
	"github.com/larsenclose/genesis/internal/kms/azurekv"
	"github.com/larsenclose/genesis/internal/kms/gcpkms"
	"github.com/larsenclose/genesis/internal/kms/mock"
	"github.com/larsenclose/genesis/internal/kms/ocivault"
	"github.com/larsenclose/genesis/internal/kms/tpm"
	"github.com/larsenclose/genesis/internal/kms/yubikey"
	"github.com/spf13/cobra"
)

var (
	rotateConfigPath  string
	rotateNewProvider string
	rotateNewKeyArn   string
	rotateNewKeyName  string
	rotateNewVaultURL string
	rotateNewKeyOCID  string
	rotateNewCryptoEP string
)

var rotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "Rotate the master key by re-encrypting with a new envelope",
	Long: `Rotate the genesis master key by decrypting the current envelope
and re-encrypting it with a new KMS key.

This is useful for:
  - Key rotation policies
  - Migrating to a different KMS key
  - Changing cloud regions

The age keypair itself is NOT regenerated - only the envelope encryption
is changed. This means all existing SOPS-encrypted secrets remain valid.

Example:
  genesis rotate \
    --config ./clusters/production/genesis/genesis-bootstrap.yaml \
    --new-key-arn arn:aws:kms:us-west-2:123456789012:key/new-key`,
	RunE: runRotate,
}

func init() {
	rotateCmd.Flags().StringVar(&rotateConfigPath, "config", "", "Path to genesis bootstrap config file")
	rotateCmd.Flags().StringVar(&rotateNewProvider, "new-provider", "", "New KMS provider (aws-kms, gcp-kms, azure-keyvault, oci-vault, mock)")
	rotateCmd.Flags().StringVar(&rotateNewKeyArn, "new-key-arn", "", "New AWS KMS key ARN for re-encryption")
	rotateCmd.Flags().StringVar(&rotateNewKeyName, "new-key-name", "", "New GCP KMS key name for re-encryption")
	rotateCmd.Flags().StringVar(&rotateNewVaultURL, "new-vault-url", "", "New Azure Key Vault URL for re-encryption")
	rotateCmd.Flags().StringVar(&rotateNewKeyOCID, "new-key-ocid", "", "New OCI Vault key OCID for re-encryption")
	rotateCmd.Flags().StringVar(&rotateNewCryptoEP, "new-crypto-endpoint", "", "New OCI Vault crypto endpoint for re-encryption")

	_ = rotateCmd.MarkFlagRequired("config") // Error ignored as cobra panics on invalid flag name
	rootCmd.AddCommand(rotateCmd)
}

func runRotate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	verboseLog("Loading config from: %s", rotateConfigPath)
	cfg, err := config.Load(rotateConfigPath)
	if err != nil {
		printError(fmt.Errorf("failed to load config: %w", err))
		return err
	}

	if err := cfg.Validate(); err != nil {
		printError(fmt.Errorf("invalid config: %w", err))
		return err
	}

	verboseLog("Creating current KMS provider for decryption...")
	currentProvider, err := createRotateProvider(ctx, cfg)
	if err != nil {
		printError(err)
		return err
	}

	verboseLog("Decrypting current envelope...")
	ciphertext, err := base64.StdEncoding.DecodeString(cfg.Spec.Envelope.Ciphertext)
	if err != nil {
		printError(fmt.Errorf("failed to decode ciphertext: %w", err))
		return err
	}

	env := &envelope.Envelope{
		Provider:   cfg.Spec.Envelope.Provider,
		PublicKey:  cfg.Spec.Envelope.PublicKey,
		Ciphertext: ciphertext,
	}

	privateKey, err := envelope.Open(ctx, currentProvider, env)
	if err != nil {
		printError(fmt.Errorf("failed to decrypt envelope: %w", err))
		return err
	}

	verboseLog("Creating new KMS provider for re-encryption...")
	newProvider, newProviderName, err := createNewRotateProvider(ctx)
	if err != nil {
		printError(fmt.Errorf("failed to create new KMS provider: %w", err))
		return err
	}

	verboseLog("Creating new envelope with new KMS key...")
	newEnv, err := envelope.Create(ctx, newProvider, privateKey)
	if err != nil {
		printError(fmt.Errorf("failed to create new envelope: %w", err))
		return err
	}

	oldProviderName := cfg.Spec.Envelope.Provider
	cfg.Spec.Envelope.Provider = newProviderName
	cfg.Spec.Envelope.Ciphertext = newEnv.CiphertextB64
	updateRotateConfigSpec(cfg, newProviderName)

	verboseLog("Saving updated config to: %s", rotateConfigPath)
	if err := config.Save(rotateConfigPath, cfg); err != nil {
		printError(fmt.Errorf("failed to save config: %w", err))
		return err
	}

	result := RotateResult{
		Success:     true,
		OldProvider: string(oldProviderName),
		NewProvider: string(newProviderName),
		PublicKey:   cfg.Spec.Envelope.PublicKey,
	}

	if jsonOutput {
		printOutput(result)
	} else {
		fmt.Println("Key rotation successful!")
		fmt.Println()
		fmt.Printf("  New Provider: %s\n", newProviderName)
		fmt.Printf("  Public Key:   %s (unchanged)\n", cfg.Spec.Envelope.PublicKey)
		fmt.Println()
		fmt.Println("The genesis configuration has been updated with the new envelope.")
		fmt.Println("Remember to commit and push the changes to your git repository.")
	}

	return nil
}

type RotateResult struct {
	Success     bool   `json:"success"`
	OldProvider string `json:"oldProvider"`
	NewProvider string `json:"newProvider"`
	PublicKey   string `json:"publicKey"`
}

func createRotateProvider(ctx context.Context, cfg *config.BootstrapConfig) (kms.Provider, error) {
	switch cfg.Spec.Envelope.Provider {
	case kms.ProviderAWSKMS:
		if cfg.Spec.Envelope.AWSKMS == nil {
			return nil, fmt.Errorf("awsKms configuration missing")
		}
		return awskms.NewProvider(awskms.Options{
			KeyArn: cfg.Spec.Envelope.AWSKMS.KeyArn,
			Region: cfg.Spec.Envelope.AWSKMS.Region,
		})

	case kms.ProviderGCPKMS:
		if cfg.Spec.Envelope.GCPKMS == nil {
			return nil, fmt.Errorf("gcpKms configuration missing")
		}
		return gcpkms.NewProvider(gcpkms.Options{
			KeyName: cfg.Spec.Envelope.GCPKMS.KeyName,
		})

	case kms.ProviderAzureKeyVault:
		if cfg.Spec.Envelope.AzureKeyVault == nil {
			return nil, fmt.Errorf("azureKeyVault configuration missing")
		}
		return azurekv.NewProvider(azurekv.Options{
			VaultURL:   cfg.Spec.Envelope.AzureKeyVault.VaultURL,
			KeyName:    cfg.Spec.Envelope.AzureKeyVault.KeyName,
			KeyVersion: cfg.Spec.Envelope.AzureKeyVault.KeyVersion,
		})

	case kms.ProviderYubiKey:
		slot := yubikey.SlotAuthentication
		fingerprint := ""
		if cfg.Spec.Envelope.YubiKey != nil {
			slot = yubikey.PIVSlot(cfg.Spec.Envelope.YubiKey.Slot)
			fingerprint = cfg.Spec.Envelope.YubiKey.PublicKeyFingerprint
		}
		return yubikey.NewProvider(yubikey.Options{
			Slot:                 slot,
			PublicKeyFingerprint: fingerprint,
		})

	case kms.ProviderOCIVault:
		if cfg.Spec.Envelope.OCIVault == nil {
			return nil, fmt.Errorf("ociVault configuration missing")
		}
		return ocivault.NewProvider(ocivault.Options{
			KeyOCID:        cfg.Spec.Envelope.OCIVault.KeyOCID,
			CryptoEndpoint: cfg.Spec.Envelope.OCIVault.CryptoEndpoint,
		})

	case kms.ProviderTPM:
		device := "/dev/tpmrm0"
		var pcrSelection *tpm.PCRSelection
		if cfg.Spec.Envelope.TPM != nil {
			device = cfg.Spec.Envelope.TPM.DevicePath
			if cfg.Spec.Envelope.TPM.PCRSelection != nil {
				pcrSelection = &tpm.PCRSelection{
					Hash: tpm.HashAlgorithm(cfg.Spec.Envelope.TPM.PCRSelection.Hash),
					PCRs: cfg.Spec.Envelope.TPM.PCRSelection.PCRs,
				}
			}
		}
		return tpm.NewProvider(tpm.Options{
			DevicePath:   device,
			PCRSelection: pcrSelection,
		})

	case kms.ProviderMock:
		return mock.NewProvider(), nil

	default:
		return nil, fmt.Errorf("unknown provider: %s", cfg.Spec.Envelope.Provider)
	}
}

func createNewRotateProvider(ctx context.Context) (kms.Provider, kms.ProviderName, error) {
	// Default to AWS KMS if no new provider specified but key-arn is provided
	provider := rotateNewProvider
	if provider == "" && rotateNewKeyArn != "" {
		provider = "aws-kms"
	}

	switch provider {
	case "aws-kms":
		if rotateNewKeyArn == "" {
			return nil, "", fmt.Errorf("--new-key-arn is required for aws-kms provider")
		}
		p, err := awskms.NewProvider(awskms.Options{KeyArn: rotateNewKeyArn})
		return p, kms.ProviderAWSKMS, err

	case "gcp-kms":
		if rotateNewKeyName == "" {
			return nil, "", fmt.Errorf("--new-key-name is required for gcp-kms provider")
		}
		p, err := gcpkms.NewProvider(gcpkms.Options{KeyName: rotateNewKeyName})
		return p, kms.ProviderGCPKMS, err

	case "azure-keyvault":
		if rotateNewVaultURL == "" {
			return nil, "", fmt.Errorf("--new-vault-url is required for azure-keyvault provider")
		}
		p, err := azurekv.NewProvider(azurekv.Options{VaultURL: rotateNewVaultURL})
		return p, kms.ProviderAzureKeyVault, err

	case "oci-vault":
		if rotateNewKeyOCID == "" {
			return nil, "", fmt.Errorf("--new-key-ocid is required for oci-vault provider")
		}
		if rotateNewCryptoEP == "" {
			return nil, "", fmt.Errorf("--new-crypto-endpoint is required for oci-vault provider")
		}
		p, err := ocivault.NewProvider(ocivault.Options{
			KeyOCID:        rotateNewKeyOCID,
			CryptoEndpoint: rotateNewCryptoEP,
		})
		return p, kms.ProviderOCIVault, err

	case "mock":
		p := mock.NewProvider()
		return p, kms.ProviderMock, nil

	case "":
		return nil, "", fmt.Errorf("--new-provider or --new-key-arn is required")

	default:
		return nil, "", fmt.Errorf("unknown provider: %s", provider)
	}
}

func updateRotateConfigSpec(cfg *config.BootstrapConfig, providerName kms.ProviderName) {
	// Clear old provider configs
	cfg.Spec.Envelope.AWSKMS = nil
	cfg.Spec.Envelope.GCPKMS = nil
	cfg.Spec.Envelope.AzureKeyVault = nil
	cfg.Spec.Envelope.OCIVault = nil
	cfg.Spec.Envelope.YubiKey = nil
	cfg.Spec.Envelope.TPM = nil

	// Set new provider config
	switch providerName {
	case kms.ProviderAWSKMS:
		cfg.Spec.Envelope.AWSKMS = &config.AWSKMSSpec{KeyArn: rotateNewKeyArn}
	case kms.ProviderGCPKMS:
		cfg.Spec.Envelope.GCPKMS = &config.GCPKMSSpec{KeyName: rotateNewKeyName}
	case kms.ProviderAzureKeyVault:
		cfg.Spec.Envelope.AzureKeyVault = &config.AzureKVSpec{VaultURL: rotateNewVaultURL}
	case kms.ProviderOCIVault:
		cfg.Spec.Envelope.OCIVault = &config.OCIVaultSpec{
			KeyOCID:        rotateNewKeyOCID,
			CryptoEndpoint: rotateNewCryptoEP,
		}
	case kms.ProviderMock:
		// No additional config needed for mock
	}
}
