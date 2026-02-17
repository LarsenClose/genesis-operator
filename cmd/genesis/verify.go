package main

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/larsenclose/genesis/internal/config"
	"github.com/larsenclose/genesis/internal/crypto"
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

var verifyCmd = &cobra.Command{
	Use:   "verify [config-file]",
	Short: "Verify a genesis configuration can be decrypted",
	Long: `Verify that the genesis bootstrap configuration can be decrypted
using the current identity credentials.

This command will:
  1. Load the genesis-bootstrap.yaml file
  2. Authenticate to the KMS provider using current credentials
  3. Decrypt the envelope to retrieve the age private key
  4. Verify the private key matches the stored public key

Example:
  genesis verify ./clusters/production/genesis/genesis-bootstrap.yaml`,
	Args: cobra.ExactArgs(1),
	RunE: runVerify,
}

func init() {
	rootCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	configPath := args[0]

	verboseLog("Loading config from: %s", configPath)
	cfg, err := config.Load(configPath)
	if err != nil {
		printError(fmt.Errorf("failed to load config: %w", err))
		return err
	}

	if err := cfg.Validate(); err != nil {
		printError(fmt.Errorf("invalid config: %w", err))
		return err
	}

	verboseLog("Creating KMS provider: %s", cfg.Spec.Envelope.Provider)
	provider, err := createVerifyProvider(ctx, cfg)
	if err != nil {
		printError(err)
		return err
	}

	verboseLog("Decoding ciphertext...")
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

	verboseLog("Decrypting envelope...")
	privateKey, err := envelope.Open(ctx, provider, env)
	if err != nil {
		printError(fmt.Errorf("failed to decrypt envelope: %w", err))
		return err
	}

	keypair, err := crypto.ParseAgeKeypair(privateKey)
	if err != nil {
		printError(fmt.Errorf("decrypted key is invalid: %w", err))
		return err
	}

	if cfg.Spec.Envelope.PublicKey != "" && keypair.PublicKey != cfg.Spec.Envelope.PublicKey {
		err := fmt.Errorf("public key mismatch: config has %s but decrypted key has %s",
			cfg.Spec.Envelope.PublicKey, keypair.PublicKey)
		printError(err)
		return err
	}

	result := VerifyResult{
		Valid:     true,
		PublicKey: keypair.PublicKey,
		Provider:  string(cfg.Spec.Envelope.Provider),
	}

	if jsonOutput {
		printOutput(result)
	} else {
		fmt.Println("Verification successful!")
		fmt.Println()
		fmt.Printf("  Provider:   %s\n", result.Provider)
		fmt.Printf("  Public Key: %s\n", result.PublicKey)
		fmt.Println()
		fmt.Println("The genesis configuration can be decrypted with current credentials.")
	}

	return nil
}

type VerifyResult struct {
	Valid     bool   `json:"valid"`
	PublicKey string `json:"publicKey"`
	Provider  string `json:"provider"`
}

func createVerifyProvider(ctx context.Context, cfg *config.BootstrapConfig) (kms.Provider, error) {
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
