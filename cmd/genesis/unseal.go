package main

// unseal.go -- SOPS decryption command.
//
// This is the one CLI command that cannot migrate to the bridge
// (internal/bridge). SOPS requires the age private key as a plaintext
// string in the SOPS_AGE_KEY environment variable of a subprocess.
// The bridge's core invariant is "key material never leaves Rust memory",
// which fundamentally conflicts with passing the key to SOPS via env var.
//
// Until SOPS itself gains a plugin/FFI interface that can consume keys
// without exposing them in process memory, unseal must use envelope.Open()
// from internal/envelope to retrieve the plaintext private key.

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

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
	unsealConfig string
	unsealInput  string
	unsealOutput string
)

var unsealCmd = &cobra.Command{
	Use:   "unseal",
	Short: "Decrypt a SOPS-encrypted secret file",
	Long: `Decrypt a SOPS-encrypted file using the genesis age private key.

This command:
  1. Loads the genesis-bootstrap.yaml configuration
  2. Decrypts the envelope to retrieve the age private key (requires identity)
  3. Uses the private key to decrypt the SOPS-encrypted file

This command requires the 'sops' binary to be installed and in your PATH.

Example:
  genesis unseal --config ./clusters/production/genesis/ --input secret.enc.yaml`,
	RunE: runUnseal,
}

func init() {
	unsealCmd.Flags().StringVar(&unsealConfig, "config", "", "Path to genesis configuration directory")
	unsealCmd.Flags().StringVarP(&unsealInput, "input", "i", "", "Input file to decrypt")
	unsealCmd.Flags().StringVarP(&unsealOutput, "output", "o", "", "Output file for decrypted content (default: stdout)")

	_ = unsealCmd.MarkFlagRequired("config") // Error ignored as cobra panics on invalid flag name
	_ = unsealCmd.MarkFlagRequired("input")
	rootCmd.AddCommand(unsealCmd)
}

func runUnseal(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	if err := checkSOPSInstalled(); err != nil {
		printError(err)
		return err
	}

	bootstrapPath := filepath.Join(unsealConfig, "genesis-bootstrap.yaml")
	verboseLog("Loading bootstrap config from: %s", bootstrapPath)

	cfg, err := config.Load(bootstrapPath)
	if err != nil {
		printError(fmt.Errorf("failed to load bootstrap config: %w", err))
		return err
	}

	if err := cfg.Validate(); err != nil {
		printError(fmt.Errorf("invalid bootstrap config: %w", err))
		return err
	}

	verboseLog("Creating KMS provider: %s", cfg.Spec.Envelope.Provider)
	provider, err := createUnsealProvider(ctx, cfg)
	if err != nil {
		printError(err)
		return err
	}

	verboseLog("Decrypting envelope to retrieve age private key...")
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

	privateKey, err := envelope.Open(ctx, provider, env)
	if err != nil {
		printError(fmt.Errorf("failed to decrypt envelope: %w", err))
		return err
	}

	verboseLog("Running SOPS decryption...")
	sopsArgs := []string{"--decrypt"}
	if unsealOutput != "" {
		sopsArgs = append(sopsArgs, "--output", unsealOutput)
	}
	sopsArgs = append(sopsArgs, unsealInput)

	sopsCmd := exec.Command("sops", sopsArgs...) // #nosec G204 -- sops is a trusted binary, args are from validated CLI flags
	sopsCmd.Env = append(os.Environ(), fmt.Sprintf("SOPS_AGE_KEY=%s", privateKey))
	sopsCmd.Stdout = os.Stdout
	sopsCmd.Stderr = os.Stderr

	if err := sopsCmd.Run(); err != nil {
		printError(fmt.Errorf("sops decryption failed: %w", err))
		return err
	}

	return nil
}

func createUnsealProvider(ctx context.Context, cfg *config.BootstrapConfig) (kms.Provider, error) {
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
