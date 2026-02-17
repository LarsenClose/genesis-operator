package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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

var (
	initProvider    string
	initKeyArn      string
	initKeyName     string
	initVaultURL    string
	initAzKeyName   string
	initAzKeyVer    string
	initOCIKeyOCID  string
	initOCICryptoEP string
	initYubiSlot    string
	initYubiFP      string
	initTPMDevice   string
	initTPMPCRs     string
	initOutput      string
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new genesis configuration",
	Long: `Initialize a new genesis configuration by generating an age keypair
and encrypting it with the specified KMS provider.

This creates:
  - genesis-bootstrap.yaml: The encrypted master key configuration (safe for git)
  - .sops.yaml: SOPS configuration pointing to the genesis public key

Example:
  genesis init --provider aws-kms --key-arn arn:aws:kms:us-west-2:123456789012:key/...`,
	RunE: runInit,
}

func init() {
	initCmd.Flags().StringVar(&initProvider, "provider", "", "KMS provider (aws-kms, gcp-kms, azure-keyvault, oci-vault, yubikey, tpm)")
	initCmd.Flags().StringVar(&initKeyArn, "key-arn", "", "AWS KMS key ARN")
	initCmd.Flags().StringVar(&initKeyName, "key-name", "", "GCP KMS key name (projects/{project}/locations/{loc}/keyRings/{ring}/cryptoKeys/{key})")
	initCmd.Flags().StringVar(&initVaultURL, "vault-url", "", "Azure Key Vault URL (https://{vault}.vault.azure.net)")
	initCmd.Flags().StringVar(&initAzKeyName, "az-key-name", "", "Azure Key Vault key name")
	initCmd.Flags().StringVar(&initAzKeyVer, "az-key-version", "", "Azure Key Vault key version (optional)")
	initCmd.Flags().StringVar(&initOCIKeyOCID, "key-ocid", "", "OCI Vault master encryption key OCID")
	initCmd.Flags().StringVar(&initOCICryptoEP, "crypto-endpoint", "", "OCI Vault crypto endpoint (https://<vault>-crypto.kms.<region>.oraclecloud.com)")
	initCmd.Flags().StringVar(&initYubiSlot, "slot", "9a", "YubiKey PIV slot (9a, 9c, 9d, 9e)")
	initCmd.Flags().StringVar(&initYubiFP, "fingerprint", "", "YubiKey public key fingerprint (SHA256:...)")
	initCmd.Flags().StringVar(&initTPMDevice, "tpm-device", "/dev/tpmrm0", "TPM device path")
	initCmd.Flags().StringVar(&initTPMPCRs, "pcrs", "0,1,2,3,7", "TPM PCR indices (comma-separated)")
	initCmd.Flags().StringVarP(&initOutput, "output", "o", ".", "Output directory for genesis files")

	_ = initCmd.MarkFlagRequired("provider") // Error ignored as cobra panics on invalid flag name
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	verboseLog("Initializing genesis with provider: %s", initProvider)

	provider, err := createKMSProvider(ctx)
	if err != nil {
		printError(err)
		return err
	}

	verboseLog("Generating age keypair...")
	keypair, err := crypto.GenerateAgeKeypair()
	if err != nil {
		printError(fmt.Errorf("failed to generate age keypair: %w", err))
		return err
	}
	verboseLog("Generated public key: %s", keypair.PublicKey)

	verboseLog("Creating envelope encryption...")
	env, err := envelope.Create(ctx, provider, keypair.PrivateKey)
	if err != nil {
		printError(fmt.Errorf("failed to create envelope: %w", err))
		return err
	}

	if err := os.MkdirAll(initOutput, 0755); err != nil {
		printError(fmt.Errorf("failed to create output directory: %w", err))
		return err
	}

	bootstrapConfig := buildBootstrapConfig(env)
	bootstrapPath := filepath.Join(initOutput, "genesis-bootstrap.yaml")
	verboseLog("Writing bootstrap config to: %s", bootstrapPath)
	if err := config.Save(bootstrapPath, bootstrapConfig); err != nil {
		printError(fmt.Errorf("failed to write bootstrap config: %w", err))
		return err
	}

	sopsConfig := config.NewSOPSConfig(keypair.PublicKey)
	sopsPath := filepath.Join(initOutput, ".sops.yaml")
	verboseLog("Writing SOPS config to: %s", sopsPath)
	if err := sopsConfig.Save(sopsPath); err != nil {
		printError(fmt.Errorf("failed to write SOPS config: %w", err))
		return err
	}

	result := InitResult{
		PublicKey:     keypair.PublicKey,
		Provider:      initProvider,
		BootstrapFile: bootstrapPath,
		SOPSFile:      sopsPath,
	}

	if jsonOutput {
		printOutput(result)
	} else {
		fmt.Println("Genesis initialized successfully!")
		fmt.Println()
		fmt.Printf("  Public Key:     %s\n", result.PublicKey)
		fmt.Printf("  Provider:       %s\n", result.Provider)
		fmt.Printf("  Bootstrap File: %s\n", result.BootstrapFile)
		fmt.Printf("  SOPS Config:    %s\n", result.SOPSFile)
		fmt.Println()
		fmt.Println("Next steps:")
		fmt.Println("  1. Commit these files to your git repository")
		fmt.Println("  2. Deploy the genesis-operator to your cluster")
		fmt.Println("  3. Use 'genesis seal' to encrypt secrets with SOPS")
	}

	return nil
}

type InitResult struct {
	PublicKey     string `json:"publicKey"`
	Provider      string `json:"provider"`
	BootstrapFile string `json:"bootstrapFile"`
	SOPSFile      string `json:"sopsFile"`
}

func createKMSProvider(ctx context.Context) (kms.Provider, error) {
	switch kms.ProviderName(initProvider) {
	case kms.ProviderAWSKMS:
		if initKeyArn == "" {
			return nil, fmt.Errorf("--key-arn is required for aws-kms provider")
		}
		return awskms.NewProvider(awskms.Options{
			KeyArn: initKeyArn,
		})

	case kms.ProviderGCPKMS:
		if initKeyName == "" {
			return nil, fmt.Errorf("--key-name is required for gcp-kms provider")
		}
		return gcpkms.NewProvider(gcpkms.Options{
			KeyName: initKeyName,
		})

	case kms.ProviderAzureKeyVault:
		if initVaultURL == "" {
			return nil, fmt.Errorf("--vault-url is required for azure-keyvault provider")
		}
		if initAzKeyName == "" {
			return nil, fmt.Errorf("--az-key-name is required for azure-keyvault provider")
		}
		return azurekv.NewProvider(azurekv.Options{
			VaultURL:   initVaultURL,
			KeyName:    initAzKeyName,
			KeyVersion: initAzKeyVer,
		})

	case kms.ProviderOCIVault:
		if initOCIKeyOCID == "" {
			return nil, fmt.Errorf("--key-ocid is required for oci-vault provider")
		}
		if initOCICryptoEP == "" {
			return nil, fmt.Errorf("--crypto-endpoint is required for oci-vault provider")
		}
		return ocivault.NewProvider(ocivault.Options{
			KeyOCID:        initOCIKeyOCID,
			CryptoEndpoint: initOCICryptoEP,
		})

	case kms.ProviderYubiKey:
		return yubikey.NewProvider(yubikey.Options{
			Slot:                 yubikey.PIVSlot(initYubiSlot),
			PublicKeyFingerprint: initYubiFP,
		})

	case kms.ProviderTPM:
		pcrs, err := parsePCRs(initTPMPCRs)
		if err != nil {
			return nil, fmt.Errorf("invalid PCR selection: %w", err)
		}
		return tpm.NewProvider(tpm.Options{
			DevicePath: initTPMDevice,
			PCRSelection: &tpm.PCRSelection{
				Hash: tpm.HashSHA256,
				PCRs: pcrs,
			},
		})

	case kms.ProviderMock:
		return mock.NewProvider(), nil

	default:
		return nil, fmt.Errorf("unknown provider: %s", initProvider)
	}
}

func parsePCRs(s string) ([]int, error) {
	if s == "" {
		return nil, fmt.Errorf("PCR selection cannot be empty")
	}
	parts := strings.Split(s, ",")
	pcrs := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid PCR index %q: %w", p, err)
		}
		pcrs = append(pcrs, n)
	}
	return pcrs, nil
}

func buildBootstrapConfig(env *envelope.Envelope) *config.BootstrapConfig {
	cfg := &config.BootstrapConfig{
		APIVersion: config.APIVersion,
		Kind:       config.KindBootstrap,
		Metadata: config.Metadata{
			Name:      "genesis-bootstrap",
			Namespace: "genesis-system",
		},
		Spec: config.BootstrapSpec{
			Envelope: config.EnvelopeSpec{
				Provider:   env.Provider,
				PublicKey:  env.PublicKey,
				Ciphertext: env.CiphertextB64,
			},
			Output: config.OutputSpec{
				SecretName:      "sops-age",
				SecretNamespace: "flux-system",
				SecretKey:       "age.agekey",
			},
		},
	}

	switch kms.ProviderName(initProvider) {
	case kms.ProviderAWSKMS:
		cfg.Spec.Envelope.AWSKMS = &config.AWSKMSSpec{
			KeyArn: initKeyArn,
		}
	case kms.ProviderGCPKMS:
		cfg.Spec.Envelope.GCPKMS = &config.GCPKMSSpec{
			KeyName: initKeyName,
		}
	case kms.ProviderAzureKeyVault:
		cfg.Spec.Envelope.AzureKeyVault = &config.AzureKVSpec{
			VaultURL:   initVaultURL,
			KeyName:    initAzKeyName,
			KeyVersion: initAzKeyVer,
		}
	case kms.ProviderOCIVault:
		cfg.Spec.Envelope.OCIVault = &config.OCIVaultSpec{
			KeyOCID:        initOCIKeyOCID,
			CryptoEndpoint: initOCICryptoEP,
		}
	case kms.ProviderYubiKey:
		cfg.Spec.Envelope.YubiKey = &config.YubiKeySpec{
			Slot:                 initYubiSlot,
			PublicKeyFingerprint: initYubiFP,
		}
	case kms.ProviderTPM:
		pcrs, _ := parsePCRs(initTPMPCRs)
		cfg.Spec.Envelope.TPM = &config.TPMSpec{
			DevicePath: initTPMDevice,
			PCRSelection: &config.PCRSelectionSpec{
				Hash: "sha256",
				PCRs: pcrs,
			},
		}
	}

	return cfg
}
