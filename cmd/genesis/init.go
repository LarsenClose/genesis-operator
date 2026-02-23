package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/larsenclose/genesis/internal/bridge"
	"github.com/larsenclose/genesis/internal/config"
	"github.com/larsenclose/genesis/internal/kms"
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
	verboseLog("Initializing genesis with provider: %s", initProvider)

	// Validate provider flags before touching the bridge.
	if err := validateInitProviderFlags(); err != nil {
		printError(err)
		return err
	}

	genesisConfigJSON := buildGenesisConfigJSON(initProvider)
	h, err := bridge.New(genesisConfigJSON)
	if err != nil {
		printError(fmt.Errorf("failed to create genesis instance: %w", err))
		return err
	}
	defer h.Free()

	kmsConfigJSON := buildKmsConfigJSON(initProvider)
	verboseLog("Generating keypair and creating envelope via bridge...")
	artifacts, err := h.Init(kmsConfigJSON)
	if err != nil {
		printError(fmt.Errorf("failed to initialize genesis: %w", err))
		return err
	}
	verboseLog("Generated public key: %s", artifacts.PublicKey)

	if err := os.MkdirAll(initOutput, 0750); err != nil {
		printError(fmt.Errorf("failed to create output directory: %w", err))
		return err
	}

	bootstrapConfig := buildBootstrapConfigFromArtifacts(artifacts)
	bootstrapPath := filepath.Join(initOutput, "genesis-bootstrap.yaml")
	verboseLog("Writing bootstrap config to: %s", bootstrapPath)
	if err := config.Save(bootstrapPath, bootstrapConfig); err != nil {
		printError(fmt.Errorf("failed to write bootstrap config: %w", err))
		return err
	}

	sopsConfig := config.NewSOPSConfig(artifacts.PublicKey)
	sopsPath := filepath.Join(initOutput, ".sops.yaml")
	verboseLog("Writing SOPS config to: %s", sopsPath)
	if err := sopsConfig.Save(sopsPath); err != nil {
		printError(fmt.Errorf("failed to write SOPS config: %w", err))
		return err
	}

	result := InitResult{
		PublicKey:     artifacts.PublicKey,
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

// validateInitProviderFlags checks that the required CLI flags for the given
// provider are present, returning a descriptive error if not.
func validateInitProviderFlags() error {
	switch kms.ProviderName(initProvider) {
	case kms.ProviderAWSKMS:
		if initKeyArn == "" {
			return fmt.Errorf("--key-arn is required for aws-kms provider")
		}
	case kms.ProviderGCPKMS:
		if initKeyName == "" {
			return fmt.Errorf("--key-name is required for gcp-kms provider")
		}
	case kms.ProviderAzureKeyVault:
		if initVaultURL == "" {
			return fmt.Errorf("--vault-url is required for azure-keyvault provider")
		}
		if initAzKeyName == "" {
			return fmt.Errorf("--az-key-name is required for azure-keyvault provider")
		}
	case kms.ProviderOCIVault:
		if initOCIKeyOCID == "" {
			return fmt.Errorf("--key-ocid is required for oci-vault provider")
		}
		if initOCICryptoEP == "" {
			return fmt.Errorf("--crypto-endpoint is required for oci-vault provider")
		}
	case kms.ProviderTPM:
		if _, err := parsePCRs(initTPMPCRs); err != nil {
			return fmt.Errorf("invalid PCR selection: %w", err)
		}
	case kms.ProviderYubiKey, kms.ProviderMock:
		// No required flags beyond what cobra enforces.
	default:
		return fmt.Errorf("unknown provider: %s", initProvider)
	}
	return nil
}

// bridgeProviderType maps Go CLI provider names to the Rust bridge provider_type
// identifiers. Providers that the Rust bridge does not support directly
// (oci-vault, yubikey, tpm) are passed through as-is -- the bridge will
// return an error if the Rust KMS factory does not recognise them.
func bridgeProviderType(goProvider string) string {
	switch kms.ProviderName(goProvider) {
	case kms.ProviderAWSKMS:
		return "aws"
	case kms.ProviderGCPKMS:
		return "gcp"
	case kms.ProviderAzureKeyVault:
		return "azure"
	case kms.ProviderMock:
		return "mock"
	default:
		// OCI, YubiKey, TPM -- pass through the Go name; the Rust side
		// will reject unsupported providers with a clear error.
		return goProvider
	}
}

// buildKmsConfigJSON constructs the JSON string expected by the bridge's
// KMS functions:  {"provider_type":"aws","settings":{...}}
func buildKmsConfigJSON(provider string) string {
	settings := buildKmsSettings(provider)
	cfg := map[string]interface{}{
		"provider_type": bridgeProviderType(provider),
		"settings":      settings,
	}
	data, _ := json.Marshal(cfg) // settings are built from validated flags; marshal cannot fail
	return string(data)
}

// buildKmsSettings returns provider-specific settings derived from CLI flags.
func buildKmsSettings(provider string) map[string]interface{} {
	switch kms.ProviderName(provider) {
	case kms.ProviderAWSKMS:
		return map[string]interface{}{
			"key_arn": initKeyArn,
		}
	case kms.ProviderGCPKMS:
		return map[string]interface{}{
			"key_name": initKeyName,
		}
	case kms.ProviderAzureKeyVault:
		s := map[string]interface{}{
			"vault_url": initVaultURL,
			"key_name":  initAzKeyName,
		}
		if initAzKeyVer != "" {
			s["key_version"] = initAzKeyVer
		}
		return s
	case kms.ProviderOCIVault:
		return map[string]interface{}{
			"key_ocid":        initOCIKeyOCID,
			"crypto_endpoint": initOCICryptoEP,
		}
	case kms.ProviderYubiKey:
		return map[string]interface{}{
			"slot":        initYubiSlot,
			"fingerprint": initYubiFP,
		}
	case kms.ProviderTPM:
		return map[string]interface{}{
			"device_path": initTPMDevice,
			"pcrs":        initTPMPCRs,
		}
	default:
		return map[string]interface{}{}
	}
}

// buildGenesisConfigJSON builds the top-level config JSON passed to bridge.New().
func buildGenesisConfigJSON(provider string) string {
	cfg := map[string]interface{}{
		"provider_type":       bridgeProviderType(provider),
		"provider_config":     buildKmsSettings(provider),
		"public_key":          nil,
		"envelope_ciphertext": nil,
	}
	data, _ := json.Marshal(cfg)
	return string(data)
}

// buildGenesisConfigJSONFromBootstrap constructs the genesis config JSON
// from a loaded BootstrapConfig, used by verify and rotate commands to
// reconstitute a bridge handle from a persisted config file.
func buildGenesisConfigJSONFromBootstrap(cfg *config.BootstrapConfig) string {
	providerConfig := kmsSettingsFromBootstrapConfig(cfg)
	gcfg := map[string]interface{}{
		"provider_type":       bridgeProviderType(string(cfg.Spec.Envelope.Provider)),
		"provider_config":     providerConfig,
		"public_key":          nil,
		"envelope_ciphertext": nil,
	}
	data, _ := json.Marshal(gcfg)
	return string(data)
}

// buildKmsConfigJSONFromBootstrap constructs the KMS config JSON from a
// loaded BootstrapConfig.
func buildKmsConfigJSONFromBootstrap(cfg *config.BootstrapConfig) string {
	settings := kmsSettingsFromBootstrapConfig(cfg)
	kmsConfig := map[string]interface{}{
		"provider_type": bridgeProviderType(string(cfg.Spec.Envelope.Provider)),
		"settings":      settings,
	}
	data, _ := json.Marshal(kmsConfig)
	return string(data)
}

// kmsSettingsFromBootstrapConfig extracts provider-specific settings from
// a BootstrapConfig into a map suitable for bridge JSON serialization.
func kmsSettingsFromBootstrapConfig(cfg *config.BootstrapConfig) map[string]interface{} {
	switch cfg.Spec.Envelope.Provider {
	case kms.ProviderAWSKMS:
		if cfg.Spec.Envelope.AWSKMS != nil {
			s := map[string]interface{}{
				"key_arn": cfg.Spec.Envelope.AWSKMS.KeyArn,
			}
			if cfg.Spec.Envelope.AWSKMS.Region != "" {
				s["region"] = cfg.Spec.Envelope.AWSKMS.Region
			}
			return s
		}
	case kms.ProviderGCPKMS:
		if cfg.Spec.Envelope.GCPKMS != nil {
			return map[string]interface{}{
				"key_name": cfg.Spec.Envelope.GCPKMS.KeyName,
			}
		}
	case kms.ProviderAzureKeyVault:
		if cfg.Spec.Envelope.AzureKeyVault != nil {
			s := map[string]interface{}{
				"vault_url": cfg.Spec.Envelope.AzureKeyVault.VaultURL,
				"key_name":  cfg.Spec.Envelope.AzureKeyVault.KeyName,
			}
			if cfg.Spec.Envelope.AzureKeyVault.KeyVersion != "" {
				s["key_version"] = cfg.Spec.Envelope.AzureKeyVault.KeyVersion
			}
			return s
		}
	case kms.ProviderOCIVault:
		if cfg.Spec.Envelope.OCIVault != nil {
			return map[string]interface{}{
				"key_ocid":        cfg.Spec.Envelope.OCIVault.KeyOCID,
				"crypto_endpoint": cfg.Spec.Envelope.OCIVault.CryptoEndpoint,
			}
		}
	case kms.ProviderYubiKey:
		if cfg.Spec.Envelope.YubiKey != nil {
			return map[string]interface{}{
				"slot":        cfg.Spec.Envelope.YubiKey.Slot,
				"fingerprint": cfg.Spec.Envelope.YubiKey.PublicKeyFingerprint,
			}
		}
	case kms.ProviderTPM:
		if cfg.Spec.Envelope.TPM != nil {
			s := map[string]interface{}{
				"device_path": cfg.Spec.Envelope.TPM.DevicePath,
			}
			if cfg.Spec.Envelope.TPM.PCRSelection != nil {
				s["pcr_hash"] = cfg.Spec.Envelope.TPM.PCRSelection.Hash
				s["pcrs"] = cfg.Spec.Envelope.TPM.PCRSelection.PCRs
			}
			return s
		}
	}
	return map[string]interface{}{}
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

// buildBootstrapConfigFromArtifacts creates a BootstrapConfig from bridge
// PublicArtifacts. The ciphertext is base64-encoded for YAML persistence.
func buildBootstrapConfigFromArtifacts(artifacts *bridge.PublicArtifacts) *config.BootstrapConfig {
	cfg := &config.BootstrapConfig{
		APIVersion: config.APIVersion,
		Kind:       config.KindBootstrap,
		Metadata: config.Metadata{
			Name:      "genesis-bootstrap",
			Namespace: "genesis-system",
		},
		Spec: config.BootstrapSpec{
			Envelope: config.EnvelopeSpec{
				Provider:   kms.ProviderName(initProvider),
				PublicKey:  artifacts.PublicKey,
				Ciphertext: base64.StdEncoding.EncodeToString(artifacts.EnvelopeCiphertext),
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
