package main

import (
	"encoding/base64"
	"fmt"

	"github.com/larsenclose/genesis/internal/bridge"
	"github.com/larsenclose/genesis/internal/config"
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

	verboseLog("Creating bridge handle for provider: %s", cfg.Spec.Envelope.Provider)
	genesisConfigJSON := buildGenesisConfigJSONFromBootstrap(cfg)
	h, err := bridge.New(genesisConfigJSON)
	if err != nil {
		printError(fmt.Errorf("failed to create genesis instance: %w", err))
		return err
	}
	defer h.Free()

	verboseLog("Decoding ciphertext...")
	ciphertext, err := base64.StdEncoding.DecodeString(cfg.Spec.Envelope.Ciphertext)
	if err != nil {
		printError(fmt.Errorf("failed to decode ciphertext: %w", err))
		return err
	}

	verboseLog("Loading keypair into bridge...")
	if err := h.Load(cfg.Spec.Envelope.PublicKey, ciphertext); err != nil {
		printError(fmt.Errorf("failed to load keypair: %w", err))
		return err
	}

	verboseLog("Verifying envelope via bridge...")
	kmsConfigJSON := buildKmsConfigJSONFromBootstrap(cfg)
	vr, err := h.Verify(kmsConfigJSON)
	if err != nil {
		printError(fmt.Errorf("failed to verify envelope: %w", err))
		return err
	}

	if !vr.PublicKeyMatches {
		err := fmt.Errorf("public key mismatch: config has %s but decrypted key has %s",
			cfg.Spec.Envelope.PublicKey, vr.PublicKey)
		printError(err)
		return err
	}

	result := VerifyResult{
		Valid:     true,
		PublicKey: vr.PublicKey,
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
