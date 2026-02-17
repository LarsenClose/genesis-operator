package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/larsenclose/genesis/internal/config"
	"github.com/spf13/cobra"
)

var (
	sealConfig string
	sealInput  string
	sealOutput string
)

var sealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Encrypt a secret file using SOPS",
	Long: `Encrypt a Kubernetes secret or other YAML file using SOPS with the
genesis age public key.

This command requires the 'sops' binary to be installed and in your PATH.

The command reads the .sops.yaml configuration from the genesis config
directory to determine the encryption key.

Example:
  genesis seal --config ./clusters/production/genesis/ --input secret.yaml --output secret.enc.yaml`,
	RunE: runSeal,
}

func init() {
	sealCmd.Flags().StringVar(&sealConfig, "config", "", "Path to genesis configuration directory")
	sealCmd.Flags().StringVarP(&sealInput, "input", "i", "", "Input file to encrypt")
	sealCmd.Flags().StringVarP(&sealOutput, "output", "o", "", "Output file for encrypted content (default: stdout)")

	_ = sealCmd.MarkFlagRequired("config") // Error ignored as cobra panics on invalid flag name
	_ = sealCmd.MarkFlagRequired("input")
	rootCmd.AddCommand(sealCmd)
}

func runSeal(cmd *cobra.Command, args []string) error {
	if err := checkSOPSInstalled(); err != nil {
		printError(err)
		return err
	}

	sopsConfigPath := filepath.Join(sealConfig, ".sops.yaml")
	if _, err := os.Stat(sopsConfigPath); os.IsNotExist(err) {
		err := fmt.Errorf(".sops.yaml not found in %s", sealConfig)
		printError(err)
		return err
	}

	verboseLog("Loading SOPS config from: %s", sopsConfigPath)
	sopsConfig, err := config.LoadSOPSConfig(sopsConfigPath)
	if err != nil {
		printError(fmt.Errorf("failed to load SOPS config: %w", err))
		return err
	}

	if len(sopsConfig.CreationRules) == 0 || sopsConfig.CreationRules[0].Age == "" {
		err := fmt.Errorf("no age key found in SOPS config")
		printError(err)
		return err
	}

	agePublicKey := sopsConfig.CreationRules[0].Age
	verboseLog("Using age public key: %s", agePublicKey)

	sopsArgs := []string{
		"--encrypt",
		"--age", agePublicKey,
	}

	if sealOutput != "" {
		sopsArgs = append(sopsArgs, "--output", sealOutput)
	}

	sopsArgs = append(sopsArgs, sealInput)

	verboseLog("Running: sops %v", sopsArgs)
	sopsCmd := exec.Command("sops", sopsArgs...) // #nosec G204 -- sops is a trusted binary, args are from validated CLI flags
	sopsCmd.Stdout = os.Stdout
	sopsCmd.Stderr = os.Stderr

	if err := sopsCmd.Run(); err != nil {
		printError(fmt.Errorf("sops encryption failed: %w", err))
		return err
	}

	if !jsonOutput && sealOutput != "" {
		fmt.Printf("Encrypted %s -> %s\n", sealInput, sealOutput)
	}

	return nil
}

func checkSOPSInstalled() error {
	_, err := exec.LookPath("sops")
	if err != nil {
		return fmt.Errorf("sops binary not found in PATH. Please install sops: https://github.com/getsops/sops")
	}
	return nil
}
