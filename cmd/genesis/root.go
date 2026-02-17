package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	verbose    bool
	jsonOutput bool
)

var rootCmd = &cobra.Command{
	Use:   "genesis",
	Short: "Universal GitOps Secrets Bootstrap",
	Long: `Genesis solves the chicken-and-egg problem in GitOps secrets management.

It provides a single, identity-based bootstrap mechanism that works across
cloud providers and bare-metal environments, requiring only one manual step
(key generation) and then enabling fully automated, declarative secrets
lifecycle management.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
}

func printOutput(data interface{}) {
	if jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(data) // Error ignored as this is terminal output
	} else {
		fmt.Println(data)
	}
}

func printError(err error) {
	if jsonOutput {
		output := map[string]interface{}{
			"error": err.Error(),
		}
		enc := json.NewEncoder(os.Stderr)
		enc.SetIndent("", "  ")
		_ = enc.Encode(output) // Error ignored as this is terminal output
	} else {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
}

func verboseLog(format string, args ...interface{}) {
	if verbose {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}
