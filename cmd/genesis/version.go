package main

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version information",
	Run: func(cmd *cobra.Command, args []string) {
		info := VersionInfo{
			Version:   Version,
			Commit:    Commit,
			BuildDate: BuildDate,
			GoVersion: runtime.Version(),
			OS:        runtime.GOOS,
			Arch:      runtime.GOARCH,
		}

		if jsonOutput {
			printOutput(info)
		} else {
			fmt.Printf("genesis %s\n", info.Version)
			fmt.Printf("  commit:     %s\n", info.Commit)
			fmt.Printf("  built:      %s\n", info.BuildDate)
			fmt.Printf("  go version: %s\n", info.GoVersion)
			fmt.Printf("  os/arch:    %s/%s\n", info.OS, info.Arch)
		}
	},
}

type VersionInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"buildDate"`
	GoVersion string `json:"goVersion"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
