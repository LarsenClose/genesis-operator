package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"
)

var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

// resolveVersion returns version info, falling back to runtime/debug.ReadBuildInfo
// when the binary was built without ldflags (e.g. plain `go build ./cmd/genesis`).
func resolveVersion() (version, commit, buildDate string) {
	// Release path: ldflags were injected.
	if Version != "dev" {
		return Version, Commit, BuildDate
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev", "unknown commit", "unknown"
	}

	// If the module version is set and meaningful, use it.
	if info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version, Commit, BuildDate
	}

	// Extract VCS settings embedded by `go build`.
	var revision, vcsTime string
	modified := false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.time":
			vcsTime = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}

	if revision == "" {
		return "dev", "unknown commit", "unknown"
	}

	short := revision
	if len(revision) > 7 {
		short = revision[:7]
	}

	// Normalise the timestamp: trim sub-second precision so it prints cleanly.
	if idx := strings.IndexByte(vcsTime, '.'); idx != -1 {
		vcsTime = vcsTime[:idx] + "Z"
	}

	if modified {
		version = fmt.Sprintf("dev-%s (dirty)", short)
	} else if vcsTime != "" {
		version = fmt.Sprintf("dev-%s (%s)", short, vcsTime)
	} else {
		version = fmt.Sprintf("dev-%s", short)
	}

	return version, short, vcsTime
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version information",
	Run: func(cmd *cobra.Command, args []string) {
		v, c, d := resolveVersion()
		info := VersionInfo{
			Version:   v,
			Commit:    c,
			BuildDate: d,
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
