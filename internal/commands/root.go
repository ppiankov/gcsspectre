package commands

import (
	"log/slog"

	"github.com/ppiankov/gcsspectre/internal/config"
	"github.com/ppiankov/gcsspectre/internal/logging"
	"github.com/spf13/cobra"
)

var (
	verbose bool
	version string
	commit  string
	date    string
	cfg     config.Config
)

var rootCmd = &cobra.Command{
	Use:   "gcsspectre",
	Short: "GCSSpectre - GCP Cloud Storage bucket auditor",
	Long: `GCSSpectre scans code repositories for GCS bucket and prefix references,
validates them against your GCP Cloud Storage infrastructure, and identifies
missing buckets, unused buckets, stale prefixes, and lifecycle misconfigurations.

Part of the Spectre family of infrastructure cleanup tools.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logging.Init(verbose)
		loaded, err := config.Load(".")
		if err != nil {
			slog.Warn("Failed to load config file", "error", err)
		} else {
			cfg = loaded
		}
	},
}

// Execute runs the root command with injected build info.
func Execute(v, c, d string) error {
	version = v
	commit = c
	date = d
	return rootCmd.Execute()
}

// GetConfig returns the loaded config.
func GetConfig() config.Config {
	return cfg
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(discoverCmd)
	rootCmd.AddCommand(initCmd)
}
