package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/ppiankov/gcsspectre/internal/analyzer"
	"github.com/ppiankov/gcsspectre/internal/baseline"
	"github.com/ppiankov/gcsspectre/internal/gcs"
	"github.com/ppiankov/gcsspectre/internal/report"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var discoverFlags struct {
	project        string
	staleDays      int
	versionDays    int
	checkPublic    bool
	severityMin    string
	maxConcurrency int
	outputFormat   string
	outputFile     string
	noProgress     bool
	timeout        time.Duration
	baselinePath   string
	updateBaseline bool
	excludeBuckets []string
}

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover and analyze all GCS buckets in a project",
	Long: `Discovers all GCS buckets in your GCP project without requiring code references.
Analyzes buckets for lifecycle misconfigurations, public access, version bloat,
stale objects, and compliance gaps.`,
	RunE: runDiscover,
}

func init() {
	discoverCmd.Flags().StringVarP(&discoverFlags.project, "project", "p", "", "GCP project ID (required)")
	discoverCmd.Flags().IntVar(&discoverFlags.staleDays, "stale-days", 90, "Days threshold for stale object detection")
	discoverCmd.Flags().IntVar(&discoverFlags.versionDays, "version-days", 30, "Days threshold for noncurrent version cleanup")
	discoverCmd.Flags().BoolVar(&discoverFlags.checkPublic, "check-public", true, "Check for public bucket access via IAM")
	discoverCmd.Flags().StringVar(&discoverFlags.severityMin, "severity", "", "Minimum severity to report: critical, high, medium, low")
	discoverCmd.Flags().IntVar(&discoverFlags.maxConcurrency, "concurrency", 10, "Max concurrent GCS API calls")
	discoverCmd.Flags().StringVarP(&discoverFlags.outputFormat, "format", "f", "text", "Output format: text, json, sarif, or spectrehub")
	discoverCmd.Flags().StringVarP(&discoverFlags.outputFile, "output", "o", "", "Output file (default: stdout)")
	discoverCmd.Flags().BoolVar(&discoverFlags.noProgress, "no-progress", false, "Disable progress indicators")
	discoverCmd.Flags().DurationVar(&discoverFlags.timeout, "timeout", 0, "Total operation timeout (e.g. 5m, 30s). 0 means no timeout")
	discoverCmd.Flags().StringVar(&discoverFlags.baselinePath, "baseline", "", "Path to previous JSON report for diff comparison")
	discoverCmd.Flags().BoolVar(&discoverFlags.updateBaseline, "update-baseline", false, "Write current results as the new baseline")
	discoverCmd.Flags().StringSliceVar(&discoverFlags.excludeBuckets, "exclude", nil, "Buckets to exclude from analysis (comma-separated)")
}

func runDiscover(cmd *cobra.Command, _ []string) error {
	applyConfigToDiscoverFlags(cmd)

	if discoverFlags.project == "" {
		return fmt.Errorf("--project is required (or set project in .gcsspectre.yaml)")
	}

	ctx := context.Background()
	if discoverFlags.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, discoverFlags.timeout)
		defer cancel()
	}
	start := time.Now()

	isTTY := term.IsTerminal(int(os.Stderr.Fd()))
	showProgress := isTTY && !discoverFlags.noProgress

	// 1. Initialize GCS client
	printStatus("Initializing GCS client...")
	gcsClient, err := gcs.NewClient(ctx)
	if err != nil {
		return enhanceError("GCS client initialization", err, discoverFlags.maxConcurrency)
	}
	defer func() { _ = gcsClient.Close() }()

	// 2. Discover all buckets
	inspector := gcs.NewInspector(gcsClient, discoverFlags.project, discoverFlags.maxConcurrency)
	inspector.SetCheckPublic(discoverFlags.checkPublic)
	if showProgress {
		inspector.SetProgressCallback(func(current, total int, message string) {
			slog.Debug("Discovery progress", slog.Int("current", current), slog.Int("total", total), slog.String("message", message))
		})
	}

	printStatus("Discovering GCS buckets in project %s...", discoverFlags.project)
	bucketInfo, err := inspector.DiscoverAllBuckets(ctx)
	if err != nil {
		return enhanceError("bucket discovery", err, discoverFlags.maxConcurrency)
	}
	printStatus("Discovered %d buckets", len(bucketInfo))

	// 3. Build exclude map
	excludeMap := make(map[string]bool)
	for _, b := range discoverFlags.excludeBuckets {
		excludeMap[b] = true
	}
	for _, b := range cfg.ExcludeBuckets {
		excludeMap[b] = true
	}

	// 4. Analyze
	printStatus("Analyzing buckets...")
	discoveryCfg := analyzer.DiscoveryConfig{
		StaleDays:      discoverFlags.staleDays,
		VersionDays:    discoverFlags.versionDays,
		SeverityMin:    analyzer.Severity(discoverFlags.severityMin),
		CheckPublic:    discoverFlags.checkPublic,
		ProjectID:      discoverFlags.project,
		ExcludeBuckets: excludeMap,
	}
	result := analyzer.AnalyzeDiscovery(bucketInfo, discoveryCfg)

	// 5. Generate report
	reportData := report.DiscoveryData{
		Tool:      "gcsspectre",
		Version:   GetVersion(),
		Timestamp: time.Now(),
		Config: report.DiscoveryConfig{
			Project:     discoverFlags.project,
			StaleDays:   discoverFlags.staleDays,
			VersionDays: discoverFlags.versionDays,
			CheckPublic: discoverFlags.checkPublic,
		},
		Result: result,
	}

	writer := os.Stdout
	if discoverFlags.outputFile != "" {
		f, err := os.Create(discoverFlags.outputFile)
		if err != nil {
			return enhanceError("output file creation", err, discoverFlags.maxConcurrency)
		}
		defer func() { _ = f.Close() }()
		writer = f
	}

	reporter, err := selectReporter(discoverFlags.outputFormat, writer)
	if err != nil {
		return err
	}

	if err := reporter.GenerateDiscovery(reportData); err != nil {
		return enhanceError("report generation", err, discoverFlags.maxConcurrency)
	}

	// 6. Baseline comparison
	if discoverFlags.baselinePath != "" {
		currentFindings := baseline.FlattenDiscoveryFindings(reportData)
		baselineFindings, err := baseline.LoadDiscoveryBaseline(discoverFlags.baselinePath)
		if err != nil {
			return enhanceError("baseline load", err, discoverFlags.maxConcurrency)
		}
		diff := baseline.Diff(currentFindings, baselineFindings)
		slog.Info("Baseline comparison",
			slog.Int("new", len(diff.New)),
			slog.Int("resolved", len(diff.Resolved)),
			slog.Int("unchanged", len(diff.Unchanged)),
		)
	}

	if discoverFlags.updateBaseline && discoverFlags.outputFile != "" {
		baselineData, err := json.MarshalIndent(reportData, "", "  ")
		if err != nil {
			return enhanceError("baseline write", err, discoverFlags.maxConcurrency)
		}
		if err := os.WriteFile(discoverFlags.outputFile, baselineData, 0644); err != nil {
			return enhanceError("baseline write", err, discoverFlags.maxConcurrency)
		}
		slog.Info("Updated baseline", slog.String("path", discoverFlags.outputFile))
	}

	slog.Info("Discovery complete",
		slog.Int("bucket_count", result.Summary.TotalBuckets),
		slog.Int("finding_count", result.Summary.TotalFindings),
		slog.Duration("duration", time.Since(start)),
	)
	if result.Summary.TotalFindings == 0 {
		fmt.Fprintf(os.Stderr, "No issues detected. %d buckets discovered.\n", result.Summary.TotalBuckets)
	}

	return nil
}

func applyConfigToDiscoverFlags(cmd *cobra.Command) {
	if !cmd.Flags().Lookup("project").Changed && cfg.Project != "" {
		discoverFlags.project = cfg.Project
	}
	if !cmd.Flags().Lookup("stale-days").Changed && cfg.StaleDays > 0 {
		discoverFlags.staleDays = cfg.StaleDays
	}
	if !cmd.Flags().Lookup("version-days").Changed && cfg.VersionDays > 0 {
		discoverFlags.versionDays = cfg.VersionDays
	}
	if !cmd.Flags().Lookup("format").Changed && cfg.Format != "" {
		discoverFlags.outputFormat = cfg.Format
	}
	if !cmd.Flags().Lookup("check-public").Changed && cfg.CheckPublic != nil {
		discoverFlags.checkPublic = cfg.CheckPublicEnabled()
	}
	if !cmd.Flags().Lookup("timeout").Changed {
		if d := cfg.TimeoutDuration(); d > 0 {
			discoverFlags.timeout = d
		}
	}
}
