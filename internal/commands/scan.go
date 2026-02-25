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
	"github.com/ppiankov/gcsspectre/internal/scanner"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var scanFlags struct {
	repoPath       string
	project        string
	staleDays      int
	maxConcurrency int
	checkPublic    bool
	severityMin    string
	outputFormat   string
	outputFile     string
	includeRefs    bool
	noProgress     bool
	timeout        time.Duration
	baselinePath   string
	updateBaseline bool
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan repository and GCS for bucket drift",
	Long: `Scans your codebase for GCS bucket references, queries GCP Cloud Storage
for actual bucket state, and detects missing buckets, stale prefixes,
and lifecycle misconfigurations.`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVarP(&scanFlags.repoPath, "repo", "r", ".", "Path to repository to scan")
	scanCmd.Flags().StringVarP(&scanFlags.project, "project", "p", "", "GCP project ID (required)")
	scanCmd.Flags().IntVar(&scanFlags.staleDays, "stale-days", 90, "Days threshold for stale prefix detection")
	scanCmd.Flags().IntVar(&scanFlags.maxConcurrency, "concurrency", 10, "Max concurrent GCS API calls")
	scanCmd.Flags().BoolVar(&scanFlags.checkPublic, "check-public", true, "Check for public bucket access via IAM")
	scanCmd.Flags().StringVar(&scanFlags.severityMin, "severity", "", "Minimum severity to report: critical, high, medium, low")
	scanCmd.Flags().StringVarP(&scanFlags.outputFormat, "format", "f", "text", "Output format: text, json, sarif, or spectrehub")
	scanCmd.Flags().StringVarP(&scanFlags.outputFile, "output", "o", "", "Output file (default: stdout)")
	scanCmd.Flags().BoolVar(&scanFlags.includeRefs, "include-references", false, "Include detailed reference list in output")
	scanCmd.Flags().BoolVar(&scanFlags.noProgress, "no-progress", false, "Disable progress indicators")
	scanCmd.Flags().DurationVar(&scanFlags.timeout, "timeout", 0, "Total operation timeout (e.g. 5m, 30s). 0 means no timeout")
	scanCmd.Flags().StringVar(&scanFlags.baselinePath, "baseline", "", "Path to previous JSON report for diff comparison")
	scanCmd.Flags().BoolVar(&scanFlags.updateBaseline, "update-baseline", false, "Write current results as the new baseline")
}

func runScan(cmd *cobra.Command, _ []string) error {
	applyConfigToScanFlags(cmd)

	if scanFlags.project == "" {
		return fmt.Errorf("--project is required (or set project in .gcsspectre.yaml)")
	}

	ctx := context.Background()
	if scanFlags.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, scanFlags.timeout)
		defer cancel()
	}
	start := time.Now()

	isTTY := term.IsTerminal(int(os.Stderr.Fd()))
	showProgress := isTTY && !scanFlags.noProgress

	// 1. Scan repository for GCS references
	printStatus("Scanning repository: %s", scanFlags.repoPath)
	repoScanner := scanner.NewRepoScanner(scanFlags.repoPath)
	references, err := repoScanner.Scan(ctx)
	if err != nil {
		return enhanceError("repository scan", err, scanFlags.maxConcurrency)
	}
	printStatus("Found %d GCS references in code", len(references))

	// 2. Initialize GCS client
	printStatus("Initializing GCS client...")
	gcsClient, err := gcs.NewClient(ctx)
	if err != nil {
		return enhanceError("GCS client initialization", err, scanFlags.maxConcurrency)
	}
	defer func() { _ = gcsClient.Close() }()

	// 3. Inspect GCS buckets
	inspector := gcs.NewInspector(gcsClient, scanFlags.project, scanFlags.maxConcurrency)
	inspector.SetCheckPublic(scanFlags.checkPublic)
	if showProgress {
		inspector.SetProgressCallback(func(current, total int, message string) {
			slog.Debug("Scan progress", slog.Int("current", current), slog.Int("total", total), slog.String("message", message))
		})
	}

	printStatus("Inspecting GCS buckets...")
	bucketInfo, err := inspector.InspectBuckets(ctx, references)
	if err != nil {
		return enhanceError("GCS inspection", err, scanFlags.maxConcurrency)
	}
	printStatus("Inspected %d buckets", len(bucketInfo))

	// 4. Analyze drift
	printStatus("Analyzing drift...")
	analyzerCfg := analyzer.AnalyzerConfig{
		StaleDays:   scanFlags.staleDays,
		CheckPublic: scanFlags.checkPublic,
		SeverityMin: analyzer.Severity(scanFlags.severityMin),
	}
	result := analyzer.Analyze(references, bucketInfo, analyzerCfg)

	// 5. Generate report
	reportData := report.Data{
		Tool:      "gcsspectre",
		Version:   GetVersion(),
		Timestamp: time.Now(),
		Config: report.ScanConfig{
			RepoPath:  scanFlags.repoPath,
			Project:   scanFlags.project,
			StaleDays: scanFlags.staleDays,
		},
		Result: result,
	}
	if scanFlags.includeRefs {
		reportData.References = references
	}

	writer := os.Stdout
	if scanFlags.outputFile != "" {
		f, err := os.Create(scanFlags.outputFile)
		if err != nil {
			return enhanceError("output file creation", err, scanFlags.maxConcurrency)
		}
		defer func() { _ = f.Close() }()
		writer = f
	}

	reporter, err := selectReporter(scanFlags.outputFormat, writer)
	if err != nil {
		return err
	}

	if err := reporter.Generate(reportData); err != nil {
		return enhanceError("report generation", err, scanFlags.maxConcurrency)
	}

	// 6. Baseline comparison
	if scanFlags.baselinePath != "" {
		currentFindings := baseline.FlattenScanFindings(reportData)
		baselineFindings, err := baseline.LoadScanBaseline(scanFlags.baselinePath)
		if err != nil {
			return enhanceError("baseline load", err, scanFlags.maxConcurrency)
		}
		diff := baseline.Diff(currentFindings, baselineFindings)
		slog.Info("Baseline comparison",
			slog.Int("new", len(diff.New)),
			slog.Int("resolved", len(diff.Resolved)),
			slog.Int("unchanged", len(diff.Unchanged)),
		)
	}

	if scanFlags.updateBaseline && scanFlags.outputFile != "" {
		baselineData, err := json.MarshalIndent(reportData, "", "  ")
		if err != nil {
			return enhanceError("baseline write", err, scanFlags.maxConcurrency)
		}
		if err := os.WriteFile(scanFlags.outputFile, baselineData, 0644); err != nil {
			return enhanceError("baseline write", err, scanFlags.maxConcurrency)
		}
		slog.Info("Updated baseline", slog.String("path", scanFlags.outputFile))
	}

	slog.Info("Scan complete",
		slog.Int("bucket_count", result.Summary.TotalBuckets),
		slog.Int("finding_count", result.Summary.TotalFindings),
		slog.Duration("duration", time.Since(start)),
	)
	if result.Summary.TotalFindings == 0 {
		fmt.Fprintf(os.Stderr, "No issues detected. %d buckets scanned.\n", result.Summary.TotalBuckets)
	}

	return nil
}

func applyConfigToScanFlags(cmd *cobra.Command) {
	if !cmd.Flags().Lookup("project").Changed && cfg.Project != "" {
		scanFlags.project = cfg.Project
	}
	if !cmd.Flags().Lookup("stale-days").Changed && cfg.StaleDays > 0 {
		scanFlags.staleDays = cfg.StaleDays
	}
	if !cmd.Flags().Lookup("format").Changed && cfg.Format != "" {
		scanFlags.outputFormat = cfg.Format
	}
	if !cmd.Flags().Lookup("check-public").Changed && cfg.CheckPublic != nil {
		scanFlags.checkPublic = cfg.CheckPublicEnabled()
	}
	if !cmd.Flags().Lookup("timeout").Changed {
		if d := cfg.TimeoutDuration(); d > 0 {
			scanFlags.timeout = d
		}
	}
}
