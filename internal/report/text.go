package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ppiankov/gcsspectre/internal/analyzer"
)

// TextReporter generates human-readable text reports.
type TextReporter struct {
	writer io.Writer
}

// NewTextReporter creates a new text reporter.
func NewTextReporter(w io.Writer) *TextReporter {
	return &TextReporter{writer: w}
}

// Generate generates a text scan report.
func (r *TextReporter) Generate(data Data) error {
	r.printHeader("GCSSpectre", data.Version, data.Timestamp.Format("2006-01-02 15:04:05"))
	_, _ = fmt.Fprintf(r.writer, "Repository: %s\n", data.Config.RepoPath)
	if data.Config.Project != "" {
		_, _ = fmt.Fprintf(r.writer, "Project: %s\n", data.Config.Project)
	}
	_, _ = fmt.Fprintf(r.writer, "\n")

	r.printSummary(data.Result)
	r.printFindings(data.Result.Findings)

	return nil
}

// GenerateDiscovery generates a text discovery report.
func (r *TextReporter) GenerateDiscovery(data DiscoveryData) error {
	r.printHeader("GCSSpectre Discovery", data.Version, data.Timestamp.Format("2006-01-02 15:04:05"))
	_, _ = fmt.Fprintf(r.writer, "Project: %s\n", data.Config.Project)
	_, _ = fmt.Fprintf(r.writer, "\n")

	r.printSummary(data.Result)
	r.printFindings(data.Result.Findings)

	return nil
}

func (r *TextReporter) printHeader(title, version, timestamp string) {
	if version != "" {
		_, _ = fmt.Fprintf(r.writer, "%s %s\n", title, version)
	} else {
		_, _ = fmt.Fprintf(r.writer, "%s Report\n", title)
	}
	_, _ = fmt.Fprintf(r.writer, "%s\n\n", strings.Repeat("=", 40))
	_, _ = fmt.Fprintf(r.writer, "Scan Time: %s\n", timestamp)
}

func (r *TextReporter) printSummary(result *analyzer.AnalysisResult) {
	_, _ = fmt.Fprintf(r.writer, "Summary\n")
	_, _ = fmt.Fprintf(r.writer, "-------\n")
	_, _ = fmt.Fprintf(r.writer, "Total Buckets: %d\n", result.Summary.TotalBuckets)
	_, _ = fmt.Fprintf(r.writer, "Total Findings: %d\n", result.Summary.TotalFindings)

	if len(result.Summary.BySeverity) > 0 {
		severities := []string{"critical", "high", "medium", "low"}
		for _, sev := range severities {
			if count, ok := result.Summary.BySeverity[sev]; ok && count > 0 {
				_, _ = fmt.Fprintf(r.writer, "  %s: %d\n", strings.ToUpper(sev), count)
			}
		}
	}

	if len(result.Errors) > 0 {
		_, _ = fmt.Fprintf(r.writer, "Errors: %d\n", len(result.Errors))
	}

	_, _ = fmt.Fprintf(r.writer, "\n")
}

func (r *TextReporter) printFindings(findings []analyzer.Finding) {
	if len(findings) == 0 {
		_, _ = fmt.Fprintf(r.writer, "No issues found.\n\n")
		return
	}

	// Group by severity
	bySeverity := map[string][]analyzer.Finding{}
	for _, f := range findings {
		bySeverity[string(f.Severity)] = append(bySeverity[string(f.Severity)], f)
	}

	severityOrder := []string{"critical", "high", "medium", "low"}
	for _, sev := range severityOrder {
		group, ok := bySeverity[sev]
		if !ok || len(group) == 0 {
			continue
		}

		// Sort by finding ID then resource ID for deterministic output
		sort.Slice(group, func(i, j int) bool {
			if group[i].ID != group[j].ID {
				return group[i].ID < group[j].ID
			}
			return group[i].ResourceID < group[j].ResourceID
		})

		_, _ = fmt.Fprintf(r.writer, "%s (%d)\n", strings.ToUpper(sev), len(group))
		_, _ = fmt.Fprintf(r.writer, "%s\n", strings.Repeat("-", 50))

		for _, f := range group {
			_, _ = fmt.Fprintf(r.writer, "  [%s] %s\n", f.ID, f.ResourceID)
			_, _ = fmt.Fprintf(r.writer, "    %s\n", f.Message)
			_, _ = fmt.Fprintf(r.writer, "    Recommendation: %s\n", f.Recommendation)
		}
		_, _ = fmt.Fprintf(r.writer, "\n")
	}
}
