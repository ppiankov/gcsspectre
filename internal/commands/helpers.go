package commands

import (
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/ppiankov/gcsspectre/internal/report"
)

func printStatus(format string, args ...interface{}) {
	slog.Info(fmt.Sprintf(format, args...))
}

// GetVersion returns the build version string.
func GetVersion() string {
	return version
}

// enhanceError enhances an error with additional context and helpful suggestions.
func enhanceError(operation string, err error, concurrency int) error {
	if err == nil {
		return nil
	}

	errMsg := err.Error()

	if strings.Contains(errMsg, "could not find default credentials") || strings.Contains(errMsg, "google: could not find") {
		return fmt.Errorf("%s failed: No GCP credentials found.\n"+
			"Solutions:\n"+
			"  - Run 'gcloud auth application-default login'\n"+
			"  - Set GOOGLE_APPLICATION_CREDENTIALS environment variable\n"+
			"  - Ensure you have a valid service account key\n"+
			"Original error: %w", operation, err)
	}

	if strings.Contains(errMsg, "403") || strings.Contains(errMsg, "PermissionDenied") || strings.Contains(errMsg, "forbidden") {
		return fmt.Errorf("%s failed: Permission Denied.\n"+
			"Solutions:\n"+
			"  - Check IAM permissions for Cloud Storage operations\n"+
			"  - Ensure you have storage.buckets.list, storage.buckets.get permissions\n"+
			"  - Verify the correct GCP project is being used\n"+
			"Original error: %w", operation, err)
	}

	if strings.Contains(errMsg, "rateLimitExceeded") || strings.Contains(errMsg, "429") {
		return fmt.Errorf("%s failed: GCS rate limit exceeded.\n"+
			"Solutions:\n"+
			"  - Reduce concurrency with --concurrency flag (current: %d)\n"+
			"  - Wait a few seconds and try again\n"+
			"Original error: %w", operation, concurrency, err)
	}

	if strings.Contains(errMsg, "no such file or directory") {
		return fmt.Errorf("%s failed: Repository path not found.\n"+
			"Solutions:\n"+
			"  - Check the --repo path is correct\n"+
			"  - Ensure the directory exists and is readable\n"+
			"Original error: %w", operation, err)
	}

	return fmt.Errorf("%s failed: %w", operation, err)
}

func selectReporter(format string, writer io.Writer) (report.Reporter, error) {
	switch format {
	case "json":
		return report.NewJSONReporter(writer), nil
	case "sarif":
		return report.NewSARIFReporter(writer), nil
	case "spectrehub":
		return report.NewSpectreHubReporter(writer), nil
	case "text":
		return report.NewTextReporter(writer), nil
	default:
		return nil, fmt.Errorf("unsupported output format: %s (supported: text, json, sarif, spectrehub)", format)
	}
}
