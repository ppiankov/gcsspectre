package baseline

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ppiankov/gcsspectre/internal/analyzer"
	"github.com/ppiankov/gcsspectre/internal/report"
)

// Finding is a flattened, identity-comparable issue from a scan or discovery.
type Finding struct {
	Type       string `json:"type"`
	ResourceID string `json:"resource_id"`
}

func (f Finding) key() string {
	return fmt.Sprintf("%s|%s", f.Type, f.ResourceID)
}

// DiffResult holds the outcome of comparing current findings against a baseline.
type DiffResult struct {
	New       []Finding
	Resolved  []Finding
	Unchanged []Finding
}

// FlattenScanFindings converts scan report findings into a flat finding list.
func FlattenScanFindings(data report.Data) []Finding {
	if data.Result == nil {
		return nil
	}
	return flattenFindings(data.Result.Findings)
}

// FlattenDiscoveryFindings converts discovery report findings into a flat finding list.
func FlattenDiscoveryFindings(data report.DiscoveryData) []Finding {
	if data.Result == nil {
		return nil
	}
	return flattenFindings(data.Result.Findings)
}

func flattenFindings(findings []analyzer.Finding) []Finding {
	var result []Finding
	for _, f := range findings {
		result = append(result, Finding{
			Type:       string(f.ID),
			ResourceID: f.ResourceID,
		})
	}
	return result
}

// LoadScanBaseline reads a previous scan JSON report and extracts findings.
func LoadScanBaseline(path string) ([]Finding, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var data report.Data
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}
	return FlattenScanFindings(data), nil
}

// LoadDiscoveryBaseline reads a previous discovery JSON report and extracts findings.
func LoadDiscoveryBaseline(path string) ([]Finding, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var data report.DiscoveryData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("parse baseline: %w", err)
	}
	return FlattenDiscoveryFindings(data), nil
}

// Diff compares current findings against a baseline.
func Diff(current, baseline []Finding) DiffResult {
	baseMap := make(map[string]struct{}, len(baseline))
	for _, f := range baseline {
		baseMap[f.key()] = struct{}{}
	}
	curMap := make(map[string]struct{}, len(current))
	for _, f := range current {
		curMap[f.key()] = struct{}{}
	}

	var result DiffResult
	for _, f := range current {
		if _, exists := baseMap[f.key()]; exists {
			result.Unchanged = append(result.Unchanged, f)
		} else {
			result.New = append(result.New, f)
		}
	}
	for _, f := range baseline {
		if _, exists := curMap[f.key()]; !exists {
			result.Resolved = append(result.Resolved, f)
		}
	}
	return result
}
