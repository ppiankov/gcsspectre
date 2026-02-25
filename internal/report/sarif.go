package report

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/ppiankov/gcsspectre/internal/analyzer"
)

const (
	sarifSchema  = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion = "2.1.0"
)

// SARIFReporter generates SARIF v2.1.0 reports.
type SARIFReporter struct {
	writer io.Writer
}

// NewSARIFReporter creates a new SARIF reporter.
func NewSARIFReporter(w io.Writer) *SARIFReporter {
	return &SARIFReporter{writer: w}
}

type sarifLog struct {
	Schema  string     `json:"$schema,omitempty"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version,omitempty"`
	Rules   []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name,omitempty"`
	ShortDescription sarifMessage `json:"shortDescription,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level,omitempty"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRuleMeta struct {
	Name        string
	Description string
	Level       string
}

var sarifRuleMap = map[analyzer.FindingID]sarifRuleMeta{
	analyzer.FindingMissingBucket:   {Name: "MissingBucket", Description: "Bucket referenced in code but does not exist in GCS", Level: "warning"},
	analyzer.FindingMissingPrefix:   {Name: "MissingPrefix", Description: "Prefix referenced in code but no objects found", Level: "warning"},
	analyzer.FindingStalePrefix:     {Name: "StalePrefix", Description: "Prefix has not been updated recently", Level: "note"},
	analyzer.FindingNoLifecycle:     {Name: "NoLifecycle", Description: "Bucket has no lifecycle rules", Level: "note"},
	analyzer.FindingStaleObjects:    {Name: "StaleObjects", Description: "Bucket has stale objects in Standard class", Level: "warning"},
	analyzer.FindingVersionBloat:    {Name: "VersionBloat", Description: "Versioning enabled without lifecycle delete rule", Level: "note"},
	analyzer.FindingPublicBucket:    {Name: "PublicBucket", Description: "Bucket is publicly accessible", Level: "error"},
	analyzer.FindingNoUniformAccess: {Name: "NoUniformAccess", Description: "Uniform bucket-level access is disabled", Level: "note"},
	analyzer.FindingCrossProject:    {Name: "CrossProject", Description: "Bucket belongs to a different project", Level: "note"},
	analyzer.FindingRetentionGap:    {Name: "RetentionGap", Description: "Compliance bucket missing retention policy", Level: "warning"},
}

// Generate generates a SARIF scan report.
func (r *SARIFReporter) Generate(data Data) error {
	return r.writeSARIF(data.Tool, data.Version, data.Result.Findings)
}

// GenerateDiscovery generates a SARIF discovery report.
func (r *SARIFReporter) GenerateDiscovery(data DiscoveryData) error {
	return r.writeSARIF(data.Tool, data.Version, data.Result.Findings)
}

func (r *SARIFReporter) writeSARIF(toolName, toolVersion string, findings []analyzer.Finding) error {
	usedRules := make(map[analyzer.FindingID]sarifRule)
	var results []sarifResult

	// Sort findings for deterministic output
	sorted := make([]analyzer.Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].ID != sorted[j].ID {
			return sorted[i].ID < sorted[j].ID
		}
		return sorted[i].ResourceID < sorted[j].ResourceID
	})

	for _, f := range sorted {
		ruleID := "gcsspectre/" + string(f.ID)
		level := "warning"
		if meta, ok := sarifRuleMap[f.ID]; ok {
			level = meta.Level
			if _, exists := usedRules[f.ID]; !exists {
				usedRules[f.ID] = sarifRule{
					ID:               ruleID,
					Name:             meta.Name,
					ShortDescription: sarifMessage{Text: meta.Description},
				}
			}
		}

		message := f.Message
		if message == "" {
			if meta, ok := sarifRuleMap[f.ID]; ok {
				message = meta.Description
			}
		}

		result := sarifResult{
			RuleID:  ruleID,
			Level:   level,
			Message: sarifMessage{Text: message},
			Locations: []sarifLocation{{
				PhysicalLocation: &sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: "gs://" + f.ResourceID},
				},
			}},
		}
		results = append(results, result)
	}

	// Build rules list sorted by ID
	ruleIDs := make([]analyzer.FindingID, 0, len(usedRules))
	for id := range usedRules {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Slice(ruleIDs, func(i, j int) bool { return ruleIDs[i] < ruleIDs[j] })

	rules := make([]sarifRule, 0, len(ruleIDs))
	for _, id := range ruleIDs {
		rules = append(rules, usedRules[id])
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:    toolName,
					Version: toolVersion,
					Rules:   rules,
				},
			},
			Results: results,
		}},
	}

	encoder := json.NewEncoder(r.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(log)
}
