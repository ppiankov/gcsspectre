package report

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
)

type spectreEnvelope struct {
	Schema    string           `json:"schema"`
	Tool      string           `json:"tool"`
	Version   string           `json:"version"`
	Timestamp string           `json:"timestamp"`
	Target    spectreTarget    `json:"target"`
	Findings  []spectreFinding `json:"findings"`
	Summary   spectreSummary   `json:"summary"`
}

type spectreTarget struct {
	Type    string `json:"type"`
	URIHash string `json:"uri_hash"`
}

type spectreFinding struct {
	ID       string         `json:"id"`
	Severity string         `json:"severity"`
	Location string         `json:"location"`
	Message  string         `json:"message"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type spectreSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// HashProject produces a sha256 hash of a project ID for target identification.
func HashProject(projectID string) string {
	h := sha256.Sum256([]byte(projectID))
	return fmt.Sprintf("sha256:%x", h)
}

// SpectreHubReporter generates spectre/v1 JSON envelope output.
type SpectreHubReporter struct {
	writer io.Writer
}

// NewSpectreHubReporter creates a new SpectreHub reporter.
func NewSpectreHubReporter(w io.Writer) *SpectreHubReporter {
	return &SpectreHubReporter{writer: w}
}

// Generate writes scan results as a spectre/v1 envelope.
func (r *SpectreHubReporter) Generate(data Data) error {
	envelope := spectreEnvelope{
		Schema:    "spectre/v1",
		Tool:      "gcsspectre",
		Version:   data.Version,
		Timestamp: data.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
		Target: spectreTarget{
			Type:    "gcs",
			URIHash: HashProject(data.Config.Project),
		},
	}

	for _, f := range data.Result.Findings {
		severity := string(f.Severity)
		envelope.Findings = append(envelope.Findings, spectreFinding{
			ID:       string(f.ID),
			Severity: severity,
			Location: f.ResourceID,
			Message:  f.Message,
			Metadata: f.Metadata,
		})
		countSeverity(&envelope.Summary, severity)
	}

	envelope.Summary.Total = len(envelope.Findings)
	if envelope.Findings == nil {
		envelope.Findings = []spectreFinding{}
	}

	enc := json.NewEncoder(r.writer)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope)
}

// GenerateDiscovery writes discovery results as a spectre/v1 envelope.
func (r *SpectreHubReporter) GenerateDiscovery(data DiscoveryData) error {
	envelope := spectreEnvelope{
		Schema:    "spectre/v1",
		Tool:      "gcsspectre",
		Version:   data.Version,
		Timestamp: data.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
		Target: spectreTarget{
			Type:    "gcs",
			URIHash: HashProject(data.Config.Project),
		},
	}

	for _, f := range data.Result.Findings {
		severity := string(f.Severity)
		envelope.Findings = append(envelope.Findings, spectreFinding{
			ID:       string(f.ID),
			Severity: severity,
			Location: f.ResourceID,
			Message:  f.Message,
			Metadata: f.Metadata,
		})
		countSeverity(&envelope.Summary, severity)
	}

	envelope.Summary.Total = len(envelope.Findings)
	if envelope.Findings == nil {
		envelope.Findings = []spectreFinding{}
	}

	enc := json.NewEncoder(r.writer)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope)
}

func countSeverity(s *spectreSummary, severity string) {
	switch severity {
	case "critical":
		s.Critical++
	case "high":
		s.High++
	case "medium":
		s.Medium++
	case "low":
		s.Low++
	}
}
