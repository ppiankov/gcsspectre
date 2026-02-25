package report

import (
	"encoding/json"
	"io"
)

// JSONReporter generates JSON reports (spectre/v1 envelope).
type JSONReporter struct {
	writer io.Writer
}

// NewJSONReporter creates a new JSON reporter.
func NewJSONReporter(w io.Writer) *JSONReporter {
	return &JSONReporter{writer: w}
}

// Generate generates a JSON scan report.
func (r *JSONReporter) Generate(data Data) error {
	data.Timestamp = data.Timestamp.UTC()
	encoder := json.NewEncoder(r.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

// GenerateDiscovery generates a JSON discovery report.
func (r *JSONReporter) GenerateDiscovery(data DiscoveryData) error {
	data.Timestamp = data.Timestamp.UTC()
	encoder := json.NewEncoder(r.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}
