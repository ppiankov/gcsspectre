package report

import (
	"time"

	"github.com/ppiankov/gcsspectre/internal/analyzer"
	"github.com/ppiankov/gcsspectre/internal/scanner"
)

// Reporter interface for different report formats.
type Reporter interface {
	Generate(data Data) error
	GenerateDiscovery(data DiscoveryData) error
}

// Data contains scan report data.
type Data struct {
	Tool       string                   `json:"tool"`
	Version    string                   `json:"version"`
	Timestamp  time.Time                `json:"timestamp"`
	Config     ScanConfig               `json:"config"`
	Result     *analyzer.AnalysisResult `json:"result"`
	References []scanner.Reference      `json:"references,omitempty"`
}

// ScanConfig contains scan configuration for reports.
type ScanConfig struct {
	RepoPath  string `json:"repo_path"`
	Project   string `json:"project,omitempty"`
	StaleDays int    `json:"stale_days"`
}

// DiscoveryData contains discovery report data.
type DiscoveryData struct {
	Tool      string                   `json:"tool"`
	Version   string                   `json:"version"`
	Timestamp time.Time                `json:"timestamp"`
	Config    DiscoveryConfig          `json:"config"`
	Result    *analyzer.AnalysisResult `json:"result"`
}

// DiscoveryConfig contains discovery configuration for reports.
type DiscoveryConfig struct {
	Project     string `json:"project"`
	StaleDays   int    `json:"stale_days,omitempty"`
	VersionDays int    `json:"version_days,omitempty"`
	CheckPublic bool   `json:"check_public"`
}
