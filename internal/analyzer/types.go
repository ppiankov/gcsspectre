package analyzer

// Severity levels for findings.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// SeverityRank returns the numeric rank of a severity (higher = more severe).
func SeverityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// ResourceType identifies the cloud resource being audited.
type ResourceType string

const (
	ResourceBucket ResourceType = "gcs_bucket"
	ResourcePrefix ResourceType = "gcs_prefix"
)

// FindingID identifies the type of issue detected.
type FindingID string

// Scan mode findings.
const (
	FindingMissingBucket FindingID = "MISSING_BUCKET"
	FindingMissingPrefix FindingID = "MISSING_PREFIX"
	FindingStalePrefix   FindingID = "STALE_PREFIX"
)

// Discover mode findings.
const (
	FindingNoLifecycle     FindingID = "NO_LIFECYCLE"
	FindingStaleObjects    FindingID = "STALE_OBJECTS"
	FindingVersionBloat    FindingID = "VERSION_BLOAT"
	FindingPublicBucket    FindingID = "PUBLIC_BUCKET"
	FindingNoUniformAccess FindingID = "NO_UNIFORM_ACCESS"
	FindingCrossProject    FindingID = "CROSS_PROJECT"
	FindingRetentionGap    FindingID = "RETENTION_GAP"
)

// Finding represents a single GCS audit finding.
type Finding struct {
	ID             FindingID      `json:"id"`
	Severity       Severity       `json:"severity"`
	ResourceType   ResourceType   `json:"resource_type"`
	ResourceID     string         `json:"resource_id"`
	Message        string         `json:"message"`
	Recommendation string         `json:"recommendation"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

// AnalysisResult holds all findings from analysis.
type AnalysisResult struct {
	Findings []Finding `json:"findings"`
	Errors   []string  `json:"errors,omitempty"`
	Summary  Summary   `json:"summary"`
}

// Summary contains aggregate counts.
type Summary struct {
	TotalBuckets   int            `json:"total_buckets"`
	TotalFindings  int            `json:"total_findings"`
	BySeverity     map[string]int `json:"by_severity"`
	ByFindingID    map[string]int `json:"by_finding_id"`
	ByResourceType map[string]int `json:"by_resource_type"`
}

// AnalyzerConfig holds parameters for analysis.
type AnalyzerConfig struct {
	StaleDays   int
	VersionDays int
	SeverityMin Severity
	CheckPublic bool
}
