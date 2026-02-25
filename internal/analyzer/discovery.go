package analyzer

import (
	"fmt"
	"strings"

	"github.com/ppiankov/gcsspectre/internal/gcs"
)

// DiscoveryConfig contains configuration for discover-mode analysis.
type DiscoveryConfig struct {
	StaleDays      int
	VersionDays    int
	SeverityMin    Severity
	CheckPublic    bool
	ProjectID      string
	ExcludeBuckets map[string]bool
}

// AnalyzeDiscovery performs discover-mode analysis across all project buckets.
func AnalyzeDiscovery(bucketInfo map[string]*gcs.BucketInfo, cfg DiscoveryConfig) *AnalysisResult {
	result := &AnalysisResult{}
	result.Summary.TotalBuckets = len(bucketInfo)

	for _, info := range bucketInfo {
		if cfg.ExcludeBuckets != nil && cfg.ExcludeBuckets[info.Name] {
			continue
		}

		analyzeNoLifecycle(info, result)
		analyzeStaleObjects(info, cfg, result)
		analyzeVersionBloat(info, cfg, result)
		if cfg.CheckPublic {
			analyzePublicBucket(info, result)
		}
		analyzeNoUniformAccess(info, result)
		analyzeCrossProject(info, cfg, result)
		analyzeRetentionGap(info, result)
	}

	// Filter by severity
	result.Findings = filterBySeverity(result.Findings, cfg.SeverityMin)

	// Build summary
	result.Summary = buildSummary(result.Findings, result.Summary.TotalBuckets)

	return result
}

// analyzeNoLifecycle checks for buckets without lifecycle rules.
func analyzeNoLifecycle(info *gcs.BucketInfo, result *AnalysisResult) {
	if info.LifecycleRules > 0 {
		return
	}

	result.Findings = append(result.Findings, Finding{
		ID:             FindingNoLifecycle,
		Severity:       SeverityMedium,
		ResourceType:   ResourceBucket,
		ResourceID:     info.Name,
		Message:        fmt.Sprintf("Bucket %q has no lifecycle rules", info.Name),
		Recommendation: "Add lifecycle rules to manage object retention and storage costs",
		Metadata: map[string]any{
			"location":      info.Location,
			"storage_class": info.StorageClass,
		},
	})
}

// analyzeStaleObjects checks for buckets with no recent updates in Standard class.
func analyzeStaleObjects(info *gcs.BucketInfo, cfg DiscoveryConfig, result *AnalysisResult) {
	staleThreshold := cfg.StaleDays
	if staleThreshold <= 0 {
		staleThreshold = 90
	}

	if info.IsEmpty || info.DaysSinceUpdate <= staleThreshold {
		return
	}

	// Only flag Standard class buckets — Nearline/Coldline/Archive are expected to be stale
	if info.StorageClass != "" && info.StorageClass != "STANDARD" && info.StorageClass != "MULTI_REGIONAL" && info.StorageClass != "REGIONAL" {
		return
	}

	result.Findings = append(result.Findings, Finding{
		ID:             FindingStaleObjects,
		Severity:       SeverityHigh,
		ResourceType:   ResourceBucket,
		ResourceID:     info.Name,
		Message:        fmt.Sprintf("Bucket %q has no object updates for %d days (class: %s)", info.Name, info.DaysSinceUpdate, info.StorageClass),
		Recommendation: "Archive to Nearline/Coldline or delete if not needed",
		Metadata: map[string]any{
			"days_since_update": info.DaysSinceUpdate,
			"storage_class":     info.StorageClass,
			"threshold":         staleThreshold,
		},
	})
}

// analyzeVersionBloat checks for versioned buckets without lifecycle cleanup.
func analyzeVersionBloat(info *gcs.BucketInfo, cfg DiscoveryConfig, result *AnalysisResult) {
	if !info.VersioningEnabled {
		return
	}

	versionThreshold := cfg.VersionDays
	if versionThreshold <= 0 {
		versionThreshold = 30
	}

	// Version bloat: versioning enabled, no lifecycle delete rule for noncurrent objects
	if info.LifecycleHasDelete {
		return
	}

	result.Findings = append(result.Findings, Finding{
		ID:             FindingVersionBloat,
		Severity:       SeverityMedium,
		ResourceType:   ResourceBucket,
		ResourceID:     info.Name,
		Message:        fmt.Sprintf("Bucket %q has versioning enabled but no lifecycle delete rule for old versions", info.Name),
		Recommendation: fmt.Sprintf("Add lifecycle rule to delete noncurrent versions after %d days", versionThreshold),
		Metadata: map[string]any{
			"versioning_enabled": true,
			"lifecycle_rules":    info.LifecycleRules,
		},
	})
}

// analyzePublicBucket checks for publicly accessible buckets.
func analyzePublicBucket(info *gcs.BucketInfo, result *AnalysisResult) {
	if info.PublicAccess == nil || !info.PublicAccess.IsPublic {
		return
	}

	result.Findings = append(result.Findings, Finding{
		ID:             FindingPublicBucket,
		Severity:       SeverityCritical,
		ResourceType:   ResourceBucket,
		ResourceID:     info.Name,
		Message:        fmt.Sprintf("Bucket %q is publicly accessible via allUsers/allAuthenticatedUsers", info.Name),
		Recommendation: "Remove public IAM bindings unless intentionally public-facing",
		Metadata: map[string]any{
			"public_members":           info.PublicAccess.PublicMembers,
			"public_roles":             info.PublicAccess.PublicRoles,
			"public_access_prevention": info.PublicAccessPrevention,
		},
	})
}

// analyzeNoUniformAccess checks for buckets without uniform bucket-level access.
func analyzeNoUniformAccess(info *gcs.BucketInfo, result *AnalysisResult) {
	if info.UniformAccessEnabled {
		return
	}

	result.Findings = append(result.Findings, Finding{
		ID:             FindingNoUniformAccess,
		Severity:       SeverityMedium,
		ResourceType:   ResourceBucket,
		ResourceID:     info.Name,
		Message:        fmt.Sprintf("Bucket %q uses legacy ACL mode (uniform bucket-level access disabled)", info.Name),
		Recommendation: "Enable uniform bucket-level access for consistent IAM-only permissions",
	})
}

// analyzeCrossProject checks for buckets in a different project than expected.
func analyzeCrossProject(info *gcs.BucketInfo, cfg DiscoveryConfig, result *AnalysisResult) {
	if cfg.ProjectID == "" || info.Project == "" {
		return
	}

	if info.Project == cfg.ProjectID {
		return
	}

	result.Findings = append(result.Findings, Finding{
		ID:             FindingCrossProject,
		Severity:       SeverityLow,
		ResourceType:   ResourceBucket,
		ResourceID:     info.Name,
		Message:        fmt.Sprintf("Bucket %q belongs to project %q, not the scanned project %q", info.Name, info.Project, cfg.ProjectID),
		Recommendation: "Verify cross-project bucket access is intentional",
		Metadata: map[string]any{
			"bucket_project":  info.Project,
			"scanned_project": cfg.ProjectID,
		},
	})
}

// analyzeRetentionGap checks compliance buckets missing retention policies.
func analyzeRetentionGap(info *gcs.BucketInfo, result *AnalysisResult) {
	if info.RetentionPolicySet {
		return
	}

	if !isComplianceBucket(info.Labels) {
		return
	}

	result.Findings = append(result.Findings, Finding{
		ID:             FindingRetentionGap,
		Severity:       SeverityHigh,
		ResourceType:   ResourceBucket,
		ResourceID:     info.Name,
		Message:        fmt.Sprintf("Compliance bucket %q has no retention policy", info.Name),
		Recommendation: "Set a retention policy to prevent premature deletion of regulated data",
		Metadata: map[string]any{
			"labels": info.Labels,
		},
	})
}

// isComplianceBucket detects compliance buckets via labels.
func isComplianceBucket(labels map[string]string) bool {
	if labels == nil {
		return false
	}

	complianceTerms := []string{"compliance", "audit", "regulatory", "retention"}

	for key, value := range labels {
		keyLower := strings.ToLower(key)
		valueLower := strings.ToLower(value)
		for _, term := range complianceTerms {
			if strings.Contains(keyLower, term) || strings.Contains(valueLower, term) {
				return true
			}
		}
	}

	return false
}
