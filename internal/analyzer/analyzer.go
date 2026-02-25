package analyzer

import (
	"fmt"

	"github.com/ppiankov/gcsspectre/internal/gcs"
	"github.com/ppiankov/gcsspectre/internal/scanner"
)

// Analyze performs scan-mode analysis: compares code references against GCS state.
func Analyze(refs []scanner.Reference, bucketInfo map[string]*gcs.BucketInfo, cfg AnalyzerConfig) *AnalysisResult {
	result := &AnalysisResult{}

	// Group references by bucket
	bucketRefs := make(map[string][]scanner.Reference)
	for _, ref := range refs {
		bucketRefs[ref.Bucket] = append(bucketRefs[ref.Bucket], ref)
	}

	result.Summary.TotalBuckets = len(bucketRefs)

	for bucket, brefs := range bucketRefs {
		info, ok := bucketInfo[bucket]
		if !ok || !info.Exists {
			result.Findings = append(result.Findings, Finding{
				ID:             FindingMissingBucket,
				Severity:       SeverityHigh,
				ResourceType:   ResourceBucket,
				ResourceID:     bucket,
				Message:        fmt.Sprintf("Bucket %q referenced in code but does not exist in GCS", bucket),
				Recommendation: "Create the bucket or remove stale code references",
				Metadata: map[string]any{
					"files": referencedFiles(brefs),
				},
			})
			continue
		}

		// Check prefixes
		for _, prefix := range info.Prefixes {
			if !prefix.Exists {
				result.Findings = append(result.Findings, Finding{
					ID:             FindingMissingPrefix,
					Severity:       SeverityMedium,
					ResourceType:   ResourcePrefix,
					ResourceID:     fmt.Sprintf("%s/%s", bucket, prefix.Prefix),
					Message:        fmt.Sprintf("Prefix %q in bucket %q referenced in code but no objects found", prefix.Prefix, bucket),
					Recommendation: "Verify code references or upload expected objects",
				})
				continue
			}

			staleThreshold := cfg.StaleDays
			if staleThreshold <= 0 {
				staleThreshold = 90
			}
			if prefix.DaysSinceUpdated > staleThreshold {
				result.Findings = append(result.Findings, Finding{
					ID:             FindingStalePrefix,
					Severity:       SeverityLow,
					ResourceType:   ResourcePrefix,
					ResourceID:     fmt.Sprintf("%s/%s", bucket, prefix.Prefix),
					Message:        fmt.Sprintf("Prefix %q in bucket %q not updated for %d days (threshold: %d)", prefix.Prefix, bucket, prefix.DaysSinceUpdated, staleThreshold),
					Recommendation: "Verify if prefix data is still needed",
					Metadata: map[string]any{
						"days_since_updated": prefix.DaysSinceUpdated,
						"threshold":          staleThreshold,
					},
				})
			}
		}

		// Check lifecycle on buckets with many objects
		if info.LifecycleRules == 0 && info.ObjectCount > 100 {
			result.Findings = append(result.Findings, Finding{
				ID:             FindingNoLifecycle,
				Severity:       SeverityMedium,
				ResourceType:   ResourceBucket,
				ResourceID:     bucket,
				Message:        fmt.Sprintf("Bucket %q has %d objects but no lifecycle rules", bucket, info.ObjectCount),
				Recommendation: "Add lifecycle rules to manage object retention",
			})
		}

		// Check public access on scan-mode buckets
		if cfg.CheckPublic && info.PublicAccess != nil && info.PublicAccess.IsPublic {
			result.Findings = append(result.Findings, Finding{
				ID:             FindingPublicBucket,
				Severity:       SeverityCritical,
				ResourceType:   ResourceBucket,
				ResourceID:     bucket,
				Message:        fmt.Sprintf("Bucket %q is publicly accessible", bucket),
				Recommendation: "Remove allUsers/allAuthenticatedUsers IAM bindings unless intentional",
				Metadata: map[string]any{
					"public_members": info.PublicAccess.PublicMembers,
					"public_roles":   info.PublicAccess.PublicRoles,
				},
			})
		}
	}

	// Filter by severity
	result.Findings = filterBySeverity(result.Findings, cfg.SeverityMin)

	// Build summary
	result.Summary = buildSummary(result.Findings, result.Summary.TotalBuckets)

	return result
}

// filterBySeverity filters findings by minimum severity.
func filterBySeverity(findings []Finding, minSeverity Severity) []Finding {
	if minSeverity == "" {
		return findings
	}
	minRank := SeverityRank(minSeverity)
	var filtered []Finding
	for _, f := range findings {
		if SeverityRank(f.Severity) >= minRank {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// buildSummary builds aggregate summary from findings.
func buildSummary(findings []Finding, totalBuckets int) Summary {
	s := Summary{
		TotalBuckets:   totalBuckets,
		TotalFindings:  len(findings),
		BySeverity:     make(map[string]int),
		ByFindingID:    make(map[string]int),
		ByResourceType: make(map[string]int),
	}
	for _, f := range findings {
		s.BySeverity[string(f.Severity)]++
		s.ByFindingID[string(f.ID)]++
		s.ByResourceType[string(f.ResourceType)]++
	}
	return s
}

// referencedFiles extracts unique file paths from references.
func referencedFiles(refs []scanner.Reference) []string {
	seen := make(map[string]bool)
	var files []string
	for _, ref := range refs {
		if !seen[ref.File] {
			files = append(files, ref.File)
			seen[ref.File] = true
		}
	}
	return files
}
