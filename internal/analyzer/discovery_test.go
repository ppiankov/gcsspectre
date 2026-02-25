package analyzer

import (
	"testing"

	"github.com/ppiankov/gcsspectre/internal/gcs"
)

func TestDiscovery_NoLifecycle(t *testing.T) {
	buckets := map[string]*gcs.BucketInfo{
		"no-lifecycle": {
			Name:           "no-lifecycle",
			Exists:         true,
			LifecycleRules: 0,
			Location:       "US",
			StorageClass:   "STANDARD",
		},
	}

	result := AnalyzeDiscovery(buckets, DiscoveryConfig{})

	found := false
	for _, f := range result.Findings {
		if f.ID == FindingNoLifecycle && f.ResourceID == "no-lifecycle" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected NO_LIFECYCLE finding")
	}
}

func TestDiscovery_WithLifecycle(t *testing.T) {
	buckets := map[string]*gcs.BucketInfo{
		"has-lifecycle": {
			Name:                 "has-lifecycle",
			Exists:               true,
			LifecycleRules:       2,
			LifecycleHasDelete:   true,
			UniformAccessEnabled: true,
		},
	}

	result := AnalyzeDiscovery(buckets, DiscoveryConfig{})

	for _, f := range result.Findings {
		if f.ID == FindingNoLifecycle && f.ResourceID == "has-lifecycle" {
			t.Fatal("did not expect NO_LIFECYCLE finding for bucket with lifecycle")
		}
	}
}

func TestDiscovery_StaleObjects(t *testing.T) {
	buckets := map[string]*gcs.BucketInfo{
		"stale-bucket": {
			Name:            "stale-bucket",
			Exists:          true,
			DaysSinceUpdate: 120,
			StorageClass:    "STANDARD",
			ObjectCount:     50,
		},
	}

	result := AnalyzeDiscovery(buckets, DiscoveryConfig{StaleDays: 90})

	found := false
	for _, f := range result.Findings {
		if f.ID == FindingStaleObjects {
			found = true
			if f.Severity != SeverityHigh {
				t.Fatalf("expected high severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected STALE_OBJECTS finding")
	}
}

func TestDiscovery_StaleObjects_SkipsNonStandard(t *testing.T) {
	buckets := map[string]*gcs.BucketInfo{
		"archive-bucket": {
			Name:            "archive-bucket",
			Exists:          true,
			DaysSinceUpdate: 365,
			StorageClass:    "COLDLINE",
			ObjectCount:     100,
		},
	}

	result := AnalyzeDiscovery(buckets, DiscoveryConfig{StaleDays: 90})

	for _, f := range result.Findings {
		if f.ID == FindingStaleObjects && f.ResourceID == "archive-bucket" {
			t.Fatal("did not expect STALE_OBJECTS for Coldline bucket")
		}
	}
}

func TestDiscovery_StaleObjects_SkipsEmpty(t *testing.T) {
	buckets := map[string]*gcs.BucketInfo{
		"empty-bucket": {
			Name:            "empty-bucket",
			Exists:          true,
			DaysSinceUpdate: 200,
			StorageClass:    "STANDARD",
			IsEmpty:         true,
		},
	}

	result := AnalyzeDiscovery(buckets, DiscoveryConfig{StaleDays: 90})

	for _, f := range result.Findings {
		if f.ID == FindingStaleObjects && f.ResourceID == "empty-bucket" {
			t.Fatal("did not expect STALE_OBJECTS for empty bucket")
		}
	}
}

func TestDiscovery_VersionBloat(t *testing.T) {
	buckets := map[string]*gcs.BucketInfo{
		"versioned": {
			Name:               "versioned",
			Exists:             true,
			VersioningEnabled:  true,
			LifecycleRules:     0,
			LifecycleHasDelete: false,
		},
	}

	result := AnalyzeDiscovery(buckets, DiscoveryConfig{VersionDays: 30})

	found := false
	for _, f := range result.Findings {
		if f.ID == FindingVersionBloat {
			found = true
		}
	}
	if !found {
		t.Fatal("expected VERSION_BLOAT finding")
	}
}

func TestDiscovery_VersionBloat_WithDeleteRule(t *testing.T) {
	buckets := map[string]*gcs.BucketInfo{
		"versioned-ok": {
			Name:               "versioned-ok",
			Exists:             true,
			VersioningEnabled:  true,
			LifecycleRules:     1,
			LifecycleHasDelete: true,
		},
	}

	result := AnalyzeDiscovery(buckets, DiscoveryConfig{})

	for _, f := range result.Findings {
		if f.ID == FindingVersionBloat && f.ResourceID == "versioned-ok" {
			t.Fatal("did not expect VERSION_BLOAT for bucket with delete lifecycle rule")
		}
	}
}

func TestDiscovery_PublicBucket(t *testing.T) {
	buckets := map[string]*gcs.BucketInfo{
		"public-bucket": {
			Name:   "public-bucket",
			Exists: true,
			PublicAccess: &gcs.PublicAccessInfo{
				IsPublic:      true,
				PublicMembers: []string{"allUsers"},
				PublicRoles:   []string{"roles/storage.objectViewer"},
			},
		},
	}

	result := AnalyzeDiscovery(buckets, DiscoveryConfig{CheckPublic: true})

	found := false
	for _, f := range result.Findings {
		if f.ID == FindingPublicBucket {
			found = true
			if f.Severity != SeverityCritical {
				t.Fatalf("expected critical severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected PUBLIC_BUCKET finding")
	}
}

func TestDiscovery_PublicCheckDisabled(t *testing.T) {
	buckets := map[string]*gcs.BucketInfo{
		"public-bucket": {
			Name:   "public-bucket",
			Exists: true,
			PublicAccess: &gcs.PublicAccessInfo{
				IsPublic:      true,
				PublicMembers: []string{"allUsers"},
			},
		},
	}

	result := AnalyzeDiscovery(buckets, DiscoveryConfig{CheckPublic: false})

	for _, f := range result.Findings {
		if f.ID == FindingPublicBucket {
			t.Fatal("did not expect PUBLIC_BUCKET when check disabled")
		}
	}
}

func TestDiscovery_NoUniformAccess(t *testing.T) {
	buckets := map[string]*gcs.BucketInfo{
		"legacy-acl": {
			Name:                 "legacy-acl",
			Exists:               true,
			UniformAccessEnabled: false,
		},
	}

	result := AnalyzeDiscovery(buckets, DiscoveryConfig{})

	found := false
	for _, f := range result.Findings {
		if f.ID == FindingNoUniformAccess {
			found = true
			if f.Severity != SeverityMedium {
				t.Fatalf("expected medium severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected NO_UNIFORM_ACCESS finding")
	}
}

func TestDiscovery_UniformAccessEnabled(t *testing.T) {
	buckets := map[string]*gcs.BucketInfo{
		"uniform-bucket": {
			Name:                 "uniform-bucket",
			Exists:               true,
			UniformAccessEnabled: true,
			LifecycleRules:       1,
		},
	}

	result := AnalyzeDiscovery(buckets, DiscoveryConfig{})

	for _, f := range result.Findings {
		if f.ID == FindingNoUniformAccess && f.ResourceID == "uniform-bucket" {
			t.Fatal("did not expect NO_UNIFORM_ACCESS for bucket with uniform access")
		}
	}
}

func TestDiscovery_CrossProject(t *testing.T) {
	buckets := map[string]*gcs.BucketInfo{
		"cross-project-bucket": {
			Name:    "cross-project-bucket",
			Exists:  true,
			Project: "other-project",
		},
	}

	result := AnalyzeDiscovery(buckets, DiscoveryConfig{ProjectID: "my-project"})

	found := false
	for _, f := range result.Findings {
		if f.ID == FindingCrossProject {
			found = true
			if f.Severity != SeverityLow {
				t.Fatalf("expected low severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected CROSS_PROJECT finding")
	}
}

func TestDiscovery_CrossProject_SameProject(t *testing.T) {
	buckets := map[string]*gcs.BucketInfo{
		"my-bucket": {
			Name:    "my-bucket",
			Exists:  true,
			Project: "my-project",
		},
	}

	result := AnalyzeDiscovery(buckets, DiscoveryConfig{ProjectID: "my-project"})

	for _, f := range result.Findings {
		if f.ID == FindingCrossProject {
			t.Fatal("did not expect CROSS_PROJECT for same project")
		}
	}
}

func TestDiscovery_RetentionGap(t *testing.T) {
	buckets := map[string]*gcs.BucketInfo{
		"compliance-bucket": {
			Name:               "compliance-bucket",
			Exists:             true,
			RetentionPolicySet: false,
			Labels:             map[string]string{"purpose": "compliance"},
		},
	}

	result := AnalyzeDiscovery(buckets, DiscoveryConfig{})

	found := false
	for _, f := range result.Findings {
		if f.ID == FindingRetentionGap {
			found = true
			if f.Severity != SeverityHigh {
				t.Fatalf("expected high severity, got %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("expected RETENTION_GAP finding")
	}
}

func TestDiscovery_RetentionGap_WithPolicy(t *testing.T) {
	buckets := map[string]*gcs.BucketInfo{
		"compliance-ok": {
			Name:               "compliance-ok",
			Exists:             true,
			RetentionPolicySet: true,
			Labels:             map[string]string{"purpose": "compliance"},
		},
	}

	result := AnalyzeDiscovery(buckets, DiscoveryConfig{})

	for _, f := range result.Findings {
		if f.ID == FindingRetentionGap && f.ResourceID == "compliance-ok" {
			t.Fatal("did not expect RETENTION_GAP for bucket with retention policy")
		}
	}
}

func TestDiscovery_RetentionGap_NonComplianceBucket(t *testing.T) {
	buckets := map[string]*gcs.BucketInfo{
		"normal-bucket": {
			Name:               "normal-bucket",
			Exists:             true,
			RetentionPolicySet: false,
			Labels:             map[string]string{"env": "prod"},
		},
	}

	result := AnalyzeDiscovery(buckets, DiscoveryConfig{})

	for _, f := range result.Findings {
		if f.ID == FindingRetentionGap && f.ResourceID == "normal-bucket" {
			t.Fatal("did not expect RETENTION_GAP for non-compliance bucket")
		}
	}
}

func TestIsComplianceBucket(t *testing.T) {
	tests := []struct {
		name     string
		labels   map[string]string
		expected bool
	}{
		{"nil labels", nil, false},
		{"empty labels", map[string]string{}, false},
		{"compliance key", map[string]string{"compliance": "true"}, true},
		{"audit value", map[string]string{"purpose": "audit"}, true},
		{"regulatory partial", map[string]string{"data-regulatory-hold": "yes"}, true},
		{"retention in key", map[string]string{"retention-policy": "7y"}, true},
		{"unrelated", map[string]string{"env": "prod", "team": "data"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isComplianceBucket(tt.labels); got != tt.expected {
				t.Errorf("isComplianceBucket(%v) = %v, want %v", tt.labels, got, tt.expected)
			}
		})
	}
}

func TestDiscovery_SeverityFilter(t *testing.T) {
	buckets := map[string]*gcs.BucketInfo{
		"critical-bucket": {
			Name:   "critical-bucket",
			Exists: true,
			PublicAccess: &gcs.PublicAccessInfo{
				IsPublic:      true,
				PublicMembers: []string{"allUsers"},
			},
		},
		"low-bucket": {
			Name:    "low-bucket",
			Exists:  true,
			Project: "other-project",
		},
	}

	// Critical filter: only PUBLIC_BUCKET
	result := AnalyzeDiscovery(buckets, DiscoveryConfig{
		CheckPublic: true,
		ProjectID:   "my-project",
		SeverityMin: SeverityCritical,
	})

	for _, f := range result.Findings {
		if SeverityRank(f.Severity) < SeverityRank(SeverityCritical) {
			t.Fatalf("expected only critical findings, got %s with severity %s", f.ID, f.Severity)
		}
	}
}

func TestDiscovery_ExcludeBuckets(t *testing.T) {
	buckets := map[string]*gcs.BucketInfo{
		"include-bucket": {
			Name:           "include-bucket",
			Exists:         true,
			LifecycleRules: 0,
		},
		"exclude-bucket": {
			Name:           "exclude-bucket",
			Exists:         true,
			LifecycleRules: 0,
		},
	}

	result := AnalyzeDiscovery(buckets, DiscoveryConfig{
		ExcludeBuckets: map[string]bool{"exclude-bucket": true},
	})

	for _, f := range result.Findings {
		if f.ResourceID == "exclude-bucket" {
			t.Fatal("did not expect findings for excluded bucket")
		}
	}
}

func TestDiscovery_Summary(t *testing.T) {
	buckets := map[string]*gcs.BucketInfo{
		"bucket-a": {
			Name:           "bucket-a",
			Exists:         true,
			LifecycleRules: 0,
		},
		"bucket-b": {
			Name:   "bucket-b",
			Exists: true,
			PublicAccess: &gcs.PublicAccessInfo{
				IsPublic:      true,
				PublicMembers: []string{"allUsers"},
			},
		},
	}

	result := AnalyzeDiscovery(buckets, DiscoveryConfig{CheckPublic: true})

	if result.Summary.TotalBuckets != 2 {
		t.Fatalf("expected 2 total buckets, got %d", result.Summary.TotalBuckets)
	}
	if result.Summary.TotalFindings == 0 {
		t.Fatal("expected findings in summary")
	}
}
