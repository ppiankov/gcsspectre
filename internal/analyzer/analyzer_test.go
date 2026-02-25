package analyzer

import (
	"testing"

	"github.com/ppiankov/gcsspectre/internal/gcs"
	"github.com/ppiankov/gcsspectre/internal/scanner"
)

func TestAnalyze_MissingBucket(t *testing.T) {
	refs := []scanner.Reference{
		{Bucket: "missing-bucket", File: "main.go", Line: 1},
	}
	bucketInfo := map[string]*gcs.BucketInfo{
		"missing-bucket": {Name: "missing-bucket", Exists: false},
	}

	result := Analyze(refs, bucketInfo, AnalyzerConfig{})

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].ID != FindingMissingBucket {
		t.Fatalf("expected MISSING_BUCKET, got %s", result.Findings[0].ID)
	}
	if result.Findings[0].Severity != SeverityHigh {
		t.Fatalf("expected high severity, got %s", result.Findings[0].Severity)
	}
}

func TestAnalyze_MissingPrefix(t *testing.T) {
	refs := []scanner.Reference{
		{Bucket: "my-bucket", Prefix: "logs/", File: "config.yaml", Line: 3},
	}
	bucketInfo := map[string]*gcs.BucketInfo{
		"my-bucket": {
			Name:   "my-bucket",
			Exists: true,
			Prefixes: []gcs.PrefixInfo{
				{Prefix: "logs/", Exists: false},
			},
		},
	}

	result := Analyze(refs, bucketInfo, AnalyzerConfig{})

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].ID != FindingMissingPrefix {
		t.Fatalf("expected MISSING_PREFIX, got %s", result.Findings[0].ID)
	}
}

func TestAnalyze_StalePrefix(t *testing.T) {
	refs := []scanner.Reference{
		{Bucket: "my-bucket", Prefix: "old-data/", File: "app.py", Line: 5},
	}
	bucketInfo := map[string]*gcs.BucketInfo{
		"my-bucket": {
			Name:   "my-bucket",
			Exists: true,
			Prefixes: []gcs.PrefixInfo{
				{Prefix: "old-data/", Exists: true, ObjectCount: 50, DaysSinceUpdated: 120},
			},
		},
	}

	result := Analyze(refs, bucketInfo, AnalyzerConfig{StaleDays: 90})

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].ID != FindingStalePrefix {
		t.Fatalf("expected STALE_PREFIX, got %s", result.Findings[0].ID)
	}
}

func TestAnalyze_FreshPrefix(t *testing.T) {
	refs := []scanner.Reference{
		{Bucket: "my-bucket", Prefix: "data/", File: "app.py", Line: 5},
	}
	bucketInfo := map[string]*gcs.BucketInfo{
		"my-bucket": {
			Name:   "my-bucket",
			Exists: true,
			Prefixes: []gcs.PrefixInfo{
				{Prefix: "data/", Exists: true, ObjectCount: 10, DaysSinceUpdated: 5},
			},
		},
	}

	result := Analyze(refs, bucketInfo, AnalyzerConfig{StaleDays: 90})

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestAnalyze_NoLifecycleOnLargeBucket(t *testing.T) {
	refs := []scanner.Reference{
		{Bucket: "big-bucket", File: "main.go", Line: 1},
	}
	bucketInfo := map[string]*gcs.BucketInfo{
		"big-bucket": {
			Name:           "big-bucket",
			Exists:         true,
			LifecycleRules: 0,
			ObjectCount:    500,
		},
	}

	result := Analyze(refs, bucketInfo, AnalyzerConfig{})

	found := false
	for _, f := range result.Findings {
		if f.ID == FindingNoLifecycle {
			found = true
		}
	}
	if !found {
		t.Fatal("expected NO_LIFECYCLE finding for large bucket without lifecycle")
	}
}

func TestAnalyze_PublicBucketInScanMode(t *testing.T) {
	refs := []scanner.Reference{
		{Bucket: "public-bucket", File: "app.go", Line: 10},
	}
	bucketInfo := map[string]*gcs.BucketInfo{
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

	result := Analyze(refs, bucketInfo, AnalyzerConfig{CheckPublic: true})

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

func TestAnalyze_PublicCheckDisabled(t *testing.T) {
	refs := []scanner.Reference{
		{Bucket: "public-bucket", File: "app.go", Line: 10},
	}
	bucketInfo := map[string]*gcs.BucketInfo{
		"public-bucket": {
			Name:   "public-bucket",
			Exists: true,
			PublicAccess: &gcs.PublicAccessInfo{
				IsPublic:      true,
				PublicMembers: []string{"allUsers"},
			},
		},
	}

	result := Analyze(refs, bucketInfo, AnalyzerConfig{CheckPublic: false})

	for _, f := range result.Findings {
		if f.ID == FindingPublicBucket {
			t.Fatal("did not expect PUBLIC_BUCKET finding when check_public is false")
		}
	}
}

func TestAnalyze_SeverityFilter(t *testing.T) {
	refs := []scanner.Reference{
		{Bucket: "missing-bucket", File: "main.go", Line: 1},
		{Bucket: "ok-bucket", Prefix: "stale/", File: "app.py", Line: 5},
	}
	bucketInfo := map[string]*gcs.BucketInfo{
		"missing-bucket": {Name: "missing-bucket", Exists: false},
		"ok-bucket": {
			Name:   "ok-bucket",
			Exists: true,
			Prefixes: []gcs.PrefixInfo{
				{Prefix: "stale/", Exists: true, ObjectCount: 10, DaysSinceUpdated: 200},
			},
		},
	}

	// No filter: should get both MISSING_BUCKET (high) and STALE_PREFIX (low)
	result := Analyze(refs, bucketInfo, AnalyzerConfig{StaleDays: 90})
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}

	// Filter high: should only get MISSING_BUCKET
	result = Analyze(refs, bucketInfo, AnalyzerConfig{StaleDays: 90, SeverityMin: SeverityHigh})
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding with high filter, got %d", len(result.Findings))
	}
	if result.Findings[0].ID != FindingMissingBucket {
		t.Fatalf("expected MISSING_BUCKET, got %s", result.Findings[0].ID)
	}
}

func TestAnalyze_Summary(t *testing.T) {
	refs := []scanner.Reference{
		{Bucket: "bucket-a", File: "a.go", Line: 1},
		{Bucket: "bucket-b", File: "b.go", Line: 1},
	}
	bucketInfo := map[string]*gcs.BucketInfo{
		"bucket-a": {Name: "bucket-a", Exists: false},
		"bucket-b": {
			Name:   "bucket-b",
			Exists: true,
			PublicAccess: &gcs.PublicAccessInfo{
				IsPublic:      true,
				PublicMembers: []string{"allUsers"},
			},
		},
	}

	result := Analyze(refs, bucketInfo, AnalyzerConfig{CheckPublic: true})

	if result.Summary.TotalBuckets != 2 {
		t.Fatalf("expected 2 total buckets, got %d", result.Summary.TotalBuckets)
	}
	if result.Summary.TotalFindings != 2 {
		t.Fatalf("expected 2 total findings, got %d", result.Summary.TotalFindings)
	}
	if result.Summary.BySeverity["high"] != 1 {
		t.Fatalf("expected 1 high finding, got %d", result.Summary.BySeverity["high"])
	}
	if result.Summary.BySeverity["critical"] != 1 {
		t.Fatalf("expected 1 critical finding, got %d", result.Summary.BySeverity["critical"])
	}
}

func TestAnalyze_BucketNotInInfo(t *testing.T) {
	refs := []scanner.Reference{
		{Bucket: "unknown-bucket", File: "main.go", Line: 1},
	}
	bucketInfo := map[string]*gcs.BucketInfo{} // Empty

	result := Analyze(refs, bucketInfo, AnalyzerConfig{})

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].ID != FindingMissingBucket {
		t.Fatalf("expected MISSING_BUCKET, got %s", result.Findings[0].ID)
	}
}

func TestAnalyze_DefaultStaleThreshold(t *testing.T) {
	refs := []scanner.Reference{
		{Bucket: "my-bucket", Prefix: "data/", File: "app.py", Line: 5},
	}
	bucketInfo := map[string]*gcs.BucketInfo{
		"my-bucket": {
			Name:   "my-bucket",
			Exists: true,
			Prefixes: []gcs.PrefixInfo{
				{Prefix: "data/", Exists: true, ObjectCount: 10, DaysSinceUpdated: 100},
			},
		},
	}

	// StaleDays=0 should default to 90
	result := Analyze(refs, bucketInfo, AnalyzerConfig{})

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].ID != FindingStalePrefix {
		t.Fatalf("expected STALE_PREFIX, got %s", result.Findings[0].ID)
	}
}

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		severity Severity
		rank     int
	}{
		{SeverityCritical, 4},
		{SeverityHigh, 3},
		{SeverityMedium, 2},
		{SeverityLow, 1},
		{Severity("unknown"), 0},
	}

	for _, tt := range tests {
		if got := SeverityRank(tt.severity); got != tt.rank {
			t.Errorf("SeverityRank(%q) = %d, want %d", tt.severity, got, tt.rank)
		}
	}
}
