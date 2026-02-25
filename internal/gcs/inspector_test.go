package gcs

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/iam"
	iampb "cloud.google.com/go/iam/apiv1/iampb"

	"cloud.google.com/go/storage"
	"github.com/ppiankov/gcsspectre/internal/scanner"
)

// mockStorage implements StorageAPI for testing.
type mockStorage struct {
	buckets   []*storage.BucketAttrs
	attrs     map[string]*storage.BucketAttrs
	policies  map[string]*iam.Policy3
	objects   map[string][]*storage.ObjectAttrs
	listErr   error
	attrsErr  map[string]error
	policyErr map[string]error
	objErr    map[string]error
}

func newMockStorage() *mockStorage {
	return &mockStorage{
		attrs:     make(map[string]*storage.BucketAttrs),
		policies:  make(map[string]*iam.Policy3),
		objects:   make(map[string][]*storage.ObjectAttrs),
		attrsErr:  make(map[string]error),
		policyErr: make(map[string]error),
		objErr:    make(map[string]error),
	}
}

func (m *mockStorage) ListBuckets(_ context.Context, _ string) ([]*storage.BucketAttrs, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.buckets, nil
}

func (m *mockStorage) BucketAttrs(_ context.Context, bucket string) (*storage.BucketAttrs, error) {
	if err, ok := m.attrsErr[bucket]; ok {
		return nil, err
	}
	if attrs, ok := m.attrs[bucket]; ok {
		return attrs, nil
	}
	return nil, errors.New("notFound")
}

func (m *mockStorage) BucketIAMPolicy(_ context.Context, bucket string) (*iam.Policy3, error) {
	if err, ok := m.policyErr[bucket]; ok {
		return nil, err
	}
	if policy, ok := m.policies[bucket]; ok {
		return policy, nil
	}
	return &iam.Policy3{}, nil
}

func (m *mockStorage) ListObjects(_ context.Context, bucket string, query *storage.Query) ([]*storage.ObjectAttrs, error) {
	key := bucket
	if query != nil && query.Prefix != "" {
		key = bucket + "/" + query.Prefix
	}
	if err, ok := m.objErr[key]; ok {
		return nil, err
	}
	if objs, ok := m.objects[key]; ok {
		return objs, nil
	}
	return nil, nil
}

func (m *mockStorage) Close() error {
	return nil
}

func TestNewInspector_DefaultConcurrency(t *testing.T) {
	mock := newMockStorage()
	inspector := NewInspector(mock, "test-project", 0)
	if inspector.concurrency != 10 {
		t.Fatalf("expected default concurrency 10, got %d", inspector.concurrency)
	}
}

func TestInspector_SetCheckPublic(t *testing.T) {
	mock := newMockStorage()
	inspector := NewInspector(mock, "test-project", 5)
	inspector.SetCheckPublic(false)
	if inspector.checkPublic {
		t.Fatal("expected checkPublic false")
	}
}

func TestInspector_ReportProgress(t *testing.T) {
	mock := newMockStorage()
	inspector := NewInspector(mock, "test-project", 5)

	var gotCurrent, gotTotal int
	var gotMessage string
	inspector.SetProgressCallback(func(current, total int, message string) {
		gotCurrent = current
		gotTotal = total
		gotMessage = message
	})

	inspector.reportProgress(2, 3, "working")
	if gotCurrent != 2 || gotTotal != 3 || gotMessage != "working" {
		t.Fatalf("unexpected progress values: %d %d %s", gotCurrent, gotTotal, gotMessage)
	}
}

func TestExtractPrefixes(t *testing.T) {
	refs := []scanner.Reference{
		{Bucket: "a", Prefix: "logs/"},
		{Bucket: "a", Prefix: ""},
		{Bucket: "b", Prefix: "logs/"},
		{Bucket: "c", Prefix: "data/"},
	}

	prefixes := extractPrefixes(refs)
	if len(prefixes) != 2 {
		t.Fatalf("expected 2 unique prefixes, got %d", len(prefixes))
	}
	found := map[string]bool{}
	for _, p := range prefixes {
		found[p] = true
	}
	if !found["logs/"] || !found["data/"] {
		t.Fatalf("unexpected prefixes: %v", prefixes)
	}
}

func TestFormatError(t *testing.T) {
	if FormatError("op", "bucket", nil) != "" {
		t.Fatal("expected empty error string for nil error")
	}

	accessErr := FormatError("op", "bucket", errors.New("AccessDenied"))
	if !strings.Contains(accessErr, "Access Denied") {
		t.Fatalf("unexpected access error: %s", accessErr)
	}

	missingErr := FormatError("op", "bucket", errors.New("notFound"))
	if !strings.Contains(missingErr, "does not exist") {
		t.Fatalf("unexpected missing error: %s", missingErr)
	}

	rateErr := FormatError("op", "bucket", errors.New("rateLimitExceeded"))
	if !strings.Contains(rateErr, "Rate limit exceeded") {
		t.Fatalf("unexpected rate error: %s", rateErr)
	}

	genericErr := FormatError("op", "bucket", errors.New("boom"))
	if !strings.Contains(genericErr, "boom") {
		t.Fatalf("unexpected generic error: %s", genericErr)
	}
}

func TestInspectBuckets_MissingBucket(t *testing.T) {
	mock := newMockStorage()
	mock.buckets = []*storage.BucketAttrs{} // No buckets exist

	inspector := NewInspector(mock, "test-project", 5)
	inspector.SetCheckPublic(false)

	refs := []scanner.Reference{
		{Bucket: "missing-bucket", File: "main.go", Line: 1},
	}

	result, err := inspector.InspectBuckets(context.Background(), refs)
	if err != nil {
		t.Fatalf("InspectBuckets failed: %v", err)
	}

	info, ok := result["missing-bucket"]
	if !ok {
		t.Fatal("expected missing-bucket in results")
	}
	if info.Exists {
		t.Fatal("expected bucket to not exist")
	}
}

func TestInspectBuckets_ExistingBucket(t *testing.T) {
	mock := newMockStorage()
	now := time.Now()
	created := now.Add(-30 * 24 * time.Hour)
	mock.buckets = []*storage.BucketAttrs{
		{
			Name:              "my-bucket",
			Location:          "US",
			StorageClass:      "STANDARD",
			Created:           created,
			VersioningEnabled: true,
		},
	}

	updated := now.Add(-5 * 24 * time.Hour)
	mock.objects["my-bucket"] = []*storage.ObjectAttrs{
		{Name: "file.txt", Size: 1024, Updated: updated, StorageClass: "STANDARD"},
	}

	inspector := NewInspector(mock, "test-project", 5)
	inspector.SetCheckPublic(false)

	refs := []scanner.Reference{
		{Bucket: "my-bucket", File: "main.go", Line: 1},
	}

	result, err := inspector.InspectBuckets(context.Background(), refs)
	if err != nil {
		t.Fatalf("InspectBuckets failed: %v", err)
	}

	info := result["my-bucket"]
	if !info.Exists {
		t.Fatal("expected bucket to exist")
	}
	if info.Location != "US" {
		t.Fatalf("expected location US, got %q", info.Location)
	}
	if !info.VersioningEnabled {
		t.Fatal("expected versioning enabled")
	}
	if info.ObjectCount != 1 {
		t.Fatalf("expected 1 object, got %d", info.ObjectCount)
	}
}

func TestInspectBuckets_PublicAccess(t *testing.T) {
	mock := newMockStorage()
	mock.buckets = []*storage.BucketAttrs{
		{Name: "public-bucket", Location: "US", Created: time.Now()},
	}
	mock.policies["public-bucket"] = &iam.Policy3{
		Bindings: []*iampb.Binding{
			{
				Role:    "roles/storage.objectViewer",
				Members: []string{"allUsers"},
			},
		},
	}

	inspector := NewInspector(mock, "test-project", 5)
	inspector.SetCheckPublic(true)

	refs := []scanner.Reference{
		{Bucket: "public-bucket", File: "app.py", Line: 5},
	}

	result, err := inspector.InspectBuckets(context.Background(), refs)
	if err != nil {
		t.Fatalf("InspectBuckets failed: %v", err)
	}

	info := result["public-bucket"]
	if info.PublicAccess == nil {
		t.Fatal("expected public access info")
	}
	if !info.PublicAccess.IsPublic {
		t.Fatal("expected bucket to be public")
	}
}

func TestDiscoverAllBuckets(t *testing.T) {
	mock := newMockStorage()
	now := time.Now()
	mock.buckets = []*storage.BucketAttrs{
		{Name: "bucket-a", Location: "US", StorageClass: "STANDARD", Created: now},
		{Name: "bucket-b", Location: "EU", StorageClass: "NEARLINE", Created: now},
	}

	inspector := NewInspector(mock, "test-project", 5)
	inspector.SetCheckPublic(false)

	result, err := inspector.DiscoverAllBuckets(context.Background())
	if err != nil {
		t.Fatalf("DiscoverAllBuckets failed: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 buckets, got %d", len(result))
	}

	if _, ok := result["bucket-a"]; !ok {
		t.Fatal("expected bucket-a in results")
	}
	if _, ok := result["bucket-b"]; !ok {
		t.Fatal("expected bucket-b in results")
	}
}

func TestInspectBuckets_WithPrefixes(t *testing.T) {
	mock := newMockStorage()
	now := time.Now()
	mock.buckets = []*storage.BucketAttrs{
		{Name: "data-bucket", Location: "US", Created: now},
	}

	updated := now.Add(-10 * 24 * time.Hour)
	mock.objects["data-bucket/logs/"] = []*storage.ObjectAttrs{
		{Name: "logs/app.log", Size: 512, Updated: updated},
	}

	inspector := NewInspector(mock, "test-project", 5)
	inspector.SetCheckPublic(false)

	refs := []scanner.Reference{
		{Bucket: "data-bucket", Prefix: "logs/", File: "config.yaml", Line: 3},
	}

	result, err := inspector.InspectBuckets(context.Background(), refs)
	if err != nil {
		t.Fatalf("InspectBuckets failed: %v", err)
	}

	info := result["data-bucket"]
	if len(info.Prefixes) != 1 {
		t.Fatalf("expected 1 prefix, got %d", len(info.Prefixes))
	}
	if !info.Prefixes[0].Exists {
		t.Fatal("expected prefix to exist")
	}
	if info.Prefixes[0].ObjectCount != 1 {
		t.Fatalf("expected 1 object in prefix, got %d", info.Prefixes[0].ObjectCount)
	}
}

func TestPopulateFromAttrs_Lifecycle(t *testing.T) {
	mock := newMockStorage()
	inspector := NewInspector(mock, "test-project", 5)

	attrs := &storage.BucketAttrs{
		Name:     "lifecycle-bucket",
		Location: "US",
		Created:  time.Now(),
		Lifecycle: storage.Lifecycle{
			Rules: []storage.LifecycleRule{
				{Action: storage.LifecycleAction{Type: storage.DeleteAction}},
				{Action: storage.LifecycleAction{Type: storage.SetStorageClassAction}},
			},
		},
		UniformBucketLevelAccess: storage.UniformBucketLevelAccess{Enabled: true},
		RetentionPolicy: &storage.RetentionPolicy{
			RetentionPeriod: 30 * 24 * time.Hour,
		},
	}

	info := &BucketInfo{Name: "lifecycle-bucket"}
	inspector.populateFromAttrs(info, attrs)

	if info.LifecycleRules != 2 {
		t.Fatalf("expected 2 lifecycle rules, got %d", info.LifecycleRules)
	}
	if !info.LifecycleHasDelete {
		t.Fatal("expected lifecycle has delete")
	}
	if !info.LifecycleHasArchive {
		t.Fatal("expected lifecycle has archive")
	}
	if !info.UniformAccessEnabled {
		t.Fatal("expected uniform access enabled")
	}
	if !info.RetentionPolicySet {
		t.Fatal("expected retention policy set")
	}
}

func TestListBucketsError(t *testing.T) {
	mock := newMockStorage()
	mock.listErr = errors.New("permission denied")

	inspector := NewInspector(mock, "test-project", 5)

	_, err := inspector.InspectBuckets(context.Background(), []scanner.Reference{
		{Bucket: "any-bucket"},
	})
	if err == nil {
		t.Fatal("expected error from InspectBuckets")
	}

	_, err = inspector.DiscoverAllBuckets(context.Background())
	if err == nil {
		t.Fatal("expected error from DiscoverAllBuckets")
	}
}
