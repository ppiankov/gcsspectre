package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRepoScanner(t *testing.T) {
	tmpDir := t.TempDir()

	testFiles := map[string]string{
		"config.yaml": `
app:
  bucket: test-bucket-123
  prefix: gs://test-bucket-123/data/
`,
		"app.py": `
from google.cloud import storage
GCS_BUCKET = "my-python-bucket"
client = storage.Client()
bucket = client.bucket("my-python-bucket")
blob = bucket.blob("key")
blob.upload_from_filename("file.txt")
`,
		"main.tf": `
resource "google_storage_bucket" "data" {
  name     = "terraform-bucket"
  location = "US"
}
`,
	}

	for filename, content := range testFiles {
		path := filepath.Join(tmpDir, filename)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}

	sc := NewRepoScanner(tmpDir)
	refs, err := sc.Scan(context.Background())
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(refs) == 0 {
		t.Fatal("Expected to find GCS references, got none")
	}

	buckets := make(map[string]bool)
	for _, ref := range refs {
		buckets[ref.Bucket] = true
	}

	expectedBuckets := []string{"test-bucket-123", "my-python-bucket", "terraform-bucket"}
	for _, expected := range expectedBuckets {
		if !buckets[expected] {
			t.Errorf("Expected to find bucket %s, but it was not found", expected)
		}
	}
}

func TestScanYAML(t *testing.T) {
	tmpDir := t.TempDir()
	yamlFile := filepath.Join(tmpDir, "test.yaml")

	content := `
storage:
  bucket: yaml-test-bucket
  url: gs://yaml-test-bucket/prefix/data
`
	if err := os.WriteFile(yamlFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	refs, err := scanYAML(yamlFile)
	if err != nil {
		t.Fatalf("scanYAML failed: %v", err)
	}

	if len(refs) == 0 {
		t.Fatal("Expected to find references in YAML")
	}

	found := false
	for _, ref := range refs {
		if ref.Bucket == "yaml-test-bucket" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected to find yaml-test-bucket")
	}
}

func TestScanYAML_GCSBucketField(t *testing.T) {
	tmpDir := t.TempDir()
	yamlFile := filepath.Join(tmpDir, "deploy.yaml")

	content := `
resources:
  cloud_function:
    gcs_bucket: function-bucket
    storage_bucket: storage-test-bucket
`
	if err := os.WriteFile(yamlFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	refs, err := scanYAML(yamlFile)
	if err != nil {
		t.Fatalf("scanYAML failed: %v", err)
	}

	buckets := make(map[string]bool)
	for _, ref := range refs {
		buckets[ref.Bucket] = true
	}

	if !buckets["function-bucket"] {
		t.Error("Expected to find function-bucket from gcs_bucket field")
	}
	if !buckets["storage-test-bucket"] {
		t.Error("Expected to find storage-test-bucket from storage_bucket field")
	}
}

func TestScanTerraform(t *testing.T) {
	tmpDir := t.TempDir()
	tfFile := filepath.Join(tmpDir, "main.tf")

	content := `
resource "google_storage_bucket" "app_data" {
  name     = "tf-test-bucket"
  location = "US"
}

resource "google_storage_bucket" "backups" {
  name     = "tf-backup-bucket"
  location = "EU"
}
`
	if err := os.WriteFile(tfFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	refs, err := scanTerraform(tfFile)
	if err != nil {
		t.Fatalf("scanTerraform failed: %v", err)
	}

	if len(refs) < 2 {
		t.Fatalf("Expected to find at least 2 buckets, found %d", len(refs))
	}

	buckets := make(map[string]bool)
	for _, ref := range refs {
		buckets[ref.Bucket] = true
	}

	if !buckets["tf-test-bucket"] {
		t.Error("Expected to find tf-test-bucket")
	}
	if !buckets["tf-backup-bucket"] {
		t.Error("Expected to find tf-backup-bucket")
	}
}

func TestScanTerraform_ObjectResource(t *testing.T) {
	tmpDir := t.TempDir()
	tfFile := filepath.Join(tmpDir, "object.tf")

	content := `
resource "google_storage_bucket_object" "object" {
  bucket = "object-bucket"
  name   = "file.txt"
  source = "local/file.txt"
}
`
	if err := os.WriteFile(tfFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	refs, err := scanTerraform(tfFile)
	if err != nil {
		t.Fatalf("scanTerraform failed: %v", err)
	}

	if len(refs) != 1 {
		t.Fatalf("Expected 1 bucket reference, got %d", len(refs))
	}
	if refs[0].Bucket != "object-bucket" {
		t.Fatalf("Expected bucket object-bucket, got %q", refs[0].Bucket)
	}
}

func TestDetectContext(t *testing.T) {
	tests := []struct {
		line     string
		expected string
	}{
		{"blob.download_to_filename('local.txt')", "read"},
		{"blob.upload_from_filename('local.txt')", "write"},
		{"bucket.list_blobs(prefix='data/')", "list"},
		{"client.get_bucket('test')", "read"},
		{"bucket = 'my-bucket'", "unknown"},
	}

	for _, tt := range tests {
		result := detectContext(tt.line)
		if result != tt.expected {
			t.Errorf("detectContext(%q) = %q, want %q", tt.line, result, tt.expected)
		}
	}
}

func TestScanJSON_HTTPAndGSURL(t *testing.T) {
	tmpDir := t.TempDir()
	jsonFile := filepath.Join(tmpDir, "config.json")

	content := `{"backup":"gs://json-bucket/path/file","url":"https://storage.googleapis.com/http-bucket/key"}`
	if err := os.WriteFile(jsonFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	refs, err := scanJSON(jsonFile)
	if err != nil {
		t.Fatalf("scanJSON failed: %v", err)
	}
	if len(refs) < 2 {
		t.Fatalf("Expected at least 2 references, got %d", len(refs))
	}

	buckets := make(map[string]Reference)
	for _, ref := range refs {
		buckets[ref.Bucket] = ref
	}

	ref, ok := buckets["json-bucket"]
	if !ok {
		t.Fatal("Expected to find json-bucket")
	}
	if ref.Prefix != "path/file" {
		t.Fatalf("Expected prefix path/file, got %q", ref.Prefix)
	}

	ref, ok = buckets["http-bucket"]
	if !ok {
		t.Fatal("Expected to find http-bucket")
	}
	if ref.Prefix != "key" {
		t.Fatalf("Expected prefix key, got %q", ref.Prefix)
	}
}

func TestScanEnv_PatternsAndComments(t *testing.T) {
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, "service.env")

	content := `
# GCS_BUCKET=comment-bucket
GCS_BUCKET=env-bucket
BUCKET_NAME="name-bucket"
STORAGE_BUCKET='storage-bucket'
BUCKET=plain-bucket
DATA=gs://url-bucket/prefix
`
	if err := os.WriteFile(envFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	refs, err := scanEnv(envFile)
	if err != nil {
		t.Fatalf("scanEnv failed: %v", err)
	}

	buckets := make(map[string]bool)
	for _, ref := range refs {
		buckets[ref.Bucket] = true
	}

	if buckets["comment-bucket"] {
		t.Fatal("Did not expect comment-bucket to be scanned")
	}

	expected := []string{"env-bucket", "name-bucket", "storage-bucket", "plain-bucket", "url-bucket"}
	for _, bucket := range expected {
		if !buckets[bucket] {
			t.Fatalf("Expected to find bucket %s", bucket)
		}
	}
}

func TestScanCode_DeduplicatesBucketName(t *testing.T) {
	tmpDir := t.TempDir()
	codeFile := filepath.Join(tmpDir, "main.go")

	content := `const url = "gs://dup-bucket/path"; const bucket = "dup-bucket"`
	if err := os.WriteFile(codeFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	refs, err := scanCode(codeFile)
	if err != nil {
		t.Fatalf("scanCode failed: %v", err)
	}

	if len(refs) != 1 {
		t.Fatalf("Expected 1 reference, got %d", len(refs))
	}
	if refs[0].Bucket != "dup-bucket" {
		t.Fatalf("Expected bucket dup-bucket, got %q", refs[0].Bucket)
	}
	if refs[0].Prefix != "path" {
		t.Fatalf("Expected prefix path, got %q", refs[0].Prefix)
	}
}

func TestScanFile_RoutesByExtension(t *testing.T) {
	tmpDir := t.TempDir()
	envFile := filepath.Join(tmpDir, "service.env")
	if err := os.WriteFile(envFile, []byte("GCS_BUCKET=env-file-bucket\n"), 0644); err != nil {
		t.Fatalf("Failed to create env file: %v", err)
	}

	sc := NewRepoScanner(tmpDir)
	refs, err := sc.scanFile(envFile)
	if err != nil {
		t.Fatalf("scanFile failed: %v", err)
	}
	if len(refs) != 1 || refs[0].Bucket != "env-file-bucket" {
		t.Fatalf("Expected env-file-bucket reference, got %v", refs)
	}

	unknownFile := filepath.Join(tmpDir, "notes.txt")
	if err := os.WriteFile(unknownFile, []byte("nothing here"), 0644); err != nil {
		t.Fatalf("Failed to create txt file: %v", err)
	}

	refs, err = sc.scanFile(unknownFile)
	if err != nil {
		t.Fatalf("scanFile failed: %v", err)
	}
	if len(refs) != 0 {
		t.Fatalf("Expected no references for unknown extension, got %d", len(refs))
	}
}

func TestScanCode_HTTPGCSUrl(t *testing.T) {
	tmpDir := t.TempDir()
	codeFile := filepath.Join(tmpDir, "app.py")

	content := `url = "https://storage.googleapis.com/http-code-bucket/data/file.csv"`
	if err := os.WriteFile(codeFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	refs, err := scanCode(codeFile)
	if err != nil {
		t.Fatalf("scanCode failed: %v", err)
	}

	if len(refs) == 0 {
		t.Fatal("Expected to find HTTP GCS reference")
	}

	if refs[0].Bucket != "http-code-bucket" {
		t.Fatalf("Expected bucket http-code-bucket, got %q", refs[0].Bucket)
	}
	if refs[0].Prefix != "data/file.csv" {
		t.Fatalf("Expected prefix data/file.csv, got %q", refs[0].Prefix)
	}
}
