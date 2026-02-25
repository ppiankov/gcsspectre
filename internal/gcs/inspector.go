package gcs

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"github.com/ppiankov/gcsspectre/internal/scanner"
)

// ProgressCallback is called during inspection to report progress.
type ProgressCallback func(current, total int, message string)

// Inspector inspects GCS buckets.
type Inspector struct {
	client           StorageAPI
	projectID        string
	concurrency      int
	checkPublic      bool
	progressCallback ProgressCallback
}

// NewInspector creates a new GCS inspector.
func NewInspector(client StorageAPI, projectID string, concurrency int) *Inspector {
	if concurrency <= 0 {
		concurrency = 10
	}
	return &Inspector{
		client:      client,
		projectID:   projectID,
		concurrency: concurrency,
		checkPublic: true,
	}
}

// SetProgressCallback sets the progress callback function.
func (i *Inspector) SetProgressCallback(callback ProgressCallback) {
	i.progressCallback = callback
}

// SetCheckPublic enables or disables public access checking.
func (i *Inspector) SetCheckPublic(enabled bool) {
	i.checkPublic = enabled
}

// reportProgress calls the progress callback if set.
func (i *Inspector) reportProgress(current, total int, message string) {
	if i.progressCallback != nil {
		i.progressCallback(current, total, message)
	}
}

// InspectBuckets inspects buckets referenced in code.
func (i *Inspector) InspectBuckets(ctx context.Context, refs []scanner.Reference) (map[string]*BucketInfo, error) {
	// Group references by bucket
	bucketRefs := make(map[string][]scanner.Reference)
	for _, ref := range refs {
		bucketRefs[ref.Bucket] = append(bucketRefs[ref.Bucket], ref)
	}

	i.reportProgress(0, 1, "Listing project buckets")

	// List all buckets in the project to check existence
	allBuckets, err := i.client.ListBuckets(ctx, i.projectID)
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	existingBuckets := make(map[string]*storage.BucketAttrs)
	for _, b := range allBuckets {
		existingBuckets[b.Name] = b
	}

	// Inspect each referenced bucket concurrently
	bucketInfo := make(map[string]*BucketInfo)
	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, i.concurrency)

	total := len(bucketRefs)
	current := 0

	for bucket, brefs := range bucketRefs {
		wg.Add(1)
		go func(bucket string, brefs []scanner.Reference) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			info := i.inspectBucket(ctx, bucket, brefs, existingBuckets[bucket])

			mu.Lock()
			current++
			i.reportProgress(current, total, fmt.Sprintf("Inspecting %s", bucket))
			bucketInfo[bucket] = info
			mu.Unlock()
		}(bucket, brefs)
	}

	wg.Wait()
	return bucketInfo, nil
}

// DiscoverAllBuckets discovers and inspects all buckets in the project.
func (i *Inspector) DiscoverAllBuckets(ctx context.Context) (map[string]*BucketInfo, error) {
	i.reportProgress(0, 1, "Listing all project buckets")

	allBuckets, err := i.client.ListBuckets(ctx, i.projectID)
	if err != nil {
		return nil, fmt.Errorf("list buckets: %w", err)
	}

	bucketInfo := make(map[string]*BucketInfo)
	var wg sync.WaitGroup
	var mu sync.Mutex
	semaphore := make(chan struct{}, i.concurrency)

	total := len(allBuckets)
	current := 0

	for _, attrs := range allBuckets {
		wg.Add(1)
		go func(attrs *storage.BucketAttrs) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			info := i.inspectBucketFull(ctx, attrs)

			mu.Lock()
			current++
			i.reportProgress(current, total, fmt.Sprintf("Inspecting %s", attrs.Name))
			bucketInfo[attrs.Name] = info
			mu.Unlock()
		}(attrs)
	}

	wg.Wait()
	return bucketInfo, nil
}

// inspectBucket inspects a single code-referenced bucket.
func (i *Inspector) inspectBucket(ctx context.Context, bucket string, refs []scanner.Reference, attrs *storage.BucketAttrs) *BucketInfo {
	info := &BucketInfo{
		Name:   bucket,
		Exists: attrs != nil,
	}

	if attrs == nil {
		return info
	}

	i.populateFromAttrs(info, attrs)

	// Check public access if enabled
	if i.checkPublic {
		i.checkPublicAccess(ctx, bucket, info)
	}

	// Sample objects
	i.sampleObjects(ctx, bucket, info)

	// Inspect prefixes from references
	prefixes := extractPrefixes(refs)
	if len(prefixes) > 0 {
		info.Prefixes = i.inspectPrefixes(ctx, bucket, prefixes)
	}

	return info
}

// inspectBucketFull performs full inspection for discovered buckets.
func (i *Inspector) inspectBucketFull(ctx context.Context, attrs *storage.BucketAttrs) *BucketInfo {
	info := &BucketInfo{
		Name:   attrs.Name,
		Exists: true,
	}

	i.populateFromAttrs(info, attrs)

	// Check public access if enabled
	if i.checkPublic {
		i.checkPublicAccess(ctx, attrs.Name, info)
	}

	// Sample objects
	i.sampleObjects(ctx, attrs.Name, info)

	return info
}

// populateFromAttrs populates BucketInfo from storage.BucketAttrs.
func (i *Inspector) populateFromAttrs(info *BucketInfo, attrs *storage.BucketAttrs) {
	info.Location = attrs.Location
	info.StorageClass = attrs.StorageClass
	info.Labels = attrs.Labels

	if !attrs.Created.IsZero() {
		created := attrs.Created
		info.CreationDate = &created
		info.AgeInDays = int(time.Since(created).Hours() / 24)
	}

	info.VersioningEnabled = attrs.VersioningEnabled

	if attrs.Lifecycle.Rules != nil {
		info.LifecycleRules = len(attrs.Lifecycle.Rules)
		for _, rule := range attrs.Lifecycle.Rules {
			if rule.Action.Type == storage.DeleteAction {
				info.LifecycleHasDelete = true
			}
			if rule.Action.Type == storage.SetStorageClassAction {
				info.LifecycleHasArchive = true
			}
		}
	}

	info.UniformAccessEnabled = attrs.UniformBucketLevelAccess.Enabled
	switch attrs.PublicAccessPrevention {
	case storage.PublicAccessPreventionEnforced:
		info.PublicAccessPrevention = "enforced"
	case storage.PublicAccessPreventionInherited:
		info.PublicAccessPrevention = "inherited"
	default:
		info.PublicAccessPrevention = "unspecified"
	}

	if attrs.RetentionPolicy != nil {
		info.RetentionPolicySet = true
		info.RetentionPeriodSeconds = int64(attrs.RetentionPolicy.RetentionPeriod.Seconds())
	}
}

// checkPublicAccess checks if a bucket has public IAM bindings.
func (i *Inspector) checkPublicAccess(ctx context.Context, bucket string, info *BucketInfo) {
	policy, err := i.client.BucketIAMPolicy(ctx, bucket)
	if err != nil {
		return
	}

	publicInfo := &PublicAccessInfo{}
	publicMembers := []string{"allUsers", "allAuthenticatedUsers"}

	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			for _, pub := range publicMembers {
				if member == pub {
					publicInfo.IsPublic = true
					publicInfo.PublicMembers = append(publicInfo.PublicMembers, member)
					publicInfo.PublicRoles = append(publicInfo.PublicRoles, binding.Role)
				}
			}
		}
	}

	if publicInfo.IsPublic {
		info.PublicAccess = publicInfo
	}
}

// sampleObjects samples objects from a bucket to determine activity and emptiness.
func (i *Inspector) sampleObjects(ctx context.Context, bucket string, info *BucketInfo) {
	query := &storage.Query{}
	if err := query.SetAttrSelection([]string{"Name", "Size", "Updated", "StorageClass"}); err != nil {
		return
	}

	objects, err := i.client.ListObjects(ctx, bucket, query)
	if err != nil {
		return
	}

	info.IsEmpty = len(objects) == 0
	info.ObjectCount = len(objects)

	var latest *time.Time
	var totalSize int64

	for _, obj := range objects {
		totalSize += obj.Size
		updated := obj.Updated
		if latest == nil || updated.After(*latest) {
			latest = &updated
		}
		if len(info.SampleObjects) < 10 {
			info.SampleObjects = append(info.SampleObjects, ObjectSample{
				Name:         obj.Name,
				Size:         obj.Size,
				Updated:      obj.Updated,
				StorageClass: obj.StorageClass,
			})
		}
	}

	info.TotalSize = totalSize
	if latest != nil {
		info.LastUpdated = latest
		info.DaysSinceUpdate = int(time.Since(*latest).Hours() / 24)
	}
}

// inspectPrefixes inspects multiple prefixes concurrently.
func (i *Inspector) inspectPrefixes(ctx context.Context, bucket string, prefixes []string) []PrefixInfo {
	var results []PrefixInfo
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, i.concurrency)

	for _, prefix := range prefixes {
		wg.Add(1)
		go func(prefix string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			info := i.inspectPrefix(ctx, bucket, prefix)

			mu.Lock()
			results = append(results, info)
			mu.Unlock()
		}(prefix)
	}

	wg.Wait()
	return results
}

// inspectPrefix inspects a single prefix.
func (i *Inspector) inspectPrefix(ctx context.Context, bucket, prefix string) PrefixInfo {
	info := PrefixInfo{
		Prefix: prefix,
		Exists: false,
	}

	query := &storage.Query{Prefix: prefix}
	if err := query.SetAttrSelection([]string{"Name", "Updated"}); err != nil {
		return info
	}

	objects, err := i.client.ListObjects(ctx, bucket, query)
	if err != nil || len(objects) == 0 {
		return info
	}

	info.Exists = true
	info.ObjectCount = len(objects)

	var latest *time.Time
	for _, obj := range objects {
		updated := obj.Updated
		if latest == nil || updated.After(*latest) {
			latest = &updated
		}
	}

	if latest != nil {
		info.LatestUpdated = latest
		info.DaysSinceUpdated = int(time.Since(*latest).Hours() / 24)
	}

	return info
}

// extractPrefixes extracts unique prefixes from references.
func extractPrefixes(refs []scanner.Reference) []string {
	seen := make(map[string]bool)
	var prefixes []string

	for _, ref := range refs {
		if ref.Prefix != "" && !seen[ref.Prefix] {
			prefixes = append(prefixes, ref.Prefix)
			seen[ref.Prefix] = true
		}
	}

	return prefixes
}

// FormatError formats an error message with context.
func FormatError(operation, resource string, err error) string {
	if err == nil {
		return ""
	}

	errMsg := err.Error()

	if strings.Contains(errMsg, "AccessDenied") || strings.Contains(errMsg, "403") {
		return fmt.Sprintf("%s failed for %s: Access Denied - check IAM permissions", operation, resource)
	}
	if strings.Contains(errMsg, "notFound") || strings.Contains(errMsg, "404") {
		return fmt.Sprintf("%s failed for %s: Bucket does not exist", operation, resource)
	}
	if strings.Contains(errMsg, "rateLimitExceeded") || strings.Contains(errMsg, "429") {
		return fmt.Sprintf("%s failed for %s: Rate limit exceeded - consider reducing --concurrency", operation, resource)
	}

	return fmt.Sprintf("%s failed for %s: %s", operation, resource, errMsg)
}
