package scanner

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

var (
	// Terraform GCS resource patterns
	tfGCSBucketResource = regexp.MustCompile(`resource\s+"google_storage_bucket"\s+"[^"]+"\s+\{`)
	tfGCSObjectResource = regexp.MustCompile(`resource\s+"google_storage_bucket_object"\s+"[^"]+"\s+\{`)
	tfBucketNameAttr    = regexp.MustCompile(`name\s+=\s+"([^"]+)"`)
	tfBucketAttr        = regexp.MustCompile(`bucket\s+=\s+"([^"]+)"`)
)

// scanTerraform scans Terraform files for GCS bucket references.
func scanTerraform(filePath string) ([]Reference, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var refs []Reference
	sc := bufio.NewScanner(file)
	lineNum := 0

	var inBucketResource bool
	var inObjectResource bool
	var currentBucket string
	var currentResourceLine int

	for sc.Scan() {
		lineNum++
		line := sc.Text()
		trimmed := strings.TrimSpace(line)

		// Check if entering google_storage_bucket resource
		if tfGCSBucketResource.MatchString(trimmed) {
			inBucketResource = true
			inObjectResource = false
			currentResourceLine = lineNum
			currentBucket = ""
			continue
		}

		// Check if entering google_storage_bucket_object resource
		if tfGCSObjectResource.MatchString(trimmed) {
			inObjectResource = true
			inBucketResource = false
			currentResourceLine = lineNum
			currentBucket = ""
			continue
		}

		// Exit resource block
		if (inBucketResource || inObjectResource) && trimmed == "}" {
			if currentBucket != "" {
				refs = append(refs, Reference{
					Bucket:  currentBucket,
					File:    filePath,
					Line:    currentResourceLine,
					Context: "terraform",
				})
			}
			inBucketResource = false
			inObjectResource = false
			currentBucket = ""
			continue
		}

		// Extract bucket name from google_storage_bucket (uses name =)
		if inBucketResource {
			if match := tfBucketNameAttr.FindStringSubmatch(trimmed); match != nil {
				currentBucket = match[1]
			}
		}

		// Extract bucket reference from google_storage_bucket_object (uses bucket =)
		if inObjectResource {
			if match := tfBucketAttr.FindStringSubmatch(trimmed); match != nil {
				currentBucket = match[1]
			}
		}

		// Also check for gs:// URLs in any line
		if matches := gcsURLPattern.FindAllStringSubmatch(line, -1); matches != nil {
			for _, match := range matches {
				refs = append(refs, Reference{
					Bucket:  match[1],
					Prefix:  match[2],
					File:    filePath,
					Line:    lineNum,
					Context: "terraform",
				})
			}
		}
	}

	if err := sc.Err(); err != nil {
		return nil, err
	}

	return refs, nil
}
