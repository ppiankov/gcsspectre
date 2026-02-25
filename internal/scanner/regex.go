package scanner

import (
	"bufio"
	"os"
	"regexp"
)

var (
	// gs:// URL pattern
	gcsURLPattern = regexp.MustCompile(`gs://([a-z0-9][a-z0-9\-_\.]{1,61}[a-z0-9])(?:/([^?\s"']+))?`)

	// HTTP(S) GCS URLs (storage.googleapis.com)
	gcsHTTPPattern = regexp.MustCompile(`https?://storage\.googleapis\.com/([a-z0-9][a-z0-9\-_\.]{1,61}[a-z0-9])(?:/([^?\s"']+))?`)

	// Bucket name pattern (for env vars and config)
	gcsBucketNamePattern = regexp.MustCompile(`(?i)(?:bucket|gcs[-_]?bucket|storage[-_]?bucket)[\s:=]+['"]?([a-z0-9][a-z0-9\-_\.]{1,61}[a-z0-9])['"]?`)

	// Context detection patterns
	writeOpPattern = regexp.MustCompile(`(?i)(put|write|upload|store|save|create)`)
	readOpPattern  = regexp.MustCompile(`(?i)(get|read|download|fetch|retrieve|load)`)
	listOpPattern  = regexp.MustCompile(`(?i)(list|ls|scan|iterate)`)
)

// scanCode scans source code files using regex patterns.
func scanCode(filePath string) ([]Reference, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var refs []Reference
	sc := bufio.NewScanner(file)
	lineNum := 0

	for sc.Scan() {
		lineNum++
		line := sc.Text()

		// Check for gs:// URLs
		if matches := gcsURLPattern.FindAllStringSubmatch(line, -1); matches != nil {
			for _, match := range matches {
				refs = append(refs, Reference{
					Bucket:  match[1],
					Prefix:  match[2],
					File:    filePath,
					Line:    lineNum,
					Context: detectContext(line),
				})
			}
		}

		// Check for HTTP(S) GCS URLs
		if matches := gcsHTTPPattern.FindAllStringSubmatch(line, -1); matches != nil {
			for _, match := range matches {
				refs = append(refs, Reference{
					Bucket:  match[1],
					Prefix:  match[2],
					File:    filePath,
					Line:    lineNum,
					Context: detectContext(line),
				})
			}
		}

		// Check for bucket name references
		if matches := gcsBucketNamePattern.FindAllStringSubmatch(line, -1); matches != nil {
			for _, match := range matches {
				isDuplicate := false
				bucket := match[1]
				for _, ref := range refs {
					if ref.Bucket == bucket && ref.Line == lineNum {
						isDuplicate = true
						break
					}
				}
				if !isDuplicate {
					refs = append(refs, Reference{
						Bucket:  bucket,
						File:    filePath,
						Line:    lineNum,
						Context: detectContext(line),
					})
				}
			}
		}
	}

	if err := sc.Err(); err != nil {
		return nil, err
	}

	return refs, nil
}

// detectContext tries to detect the type of GCS operation from the line.
func detectContext(line string) string {
	if writeOpPattern.MatchString(line) {
		return "write"
	}
	if readOpPattern.MatchString(line) {
		return "read"
	}
	if listOpPattern.MatchString(line) {
		return "list"
	}
	return "unknown"
}
