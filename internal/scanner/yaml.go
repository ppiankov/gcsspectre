package scanner

import (
	"bufio"
	"os"
	"regexp"
)

var yamlBucketPattern = regexp.MustCompile(`(?i)(?:bucket|gcs_bucket|gcsBucket|storage_bucket):\s*['"]?([a-z0-9][a-z0-9\-_\.]{1,61}[a-z0-9])['"]?`)

// scanYAML scans YAML files for GCS bucket references.
func scanYAML(filePath string) ([]Reference, error) {
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
					Context: "yaml",
				})
			}
		}

		// Check for bucket: field
		if matches := yamlBucketPattern.FindAllStringSubmatch(line, -1); matches != nil {
			for _, match := range matches {
				refs = append(refs, Reference{
					Bucket:  match[1],
					File:    filePath,
					Line:    lineNum,
					Context: "yaml",
				})
			}
		}
	}

	if err := sc.Err(); err != nil {
		return nil, err
	}

	return refs, nil
}
