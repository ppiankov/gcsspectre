package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// RepoScanner scans a repository for GCS references.
type RepoScanner struct {
	repoPath string
}

// NewRepoScanner creates a new repository scanner.
func NewRepoScanner(repoPath string) *RepoScanner {
	return &RepoScanner{
		repoPath: repoPath,
	}
}

// Scan walks the repository and returns all GCS references found.
func (s *RepoScanner) Scan(_ context.Context) ([]Reference, error) {
	var allRefs []Reference
	seen := make(map[string]bool)

	err := filepath.Walk(s.repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			if strings.HasPrefix(info.Name(), ".") && info.Name() != "." {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip hidden files
		if strings.HasPrefix(info.Name(), ".") {
			return nil
		}

		// Skip files > 10MB
		if info.Size() > 10*1024*1024 {
			return nil
		}

		refs, err := s.scanFile(path)
		if err != nil {
			return nil
		}

		for _, ref := range refs {
			key := ref.Bucket + "|" + ref.Prefix
			if !seen[key] {
				allRefs = append(allRefs, ref)
				seen[key] = true
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return allRefs, nil
}

// scanFile dispatches to the appropriate scanner based on file extension.
func (s *RepoScanner) scanFile(filePath string) ([]Reference, error) {
	ext := strings.ToLower(filepath.Ext(filePath))
	basename := strings.ToLower(filepath.Base(filePath))

	switch {
	case ext == ".tf" || ext == ".hcl":
		return scanTerraform(filePath)
	case ext == ".yaml" || ext == ".yml":
		return scanYAML(filePath)
	case ext == ".json":
		return scanJSON(filePath)
	case basename == ".env" || strings.HasSuffix(basename, ".env"):
		return scanEnv(filePath)
	case ext == ".py" || ext == ".js" || ext == ".ts" || ext == ".go" || ext == ".java" || ext == ".sh":
		return scanCode(filePath)
	default:
		return nil, nil
	}
}
