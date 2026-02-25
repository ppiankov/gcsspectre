# Contributing to GCSSpectre

Thank you for considering contributing to GCSSpectre! This document outlines the process for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/gcsspectre`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Test your changes
6. Commit and push
7. Create a Pull Request

## Development Setup

### Prerequisites

- Go 1.25 or later
- Make
- gcloud CLI (for testing)
- golangci-lint (for linting)

### Building

```bash
make build
```

### Running Tests

```bash
make test
```

### Code Formatting

```bash
make fmt
```

### Linting

```bash
make lint
```

## Project Structure

```
gcsspectre/
├── cmd/gcsspectre/          # CLI entry point
├── internal/
│   ├── commands/            # Cobra CLI commands
│   ├── scanner/             # Repository scanning
│   ├── gcs/                 # GCP Cloud Storage integration
│   ├── analyzer/            # Finding-based analysis
│   ├── report/              # Report generation
│   ├── baseline/            # Finding diff engine
│   ├── config/              # Config file loading
│   └── logging/             # Structured logging
└── docs/                    # Documentation
```

## Contribution Areas

We welcome contributions in these areas:

### 1. Scanner Enhancements

Add support for new file formats or patterns:
- CloudFormation/CDK improvements
- Pulumi support
- Language-specific SDK patterns (Python, Java, Node.js)
- Helm chart scanning

Example: Add a new scanner in `internal/scanner/`

### 2. Analysis Improvements

Enhance audit signals:
- Better stale object heuristics
- Cost estimation
- Encryption analysis
- Cross-project bucket mapping

Example: Extend `internal/analyzer/discovery.go`

### 3. GCS Integration

Improve Cloud Storage API integration:
- Pagination for large bucket listing
- Better error handling for edge cases
- Soft-delete object detection

Example: Enhance `internal/gcs/inspector.go`

### 4. Reporting

Add new report formats or improve existing ones:
- HTML reports
- CSV exports
- Integration with other tools

Example: Add new reporter in `internal/report/`

### 5. Documentation

- Improve README
- Add tutorials
- Write blog posts

### 6. Testing

- Add unit tests
- Add integration tests
- Improve test coverage

## Coding Guidelines

### Go Style

- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use `gofmt` for formatting
- Pass `golangci-lint` checks
- Write clear, concise comments
- Keep functions small and focused

### Error Handling

- Always check errors
- Wrap errors with context using `fmt.Errorf`
- Don't panic in library code

```go
// Good
if err != nil {
    return fmt.Errorf("failed to list buckets: %w", err)
}

// Bad
if err != nil {
    panic(err)
}
```

### Naming Conventions

- Use descriptive names
- Follow Go naming conventions
- Exported names should be clear to external users

### Concurrency

- Use goroutines judiciously
- Always use proper synchronization (mutex, channels)
- Respect the `--concurrency` flag
- Test concurrent code with `-race` flag

### Testing

- Write tests for new features
- Maintain or improve test coverage (target: >85%)
- Use table-driven tests where appropriate
- All tests must pass with `-race` flag

```go
func TestBucketAnalyzer(t *testing.T) {
    tests := []struct {
        name     string
        bucket   string
        expected FindingID
    }{
        {"missing", "old-bucket", FindingMissingBucket},
        {"no lifecycle", "no-rules", FindingNoLifecycle},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

## Commit Messages

Format: `type: concise imperative statement`

Types: feat, fix, docs, test, refactor, chore, perf, ci, build

Examples:
- `feat: add cross-project bucket detection`
- `fix: handle nil retention policy`
- `test: add discovery analyzer edge cases`

## Pull Request Process

1. **Update documentation**: Update README if needed
2. **Add tests**: Ensure new code is tested
3. **Run checks**: `make test && make lint`
4. **Update CHANGELOG**: Add entry for your change
5. **Create PR**: With clear description
6. **Respond to feedback**: Address review comments

## Code Review

All submissions require review. We'll review for:
- Code quality
- Test coverage
- Documentation
- Performance
- Security

## SpectreHub Compatibility

When making changes, ensure compatibility with SpectreHub:
- JSON output format must match spectre/v1 schema
- Include `tool`, `version`, `timestamp` fields
- Follow Spectre family conventions
- SpectreHub envelope must include `findings` array (never null)

## Questions?

- Open an issue for discussion
- Join discussions in existing issues
- Reach out to maintainers

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
