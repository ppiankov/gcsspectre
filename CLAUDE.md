# gcsspectre

GCP Cloud Storage auditor. Finds unused, misconfigured, and wasteful GCS buckets.

## Commands

- `make build` — Build binary to ./bin/gcsspectre
- `make test` — Run tests with -race flag
- `make lint` — Run golangci-lint
- `make fmt` — Format with gofmt/goimports
- `make clean` — Clean build artifacts

## Architecture

- Entry: cmd/gcsspectre/main.go — minimal, single Execute() call delegates to internal/commands
- commands — Cobra CLI commands (scan, discover, init, version) and shared helpers
- scanner — Repository scanning: regex, YAML, Terraform, JSON, .env parsers for gs:// references
- gcs — GCP Cloud Storage client wrapper, concurrent bucket inspector
- analyzer — Drift analysis (scan mode) and risk scoring (discover mode)
- report — Text, JSON (spectre/v1), SARIF, SpectreHub output formatters
- baseline — Finding comparison across scans
- config — .gcsspectre.yaml config file loading
- logging — slog initialization

## Conventions

- Minimal main.go — single Execute() call
- Internal packages: short single-word names (scanner, gcs, analyzer, report, commands)
- Struct-based domain models with json tags
- Interface-based GCS client mocking for tests
- Package-level compiled regexes via regexp.MustCompile in var blocks
- All GCS API calls go through context-aware methods

## Anti-Patterns

- NEVER modify or delete GCS resources — read-only auditing only
- NEVER make GCS API calls without context
- NEVER skip error handling
- NEVER compile regexes inside functions
- NEVER use init() functions unless absolutely necessary
- NEVER use global mutable state
- NEVER hardcode GCP credentials

## Verification

- Run `make test` after code changes (includes -race)
- Run `make lint` before marking complete
- Run `go vet ./...` for suspicious constructs
