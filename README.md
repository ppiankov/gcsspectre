# GCSSpectre

[![CI](https://github.com/ppiankov/gcsspectre/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/gcsspectre/actions/workflows/ci.yml)
[![Go 1.25+](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

GCP Cloud Storage auditor. Finds unused, misconfigured, and wasteful GCS buckets.

Part of the [Spectre family](https://github.com/ppiankov) of infrastructure cleanup tools.

## What it is

GCSSpectre correlates GCS bucket references found in your codebase against live GCP state. It operates in two modes:

- **Scan mode** cross-references code against GCS to detect drift: missing buckets, stale prefixes, and lifecycle gaps.
- **Discover mode** inspects all GCS buckets in a GCP project to find lifecycle misconfigurations, public access, version bloat, stale objects, and compliance gaps -- without requiring any code.

Both modes produce deterministic, machine-readable output suitable for CI/CD gating.

## What it is NOT

- Not a replacement for Security Command Center or Cloud Asset Inventory. GCSSpectre does not monitor in real time.
- Not a data scanner. It never reads object contents, only metadata.
- Not a remediation tool. It reports problems and lets you decide what to do.
- Not a cost calculator. It identifies waste but does not estimate dollar amounts.
- Not a security scanner. Public access and IAM checks are surface-level flags, not a compliance audit.

## Philosophy

*Principiis obsta* -- resist the beginnings.

Infrastructure drift is not a detection problem. It is a structural problem. By the time a missing bucket breaks a deployment, the damage is done. GCSSpectre is designed to surface these conditions early -- in CI, in code review, in scheduled audits -- so they can be addressed before they matter.

The tool presents evidence and lets humans decide. It does not auto-remediate, does not guess intent, and does not assign confidence scores where deterministic checks suffice.

## Installation

```bash
# Homebrew
brew install ppiankov/tap/gcsspectre

# Docker
docker pull ghcr.io/ppiankov/gcsspectre:latest

# From source
git clone https://github.com/ppiankov/gcsspectre.git
cd gcsspectre && make build
```

## Quick start

```bash
# Initialize config and show required IAM permissions
gcsspectre init --project my-project

# Scan mode: correlate code references against GCS
gcsspectre scan --repo . --project my-project

# Discover mode: audit all buckets in a GCP project
gcsspectre discover --project my-project

# SARIF output for GitHub Security tab
gcsspectre scan --repo . --project my-project --format sarif --output results.sarif

# Baseline: suppress known findings on repeat runs
gcsspectre scan --repo . --project my-project --format json --output baseline.json --update-baseline
gcsspectre scan --repo . --project my-project --baseline baseline.json
```

Requires valid GCP credentials (`gcloud auth application-default login` or `GOOGLE_APPLICATION_CREDENTIALS`).

## Usage

### Scan mode

Cross-references GCS references in code with live GCP state.

```bash
# Basic scan
gcsspectre scan --repo ./my-repo --project my-project

# JSON output for CI/CD
gcsspectre scan --repo . --project my-project --format json --output report.json

# Custom staleness threshold
gcsspectre scan --repo . --project my-project --stale-days 60

# Disable public access checking
gcsspectre scan --repo . --project my-project --check-public=false

# Include file-level reference details
gcsspectre scan --repo . --project my-project --include-references --format json
```

**Scan flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--repo, -r` | `.` | Repository path to scan |
| `--project, -p` | | GCP project ID (required) |
| `--stale-days` | `90` | Stale prefix threshold |
| `--check-public` | `true` | Check for public bucket access via IAM |
| `--severity` | | Minimum severity: critical, high, medium, low |
| `--concurrency` | `10` | Max concurrent GCS API calls |
| `--format, -f` | `text` | Output format: text, json, sarif, spectrehub |
| `--output, -o` | stdout | Output file |
| `--include-references` | `false` | Include reference details in output |
| `--baseline` | | Previous JSON report for diff comparison |
| `--update-baseline` | `false` | Write results as new baseline |
| `--timeout` | `0` | Operation timeout (e.g. 5m) |
| `--no-progress` | `false` | Disable TTY progress indicators |

### Discover mode

Audits all GCS buckets in a GCP project without requiring code references.

```bash
# Discover all buckets
gcsspectre discover --project my-project

# Exclude specific buckets
gcsspectre discover --project my-project --exclude public-website,staging-logs

# Custom thresholds
gcsspectre discover --project my-project --stale-days 180 --version-days 60

# CI/CD gating with minimum severity
gcsspectre discover --project my-project --severity high --format json
```

**Discover flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--project, -p` | | GCP project ID (required) |
| `--stale-days` | `90` | Stale object threshold |
| `--version-days` | `30` | Noncurrent version cleanup threshold |
| `--check-public` | `true` | Check for public bucket access via IAM |
| `--severity` | | Minimum severity: critical, high, medium, low |
| `--exclude` | | Buckets to exclude (comma-separated) |
| `--concurrency` | `10` | Max concurrent GCS API calls |
| `--format, -f` | `text` | Output format: text, json, sarif, spectrehub |
| `--output, -o` | stdout | Output file |
| `--baseline` | | Previous JSON report for diff comparison |
| `--update-baseline` | `false` | Write results as new baseline |
| `--timeout` | `0` | Operation timeout (e.g. 5m) |
| `--no-progress` | `false` | Disable TTY progress indicators |

### Finding classifications

| Finding | Mode | Severity | Meaning |
|---------|------|----------|---------|
| `MISSING_BUCKET` | scan | high | Referenced in code, does not exist in GCS |
| `MISSING_PREFIX` | scan | medium | Code references a prefix with no objects |
| `STALE_PREFIX` | scan | low | Prefix exists but unmodified for N days |
| `NO_LIFECYCLE` | discover | medium | No lifecycle rules on bucket |
| `STALE_OBJECTS` | discover | high | No update in N days, still Standard class |
| `VERSION_BLOAT` | discover | medium | Versioning on, no lifecycle delete rule |
| `PUBLIC_BUCKET` | both | critical | allUsers/allAuthenticatedUsers in IAM |
| `NO_UNIFORM_ACCESS` | discover | medium | Legacy ACL mode (uniform access disabled) |
| `CROSS_PROJECT` | discover | low | Bucket belongs to a different project |
| `RETENTION_GAP` | discover | high | Compliance bucket missing retention policy |

### Config file

GCSSpectre looks for `.gcsspectre.yaml` in the current directory and home directory:

```yaml
project: "my-project"
stale_days: 90
version_days: 30
format: text
check_public: true
exclude_buckets:
  - public-website-bucket
timeout: 5m
```

Generate one with `gcsspectre init --project my-project`.

## Architecture

```
gcsspectre/
├── cmd/gcsspectre/main.go        # Entry point, delegates to commands
├── internal/
│   ├── commands/                  # Cobra CLI: scan, discover, init, version
│   │   ├── root.go
│   │   ├── scan.go
│   │   ├── discover.go
│   │   ├── init.go
│   │   ├── helpers.go
│   │   └── version.go
│   ├── scanner/                   # Repository scanning (regex, YAML, Terraform, JSON, .env)
│   │   ├── scanner.go
│   │   ├── regex.go
│   │   ├── yaml.go
│   │   ├── terraform.go
│   │   ├── json.go
│   │   ├── env.go
│   │   └── types.go
│   ├── gcs/                       # GCP Cloud Storage integration
│   │   ├── client.go              # StorageAPI interface + real client
│   │   ├── inspector.go           # Concurrent bucket inspector
│   │   └── types.go
│   ├── analyzer/                  # Finding-based analysis
│   │   ├── analyzer.go            # Scan mode: code-vs-GCS drift
│   │   ├── discovery.go           # Discover mode: 7 audit signals
│   │   └── types.go
│   ├── report/                    # Output generation
│   │   ├── text.go
│   │   ├── json.go
│   │   ├── sarif.go
│   │   ├── spectrehub.go
│   │   └── types.go
│   ├── baseline/                  # Finding diff engine
│   │   └── baseline.go
│   ├── config/                    # .gcsspectre.yaml loader
│   │   └── config.go
│   └── logging/                   # slog initialization
│       └── logging.go
├── Makefile
├── go.mod
└── go.sum
```

Key design decisions:

- `cmd/gcsspectre/main.go` is minimal -- a single `Execute()` call.
- All logic lives in `internal/` to prevent external import.
- GCS API calls use a bounded worker pool (`--concurrency`) with semaphore-based concurrency control.
- Scanner dispatches files to format-specific parsers based on extension.
- Finding-based model: flat `Finding` struct with `ID`, `Severity`, `ResourceType`, `ResourceID`, `Message`, `Recommendation`, `Metadata`.
- Analysis is deterministic: same inputs always produce the same findings.
- GCS buckets are global -- no region iteration needed (unlike S3).

## Known limitations

- **No object-level scanning.** GCSSpectre inspects bucket and prefix metadata. It does not list or read individual objects beyond what is needed for prefix existence and staleness checks.
- **Staleness proxy.** GCS has no `LastAccessTime`. Uses `ObjectAttrs.Updated` as a proxy, which reflects when an object was last written or metadata-updated, not last read.
- **Regex-based code scanning.** The scanner uses pattern matching, not AST parsing. It will miss dynamically constructed bucket names and may produce false positives on commented-out code.
- **No cost estimation.** The tool identifies unused resources but does not calculate storage costs.
- **IAM permissions required.** Needs `storage.buckets.list`, `storage.buckets.get`, `storage.buckets.getIamPolicy`, `storage.objects.list`. Missing permissions produce errors, not silent failures.
- **No real-time monitoring.** GCSSpectre is a point-in-time scanner, not a daemon. Run it in CI or on a schedule.
- **Single project.** Cross-project scanning is not supported. Run separately per project.

## Roadmap

- Cost estimation for unused and stale resources
- Deep prefix scanning with pagination
- Cross-project scanning
- Object versioning age analysis
- Naming convention enforcement
- Historical trend tracking
- SpectreHub integration for cross-tool correlation

## License

MIT License -- see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and pull requests welcome.

Part of the Spectre family:
[S3Spectre](https://github.com/ppiankov/s3spectre) |
[IAMSpectre](https://github.com/ppiankov/iamspectre) |
[VaultSpectre](https://github.com/ppiankov/vaultspectre) |
[ClickSpectre](https://github.com/ppiankov/clickspectre) |
[KafkaSpectre](https://github.com/ppiankov/kafkaspectre)
