---
name: gcsspectre
description: GCP Cloud Storage auditor — finds unused, misconfigured, and wasteful GCS buckets
user-invocable: false
metadata: {"requires":{"bins":["gcsspectre"]}}
---

# gcsspectre -- GCP Cloud Storage Auditor

Scans GCS buckets for drift, waste, misconfiguration, and security risks. Correlates code references against live GCP state.

## Install

```bash
go install github.com/ppiankov/gcsspectre/cmd/gcsspectre@latest
```

## Commands

### gcsspectre scan

Scan repository and GCS for bucket drift.

**Flags:**
- `-r, --repo` -- repository path (default: .)
- `-p, --project` -- GCP project ID (required)
- `--stale-days` -- stale prefix threshold in days (default: 90)
- `--check-public` -- check for public bucket access (default: true)
- `--severity` -- minimum severity to report: critical, high, medium, low
- `-f, --format` -- output format: text, json, sarif, spectrehub (default: text)
- `-o, --output` -- output file path (default: stdout)
- `--concurrency` -- max concurrent GCS API calls (default: 10)
- `--baseline` -- previous JSON report for diff comparison
- `--timeout` -- scan timeout (e.g. 5m)

### gcsspectre discover

Discover and analyze all GCS buckets in a project.

**Flags:**
- `-p, --project` -- GCP project ID (required)
- `--stale-days` -- stale object threshold in days (default: 90)
- `--version-days` -- noncurrent version threshold in days (default: 30)
- `--check-public` -- check for public bucket access (default: true)
- `--severity` -- minimum severity to report: critical, high, medium, low
- `--exclude` -- buckets to exclude (comma-separated)
- `-f, --format` -- output format: text, json, sarif, spectrehub (default: text)
- `-o, --output` -- output file path (default: stdout)
- `--concurrency` -- max concurrent GCS API calls (default: 10)
- `--baseline` -- previous JSON report for diff comparison
- `--timeout` -- scan timeout (e.g. 5m)

**JSON output:**
```json
{
  "tool": "gcsspectre",
  "version": "0.1.0",
  "timestamp": "2026-02-25T12:00:00Z",
  "config": {
    "project": "my-project",
    "stale_days": 90,
    "check_public": true
  },
  "result": {
    "findings": [
      {
        "id": "PUBLIC_BUCKET",
        "severity": "critical",
        "resource_type": "gcs_bucket",
        "resource_id": "my-public-bucket",
        "message": "Bucket \"my-public-bucket\" is publicly accessible via allUsers/allAuthenticatedUsers",
        "recommendation": "Remove public IAM bindings unless intentionally public-facing",
        "metadata": {
          "public_members": ["allUsers"],
          "public_roles": ["roles/storage.objectViewer"]
        }
      }
    ],
    "summary": {
      "total_buckets": 12,
      "total_findings": 3,
      "by_severity": {"critical": 1, "high": 1, "medium": 1},
      "by_finding_id": {"PUBLIC_BUCKET": 1, "STALE_OBJECTS": 1, "NO_LIFECYCLE": 1}
    }
  }
}
```

**Exit codes:**
- 0: scan completed (findings may or may not be present)
- 1: error (credentials, permissions, network)

### gcsspectre init

Generate `.gcsspectre.yaml` config file and print required IAM permissions.

### gcsspectre version

Print version, commit hash, and build date.

## What this does NOT do

- Does not modify or delete GCS resources -- read-only auditing only
- Does not store cloud credentials -- uses standard GCP SDK credential chain
- Does not require admin access -- works with read-only storage permissions
- Does not use ML or probabilistic analysis -- deterministic checks
- Does not estimate costs -- findings are waste/risk signals, not dollar amounts

## Parsing examples

```bash
# List all critical findings
gcsspectre discover --project my-project --format json | jq '[.result.findings[] | select(.severity == "critical")]'

# Count findings by type
gcsspectre discover --project my-project --format json | jq '.result.summary.by_finding_id'

# Public buckets
gcsspectre discover --project my-project --format json | jq '[.result.findings[] | select(.id == "PUBLIC_BUCKET")] | .[] | .resource_id'

# Stale Standard-class buckets
gcsspectre discover --project my-project --format json | jq '[.result.findings[] | select(.id == "STALE_OBJECTS")] | .[] | {bucket: .resource_id, days: .metadata.days_since_update}'

# Compliance buckets without retention
gcsspectre discover --project my-project --format json | jq '[.result.findings[] | select(.id == "RETENTION_GAP")] | .[] | .resource_id'
```
