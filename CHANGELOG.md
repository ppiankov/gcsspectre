# Changelog

All notable changes to GCSSpectre will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-25

### Added

- Scan mode (`gcsspectre scan`): cross-references GCS bucket references in code against live GCP state to detect drift, including missing buckets, stale prefixes, and lifecycle misconfigurations
- Discover mode (`gcsspectre discover`): inspects all GCS buckets in a GCP project without requiring code references, with 7 audit signals: NO_LIFECYCLE, STALE_OBJECTS, VERSION_BLOAT, PUBLIC_BUCKET, NO_UNIFORM_ACCESS, CROSS_PROJECT, RETENTION_GAP
- Init command (`gcsspectre init`): generates `.gcsspectre.yaml` config and prints minimum IAM policy
- Repository scanners for Terraform (`google_storage_bucket`), YAML, JSON, .env files, and source code (`gs://` URL and bucket name extraction)
- Four output formats: text, JSON (spectre/v1), SARIF (v2.1.0), SpectreHub (spectre/v1)
- Baseline diff mode: `--baseline` and `--update-baseline` flags for suppressing known findings
- Config file support: `.gcsspectre.yaml` in CWD or home directory
- Structured logging via `log/slog` with `--verbose` flag
- Severity filtering via `--severity` flag
- Configurable concurrency for GCS API calls (`--concurrency`)
- Public access detection via IAM policy inspection (`--check-public`)
- Compliance bucket detection via label heuristics (compliance, audit, regulatory, retention)
- Version injection via LDFLAGS (version, commit, date)
- GoReleaser v2 config for multi-platform releases
- Docker images via multi-stage distroless build, multi-arch manifests on ghcr.io
- Homebrew formula via GoReleaser brews section
- Enhanced error messages with actionable suggestions for common GCP failures (credentials, permissions, rate limiting)

[0.1.0]: https://github.com/ppiankov/gcsspectre/releases/tag/v0.1.0
