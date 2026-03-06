# gcsspectre

[![CI](https://github.com/ppiankov/gcsspectre/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/gcsspectre/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ppiankov/gcsspectre)](https://goreportcard.com/report/github.com/ppiankov/gcsspectre)
[![ANCC](https://img.shields.io/badge/ANCC-compliant-brightgreen)](https://ancc.dev)

**gcsspectre** — GCS bucket auditor for drift and misconfigurations. Part of [SpectreHub](https://github.com/ppiankov/spectrehub).

## What it is

- Scan mode cross-references GCS bucket refs in code against live GCP state
- Discover mode inspects all buckets in a project for lifecycle, public access, and versioning issues
- Detects missing buckets, stale prefixes, and compliance gaps
- Produces deterministic output for CI/CD gating
- Outputs text, JSON, SARIF, and SpectreHub formats

## What it is NOT

- Not a replacement for Security Command Center — not real-time
- Not a data scanner — never reads object contents, only metadata
- Not a remediation tool — reports only, never modifies buckets
- Not a cost calculator — identifies waste, does not estimate dollars

## Quick start

### Homebrew

```sh
brew tap ppiankov/tap
brew install gcsspectre
```

### From source

```sh
git clone https://github.com/ppiankov/gcsspectre.git
cd gcsspectre
make build
```

### Usage

```sh
gcsspectre discover --project my-project --format json
```

## CLI commands

| Command | Description |
|---------|-------------|
| `gcsspectre scan` | Cross-reference code bucket refs against live GCS state |
| `gcsspectre discover` | Inspect all GCS buckets in a project |
| `gcsspectre version` | Print version |

## SpectreHub integration

gcsspectre feeds GCS bucket findings into [SpectreHub](https://github.com/ppiankov/spectrehub) for unified visibility across your infrastructure.

```sh
spectrehub collect --tool gcsspectre
```

## Safety

gcsspectre operates in **read-only mode**. It inspects and reports — never modifies, deletes, or alters your buckets.

## Documentation

| Document | Contents |
|----------|----------|
| [CLI Reference](docs/cli-reference.md) | Full command reference, flags, and configuration |

## License

MIT — see [LICENSE](LICENSE).

---

Built by [Obsta Labs](https://obstalabs.dev)
