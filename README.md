# magpie

> Fast, zero-config git secret scanner. Single binary, built-in rules, confidence scoring.

![version](https://img.shields.io/badge/version-0.1.0-blue)
![rust](https://img.shields.io/badge/rust-2021-orange)

magpie scans git history for exposed secrets — API keys, tokens, private keys, high-entropy strings. It walks diffs commit-by-commit, so you see exactly when a secret was introduced.

## Install

Build from source:

```bash
git clone https://github.com/tobiasdotrip/magpie.git
cd magpie
cargo build --release
# Binary at target/release/magpie
```

## Quick start

```bash
# Scan current repo
magpie scan

# Scan a specific repo
magpie scan /path/to/repo

# JSON output
magpie scan --format json
```

## Output

```
[HIGH] aws-access-key-id — AWS Access Key ID
  File: config.env:3 (commit abc1234)
  Match: AKIA****

[MEDIUM] generic-secret — Generic Secret assignment
  File: deploy.yml:12 (commit def5678)
  Match: secr****

✓ Scan complete: 142 commits, 87 files scanned
  2 findings: 1 high, 1 medium, 0 low
```

Secrets are redacted in terminal output. JSON output (`--format json`) includes the full matched text for machine consumption.

## Built-in rules

| Rule | Description | Example |
|------|-------------|---------|
| `aws-access-key-id` | AWS Access Key ID | `AKIA...` |
| `aws-secret-access-key` | AWS Secret Access Key | `aws_secret_access_key = ...` |
| `github-token` | GitHub Personal Access Token | `ghp_...`, `github_pat_...` |
| `github-oauth` | GitHub OAuth Token | `gho_...` |
| `generic-api-key` | Generic API Key assignment | `api_key = ...` |
| `private-key` | Private Key (PEM) | `-----BEGIN PRIVATE KEY-----` |
| `jwt` | JSON Web Token | `eyJ...` |
| `generic-secret` | Generic secret/password/token | `password = ...` |

## Confidence scoring

Each finding gets a confidence level based on contextual signals:

**High** — Specific pattern (AWS key prefix `AKIA`, GitHub token prefix `ghp_`) or secret found in a sensitive file (`.env`, `.pem`, `.key`).

**Medium** — Generic pattern with high Shannon entropy (> 4.0). Likely a real secret, but could be a hash or random identifier.

**Low** — Generic pattern with low entropy, or any finding in test/example/fixture files.

## CI usage

magpie exits with code **1** if any **High** confidence finding is detected. Zero otherwise.

```yaml
# GitHub Actions
- name: Scan for secrets
  run: magpie scan

# GitLab CI
secret-scan:
  script: magpie scan
```

JSON output for programmatic consumption:

```bash
magpie scan --format json | jq '.findings[] | select(.confidence == "High")'
```

## How it works

1. Opens the git repo via libgit2
2. Walks every commit, extracts diffs (added lines only)
3. Matches each line against built-in regex rules
4. If a rule has a capture group, the captured value is scored separately (avoids diluting entropy with prefixes like `password=`)
5. Scores confidence using: pattern specificity, file path, Shannon entropy
6. Outputs findings sorted by confidence

## Roadmap

- **v0.2.0** — Allowlist (`.magpie-allow`) + incremental scan (only new commits)
- **v0.3.0** — `magpie watch` (pre-commit hook) + custom rules (`.magpie.toml`)
- **v0.4.0** — `magpie nest` (local findings dashboard via SQLite)
