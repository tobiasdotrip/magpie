# magpie

> Fast, zero-config git secret scanner. Single binary, built-in rules, confidence scoring.

![version](https://img.shields.io/badge/version-0.4.0-blue)
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

✓ Scan complete (full): 142 commits, 87 files scanned
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

magpie exits with code **1** if any **High** confidence finding is detected.

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

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed, no high-confidence findings |
| 1 | Scan completed, high-confidence findings detected |
| 2 | Technical error (git2 failure, rule loading error) |

## Allowlist

Create `.magpie-allow` at the repo root to suppress known false positives:

```
# Ignore all findings in test fixtures
aws-access-key-id:tests/**
aws-access-key-id:src/tests/**

# Ignore a specific false positive in a specific commit
generic-secret:docs/config-example.yml:a1b2c3d
```

Format: `rule_id:file_glob[:commit_sha]`

- Without commit — finding ignored everywhere
- With commit (7-char SHA) — ignored only in that commit

## Pre-commit hook (`magpie watch`)

`magpie watch` scans staged changes (equivalent to `git diff --cached`) for secrets. Same rules, scoring, and allowlist as `scan`.

```bash
magpie watch
```

Integrate with your hook framework:

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: magpie
      name: magpie secret scan
      entry: magpie watch
      language: system
```

## Custom rules

Create `.magpie.toml` at the repo root to add rules or disable built-in ones:

```toml
[config]
disable_rules = ["generic-secret", "jwt"]

[[rules]]
id = "internal-api-key"
description = "Internal API Key"
pattern = 'INTERNAL_[A-Z0-9]{32}'
keywords = ["INTERNAL_"]
```

Custom rules use the same format as built-in rules. They apply to both `scan` and `watch`.

## Findings dashboard (`magpie nest`)

Track scan history in a local SQLite database.

```bash
magpie nest              # Show dashboard (creates DB on first run)
magpie nest show         # Same as above, explicit
magpie nest reset        # Clear all stored data
```

Once the database exists, `scan` and `watch` automatically persist results. The database (`.magpie.db`) is local — add it to your `.gitignore`.

Example output:

```
Last scan: 2026-03-21T14:30:00 (incremental, 3 commits, 8 files)
  2 findings: 1 high, 1 medium, 0 low

History: 12 scans, 47 total findings
  By confidence: 15 high, 18 medium, 14 low
  Top rules: aws-access-key-id (12), generic-secret (8), jwt (5)
```

## Incremental scan

After the first scan, magpie stores the last scanned commit in `.magpie-state` and only scans new commits on subsequent runs.

```bash
magpie scan          # First run: full scan. Next runs: incremental.
magpie scan --full   # Force a full scan
```

Add `.magpie-state` to your `.gitignore` — it's local state, not meant to be shared.

## How it works

1. Opens the git repo via libgit2
2. Walks every commit, extracts diffs (added lines only)
3. Matches each line against built-in regex rules
4. If a rule has a capture group, the captured value is scored separately (avoids diluting entropy with prefixes like `password=`)
5. Scores confidence using: pattern specificity, file path, Shannon entropy
6. Outputs findings sorted by confidence

## Roadmap

- `magpie shiny` — list detectable patterns
