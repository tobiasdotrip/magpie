<p align="center">
  <img src="assets/logo.jpg" alt="magpie" width="500">
  <h1 align="center">magpie</h1>
  <p align="center"><em>Fast, zero-config git secret scanner. Single binary, built-in rules, confidence scoring.</em></p>
  <p align="center">
    <img src="https://img.shields.io/github/v/release/tobiasdotrip/magpie" alt="latest release">
    <img src="https://img.shields.io/badge/rust-2021-orange" alt="rust">
  </p>
</p>

magpie scans git history for exposed secrets — API keys, tokens, private keys, high-entropy strings. It walks diffs commit-by-commit, so you see exactly when a secret was introduced.

## Install

Build from source:

```bash
git clone https://github.com/tobiasdotrip/magpie.git
cd magpie
cargo install --locked --path .
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

Secrets are redacted by default in both terminal and JSON output. To include raw values in JSON, explicitly pass `--show-secrets`; avoid doing so in shared terminals or CI logs.

If magpie finds a real credential, revoke or rotate it first. Cleaning the Git history afterwards does not invalidate a secret that may already have been copied.

## Built-in rules

| Rule                    | Description                   | Example                       |
| ----------------------- | ----------------------------- | ----------------------------- |
| `aws-access-key-id`     | AWS Access Key ID             | `AKIA...`                     |
| `aws-secret-access-key` | AWS Secret Access Key         | `aws_secret_access_key = ...` |
| `github-token`          | GitHub Personal Access Token  | `ghp_...`, `github_pat_...`   |
| `github-oauth`          | GitHub OAuth Token            | `gho_...`                     |
| `generic-api-key`       | Generic API Key assignment    | `api_key = ...`               |
| `private-key`           | Private Key (PEM)             | `-----BEGIN PRIVATE KEY-----` |
| `jwt`                   | JSON Web Token                | `eyJ...`                      |
| `generic-secret`        | Generic secret/password/token | `password = ...`              |

## Confidence scoring

Each finding gets a confidence level based on contextual signals:

**High** — Specific pattern (AWS key prefix `AKIA`, GitHub token prefix `ghp_`) or secret found in a sensitive file (`.env`, `.pem`, `.key`).

**Medium** — Generic pattern with high Shannon entropy (> 4.0). Likely a real secret, but could be a hash or random identifier.

**Low** — Generic pattern with low entropy, or a generic finding in test/example/fixture files. Specific credential formats remain high confidence in every path.

## CI usage

magpie exits with code **1** if any **High** confidence finding is detected.

```yaml
name: Secret scan
on: [push, pull_request]

jobs:
  magpie:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: dtolnay/rust-toolchain@stable
      - name: Install magpie
        run: cargo install --locked --git https://github.com/tobiasdotrip/magpie.git
      - name: Scan full history
        run: magpie scan --full
```

JSON output for programmatic consumption:

```bash
magpie scan --format json | jq '.findings[] | select(.confidence == "High")'

# Reveal raw matches only when a trusted downstream consumer requires them
magpie scan --format json --show-secrets
```

## Exit codes

| Code | Meaning                                            |
| ---- | -------------------------------------------------- |
| 0    | Scan completed, no high-confidence findings        |
| 1    | Scan completed, high-confidence findings detected  |
| 2    | Technical error (git2 failure, rule loading error) |

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

After the first successful scan, magpie stores the last scanned commit and active rule signature in `.magpie-state`, then only scans new commits while those rules remain unchanged. A scan with high-confidence findings does not advance the state, so unresolved secrets remain visible.

```bash
magpie scan          # First run: full scan. Next runs: incremental.
magpie scan --full   # Force a full scan
```

Add `.magpie-state` to your `.gitignore` — it's local state, not meant to be shared.

## List rules (`magpie shiny`)

See what patterns magpie detects — the magpie is attracted to shiny things.

```bash
magpie shiny             # List active rules
magpie shiny --format json
```

Custom rules from `.magpie.toml` are tagged `[custom]`. Disabled rules are excluded.

## How it works

1. Opens the git repo via libgit2
2. Walks every commit, extracts diffs (added lines only)
3. Matches each line against built-in regex rules
4. If a rule has a capture group, the captured value is scored separately (avoids diluting entropy with prefixes like `password=`)
5. Scores confidence using: pattern specificity, file path, Shannon entropy
6. Outputs findings with confidence and commit context

## Limitations

- Pattern and entropy matching can produce false positives and false negatives; magpie complements review and credential scanning controls rather than replacing them.
- History scans inspect UTF-8 added lines from commits reachable from the current `HEAD`. Binary data, deleted-only content, unreachable commits, other refs, and submodules are not exhaustively scanned.
- Merge commits are compared with their first parent, and incremental scans rely on the local `.magpie-state`; use `scan --full` in CI or after history changes.

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE-APACHE) or the [MIT license](LICENSE-MIT), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
