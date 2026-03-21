use std::process::Command;
use tempfile::TempDir;

fn run_git(dir: &std::path::Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn create_repo_with_secret() -> TempDir {
    let dir = TempDir::new().unwrap();
    let p = dir.path();

    run_git(p, &["init"]);
    run_git(p, &["config", "user.email", "t@t.com"]);
    run_git(p, &["config", "user.name", "T"]);

    std::fs::write(p.join(".env"), "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n").unwrap();
    run_git(p, &["add", "."]);
    run_git(p, &["commit", "-m", "init"]);

    dir
}

fn create_clean_repo() -> TempDir {
    let dir = TempDir::new().unwrap();
    let p = dir.path();

    run_git(p, &["init"]);
    run_git(p, &["config", "user.email", "t@t.com"]);
    run_git(p, &["config", "user.name", "T"]);

    std::fs::write(p.join("readme.md"), "# Clean repo\n").unwrap();
    run_git(p, &["add", "."]);
    run_git(p, &["commit", "-m", "init"]);

    dir
}

#[test]
fn scan_detects_aws_key_and_exits_nonzero() {
    let dir = create_repo_with_secret();
    let bin = env!("CARGO_BIN_EXE_magpie");

    let output = Command::new(bin)
        .args(["scan", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success(),
        "Should exit non-zero for high-confidence findings"
    );
    assert!(
        stdout.contains("aws-access-key-id"),
        "Should mention rule ID, got: {stdout}"
    );
    assert!(
        stdout.contains("AKIA****"),
        "Should redact matched text, got: {stdout}"
    );
}

#[test]
fn scan_clean_repo_exits_zero() {
    let dir = create_clean_repo();
    let bin = env!("CARGO_BIN_EXE_magpie");

    let output = Command::new(bin)
        .args(["scan", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "Should exit zero for clean repo, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn scan_json_output_is_valid() {
    let dir = create_repo_with_secret();
    let bin = env!("CARGO_BIN_EXE_magpie");

    let output = Command::new(bin)
        .args(["scan", dir.path().to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("JSON output should be valid JSON");
    assert!(
        !parsed["findings"].as_array().unwrap().is_empty(),
        "Should have at least one finding"
    );
    assert!(
        stdout.contains("AKIAIOSFODNN7EXAMPLE"),
        "JSON output should contain full (non-redacted) matched text"
    );
}

#[test]
fn incremental_scan_skips_already_scanned_commits() {
    let dir = create_repo_with_secret();
    let bin = env!("CARGO_BIN_EXE_magpie");

    // First scan (full) — creates .magpie-state
    let output = Command::new(bin)
        .args(["scan", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(dir.path().join(".magpie-state").exists());

    // Add a clean commit
    std::fs::write(dir.path().join("clean.txt"), "nothing secret here\n").unwrap();
    run_git(dir.path(), &["add", "."]);
    run_git(dir.path(), &["commit", "-m", "add clean file"]);

    // Second scan (incremental) — only new commit, should be clean
    let output = Command::new(bin)
        .args(["scan", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "Incremental scan should exit 0 for clean new commits");
    assert!(stdout.contains("(incremental)"));

    // Verify .magpie-state updated to new HEAD
    let state_content = std::fs::read_to_string(dir.path().join(".magpie-state")).unwrap();
    let new_head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    let expected_sha = String::from_utf8_lossy(&new_head.stdout).trim().to_string();
    assert!(state_content.contains(&expected_sha));
}

#[test]
fn full_flag_forces_full_scan() {
    let dir = create_repo_with_secret();
    let bin = env!("CARGO_BIN_EXE_magpie");

    // First scan to create .magpie-state
    Command::new(bin)
        .args(["scan", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    // --full should still find the secret
    let output = Command::new(bin)
        .args(["scan", "--full", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!output.status.success(), "Full scan should still find secrets");
    assert!(stdout.contains("(full)"));
}

#[test]
fn allowlist_suppresses_findings() {
    let dir = create_repo_with_secret();
    let bin = env!("CARGO_BIN_EXE_magpie");

    std::fs::write(
        dir.path().join(".magpie-allow"),
        "aws-access-key-id:.env\n",
    ).unwrap();

    let output = Command::new(bin)
        .args(["scan", "--full", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success(), "Allowlisted finding should not cause exit 1");
}

#[test]
fn allowlist_with_commit_pin() {
    let dir = create_repo_with_secret();
    let bin = env!("CARGO_BIN_EXE_magpie");

    // Get commit SHA (force full 40-char, then take first 7)
    let sha_output = Command::new("git")
        .args(["log", "--format=%H", "-1"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    let full_sha = String::from_utf8_lossy(&sha_output.stdout).trim().to_string();
    let sha = &full_sha[..7];

    // Allowlist with correct commit
    std::fs::write(
        dir.path().join(".magpie-allow"),
        format!("aws-access-key-id:.env:{sha}\n"),
    ).unwrap();

    let output = Command::new(bin)
        .args(["scan", "--full", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "Correct commit pin should suppress finding");

    // Allowlist with wrong commit
    std::fs::write(
        dir.path().join(".magpie-allow"),
        "aws-access-key-id:.env:0000000\n",
    ).unwrap();

    let output = Command::new(bin)
        .args(["scan", "--full", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success(), "Wrong commit pin should not suppress finding");
}

#[test]
fn watch_detects_staged_secret() {
    let dir = TempDir::new().unwrap();
    let p = dir.path();
    let bin = env!("CARGO_BIN_EXE_magpie");

    run_git(p, &["init"]);
    run_git(p, &["config", "user.email", "t@t.com"]);
    run_git(p, &["config", "user.name", "T"]);
    std::fs::write(p.join("readme.md"), "# test\n").unwrap();
    run_git(p, &["add", "."]);
    run_git(p, &["commit", "-m", "init"]);

    std::fs::write(p.join(".env"), "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n").unwrap();
    run_git(p, &["add", ".env"]);

    let output = Command::new(bin)
        .args(["watch", p.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!output.status.success(), "Should exit 1 for staged secret");
    assert!(stdout.contains("aws-access-key-id"));
    assert!(stdout.contains("(watch)"));
}

#[test]
fn watch_nothing_staged_exits_zero() {
    let dir = TempDir::new().unwrap();
    let p = dir.path();
    let bin = env!("CARGO_BIN_EXE_magpie");

    run_git(p, &["init"]);
    run_git(p, &["config", "user.email", "t@t.com"]);
    run_git(p, &["config", "user.name", "T"]);
    std::fs::write(p.join("readme.md"), "# test\n").unwrap();
    run_git(p, &["add", "."]);
    run_git(p, &["commit", "-m", "init"]);

    let output = Command::new(bin)
        .args(["watch", p.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("nothing staged"));
}

#[test]
fn watch_respects_allowlist() {
    let dir = TempDir::new().unwrap();
    let p = dir.path();
    let bin = env!("CARGO_BIN_EXE_magpie");

    run_git(p, &["init"]);
    run_git(p, &["config", "user.email", "t@t.com"]);
    run_git(p, &["config", "user.name", "T"]);
    std::fs::write(p.join("readme.md"), "# test\n").unwrap();
    run_git(p, &["add", "."]);
    run_git(p, &["commit", "-m", "init"]);

    std::fs::write(p.join(".env"), "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n").unwrap();
    std::fs::write(p.join(".magpie-allow"), "aws-access-key-id:.env\n").unwrap();
    run_git(p, &["add", ".env"]);

    let output = Command::new(bin)
        .args(["watch", p.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "Allowlisted staged finding should not cause exit 1");
}

#[test]
fn scan_with_custom_rules() {
    let dir = TempDir::new().unwrap();
    let p = dir.path();
    let bin = env!("CARGO_BIN_EXE_magpie");

    run_git(p, &["init"]);
    run_git(p, &["config", "user.email", "t@t.com"]);
    run_git(p, &["config", "user.name", "T"]);

    std::fs::write(p.join("config.txt"), "CUSTOM_ABCDEFGHIJ\n").unwrap();
    std::fs::write(
        p.join(".magpie.toml"),
        r#"
[[rules]]
id = "custom-key"
description = "Custom Key"
pattern = 'CUSTOM_[A-Z]{10}'
"#,
    ).unwrap();
    run_git(p, &["add", "."]);
    run_git(p, &["commit", "-m", "init"]);

    let output = Command::new(bin)
        .args(["scan", "--full", p.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let findings = parsed["findings"].as_array().unwrap();
    assert!(findings.iter().any(|f| f["rule_id"] == "custom-key"));
}

#[test]
fn scan_with_disable_rules() {
    let dir = create_repo_with_secret();
    let p = dir.path();
    let bin = env!("CARGO_BIN_EXE_magpie");

    std::fs::write(
        p.join(".magpie.toml"),
        r#"
[config]
disable_rules = ["aws-access-key-id"]
"#,
    ).unwrap();

    let output = Command::new(bin)
        .args(["scan", "--full", p.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "Disabled rule should not produce findings");
}

#[test]
fn nest_creates_db_and_shows_empty_dashboard() {
    let dir = create_clean_repo();
    let bin = env!("CARGO_BIN_EXE_magpie");

    let output = Command::new(bin)
        .args(["nest", "show", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("No scans recorded yet"));
    assert!(dir.path().join(".magpie.db").exists());
}

#[test]
fn scan_persists_to_nest_db() {
    let dir = create_repo_with_secret();
    let bin = env!("CARGO_BIN_EXE_magpie");

    // Create DB first
    Command::new(bin)
        .args(["nest", "show", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    // Run scan
    Command::new(bin)
        .args(["scan", "--full", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    // Check dashboard
    let output = Command::new(bin)
        .args(["nest", "show", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Last scan:"));
    assert!(stdout.contains("aws-access-key-id"));
}

#[test]
fn nest_reset_clears_data() {
    let dir = create_repo_with_secret();
    let bin = env!("CARGO_BIN_EXE_magpie");

    // Create DB and run scan
    Command::new(bin)
        .args(["nest", "show", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    Command::new(bin)
        .args(["scan", "--full", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    // Reset
    let output = Command::new(bin)
        .args(["nest", "reset", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());

    // Dashboard should be empty
    let output = Command::new(bin)
        .args(["nest", "show", dir.path().to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("No scans recorded yet"));
}

#[test]
fn scan_without_nest_db_does_not_create_it() {
    let dir = create_clean_repo();
    let bin = env!("CARGO_BIN_EXE_magpie");

    Command::new(bin)
        .args(["scan", "--full", dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!dir.path().join(".magpie.db").exists());
}
