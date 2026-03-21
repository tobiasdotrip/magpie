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
