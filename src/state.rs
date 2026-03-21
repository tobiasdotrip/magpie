use git2::Oid;
use std::path::Path;

const STATE_FILE: &str = ".magpie-state";

pub fn read(repo_path: &Path) -> Option<Oid> {
    let content = std::fs::read_to_string(repo_path.join(STATE_FILE)).ok()?;
    let sha = content
        .lines()
        .find_map(|line| line.strip_prefix("last_scanned="))?
        .trim();
    Oid::from_str(sha).ok()
}

pub fn write(repo_path: &Path, oid: Oid) -> Result<(), std::io::Error> {
    std::fs::write(
        repo_path.join(STATE_FILE),
        format!("last_scanned={}\n", oid),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn read_nonexistent_returns_none() {
        let dir = TempDir::new().unwrap();
        assert!(read(dir.path()).is_none());
    }

    #[test]
    fn write_then_read_roundtrip() {
        let dir = TempDir::new().unwrap();
        let sha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let oid = git2::Oid::from_str(sha).unwrap();
        write(dir.path(), oid).unwrap();
        let result = read(dir.path());
        assert_eq!(result, Some(oid));
    }

    #[test]
    fn read_malformed_returns_none() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".magpie-state"), "garbage\n").unwrap();
        assert!(read(dir.path()).is_none());
    }

    #[test]
    fn read_empty_file_returns_none() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".magpie-state"), "").unwrap();
        assert!(read(dir.path()).is_none());
    }

    #[test]
    fn read_wrong_format_returns_none() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join(".magpie-state"), "last_scanned=ZZZZ\n").unwrap();
        assert!(read(dir.path()).is_none());
    }
}
