use sha2::{Digest, Sha256};
use std::io;

use crate::fsverity;

/// Verify a file's integrity against an expected SHA-256 hex digest.
///
/// First attempts fs-verity kernel measurement (zero-copy, TOCTOU-safe).
/// Falls back to userspace SHA-256 if fs-verity is unavailable.
pub fn verify_file(path: &str, expected_hex: &str) -> Result<(), VerifyError> {
    let actual_hex = match fsverity::measure(path) {
        Ok(digest) => digest,
        Err(_) => compute_sha256(path)?,
    };

    if actual_hex != expected_hex {
        return Err(VerifyError::DigestMismatch {
            path: path.to_string(),
            expected: expected_hex.to_string(),
            actual: actual_hex,
        });
    }

    Ok(())
}

/// Compute SHA-256 digest of a file, returning lowercase hex.
pub fn compute_sha256(path: &str) -> Result<String, VerifyError> {
    let data = std::fs::read(path)?;
    let hash = Sha256::digest(&data);
    Ok(hex::encode(hash))
}

#[derive(Debug)]
pub enum VerifyError {
    Io(io::Error),
    DigestMismatch {
        path: String,
        expected: String,
        actual: String,
    },
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::DigestMismatch {
                path,
                expected,
                actual,
            } => write!(
                f,
                "digest mismatch for {path}: expected {expected}, got {actual}"
            ),
        }
    }
}

impl std::error::Error for VerifyError {}

impl From<io::Error> for VerifyError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("testfile");
        std::fs::write(&path, b"hello world\n").unwrap();

        let digest = compute_sha256(path.to_str().unwrap()).unwrap();
        // sha256("hello world\n")
        assert_eq!(
            digest,
            "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"
        );
    }

    #[test]
    fn test_verify_file_match() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("testfile");
        std::fs::write(&path, b"hello world\n").unwrap();

        let result = verify_file(
            path.to_str().unwrap(),
            "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_file_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("testfile");
        std::fs::write(&path, b"hello world\n").unwrap();

        let result = verify_file(path.to_str().unwrap(), "0000000000000000");
        assert!(matches!(result, Err(VerifyError::DigestMismatch { .. })));
    }

    #[test]
    fn test_verify_file_not_found() {
        let result = verify_file("/nonexistent/path", "abcd");
        assert!(matches!(result, Err(VerifyError::Io(_))));
    }
}
