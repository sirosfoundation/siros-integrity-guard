use serde::Deserialize;
use std::io;

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub files: Vec<FileEntry>,
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub digest: String,
}

impl Manifest {
    pub fn load(path: &str) -> Result<Self, ManifestError> {
        let data = std::fs::read_to_string(path)?;
        let manifest: Manifest = serde_json::from_str(&data)?;

        if manifest.version != 1 {
            return Err(ManifestError::UnsupportedVersion(manifest.version));
        }

        if manifest.files.is_empty() {
            return Err(ManifestError::EmptyFileList);
        }

        Ok(manifest)
    }

    /// Return the manifest data that was signed (everything except the signature field).
    /// This is the canonical JSON of {"version":..., "files":[...]}.
    pub fn signed_payload(raw: &[u8]) -> Result<Vec<u8>, ManifestError> {
        let v: serde_json::Value = serde_json::from_slice(raw)?;
        let obj = v.as_object().ok_or(ManifestError::InvalidFormat)?;

        let mut payload = serde_json::Map::new();
        for (k, v) in obj {
            if k != "signature" {
                payload.insert(k.clone(), v.clone());
            }
        }

        let canonical = serde_json::to_vec(&payload)?;
        Ok(canonical)
    }
}

#[derive(Debug)]
pub enum ManifestError {
    Io(io::Error),
    Json(serde_json::Error),
    UnsupportedVersion(u32),
    EmptyFileList,
    InvalidFormat,
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Json(e) => write!(f, "JSON parse error: {e}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported manifest version: {v}"),
            Self::EmptyFileList => write!(f, "manifest contains no files"),
            Self::InvalidFormat => write!(f, "invalid manifest format"),
        }
    }
}

impl std::error::Error for ManifestError {}

impl From<io::Error> for ManifestError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for ManifestError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

/// Serde helper for hex-encoded byte arrays.
mod hex_bytes {
    use serde::Deserializer;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = serde::Deserialize::deserialize(deserializer)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_manifest() {
        let json = r#"{
            "version": 1,
            "files": [
                {"path": "/app/server", "digest": "abcd1234"},
                {"path": "/app/config.toml", "digest": "ef567890"}
            ],
            "signature": "deadbeef"
        }"#;

        let manifest: Manifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.version, 1);
        assert_eq!(manifest.files.len(), 2);
        assert_eq!(manifest.files[0].path, "/app/server");
        assert_eq!(manifest.files[0].digest, "abcd1234");
        assert_eq!(manifest.signature, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_signed_payload_excludes_signature() {
        let json = r#"{"version":1,"files":[{"path":"/app/bin","digest":"aa"}],"signature":"ff"}"#;
        let payload = Manifest::signed_payload(json.as_bytes()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert!(v.get("signature").is_none());
        assert!(v.get("version").is_some());
        assert!(v.get("files").is_some());
    }

    #[test]
    fn test_reject_unsupported_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        std::fs::write(
            &path,
            r#"{"version":99,"files":[{"path":"/x","digest":"aa"}],"signature":"ff"}"#,
        )
        .unwrap();

        let result = Manifest::load(path.to_str().unwrap());
        assert!(matches!(result, Err(ManifestError::UnsupportedVersion(99))));
    }

    #[test]
    fn test_reject_empty_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        std::fs::write(&path, r#"{"version":1,"files":[],"signature":"ff"}"#).unwrap();

        let result = Manifest::load(path.to_str().unwrap());
        assert!(matches!(result, Err(ManifestError::EmptyFileList)));
    }
}
