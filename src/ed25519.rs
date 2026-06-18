use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::manifest::Manifest;

/// Verify the manifest Ed25519 signature using the given public key.
///
/// The public key is a 32-byte Ed25519 key loaded from a file (raw or SSH format).
/// The signature covers the canonical JSON payload (manifest without the signature field).
pub fn verify_manifest_signature(
    pubkey_bytes: &[u8; 32],
    raw_manifest: &[u8],
    signature_bytes: &[u8],
) -> Result<(), Ed25519Error> {
    let verifying_key =
        VerifyingKey::from_bytes(pubkey_bytes).map_err(|_| Ed25519Error::InvalidPublicKey)?;

    let signature = Signature::from_slice(signature_bytes)
        .map_err(|_| Ed25519Error::InvalidSignature)?;

    let payload =
        Manifest::signed_payload(raw_manifest).map_err(|e| Ed25519Error::Manifest(e.to_string()))?;

    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| Ed25519Error::VerificationFailed)?;

    Ok(())
}

/// Load an Ed25519 public key from a file.
///
/// Supports:
/// - Raw 32-byte binary
/// - 64-character hex string
/// - SSH public key format (ssh-ed25519 ...)
pub fn load_public_key(path: &str) -> Result<[u8; 32], Ed25519Error> {
    let data = std::fs::read(path).map_err(Ed25519Error::Io)?;

    // Try raw 32-byte key
    if data.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&data);
        return Ok(key);
    }

    // Try hex-encoded (64 chars + optional newline)
    let text = String::from_utf8_lossy(&data);
    let trimmed = text.trim();
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes = hex::decode(trimmed).map_err(|_| Ed25519Error::InvalidPublicKey)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }

    // Try SSH public key format: ssh-ed25519 <base64> <comment>
    if trimmed.starts_with("ssh-ed25519 ") {
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 2 {
            use base64ct::{Base64, Encoding};
            let blob = Base64::decode_vec(parts[1])
                .map_err(|_| Ed25519Error::InvalidPublicKey)?;
            // SSH wire format: 4-byte length + "ssh-ed25519" + 4-byte length + 32-byte key
            if blob.len() >= 51 {
                // Skip type string (4 + 11 = 15 bytes), then 4-byte length
                let key_start = 15 + 4;
                if blob.len() >= key_start + 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&blob[key_start..key_start + 32]);
                    return Ok(key);
                }
            }
        }
    }

    Err(Ed25519Error::InvalidPublicKey)
}

#[derive(Debug)]
pub enum Ed25519Error {
    Io(std::io::Error),
    InvalidPublicKey,
    InvalidSignature,
    VerificationFailed,
    Manifest(String),
}

impl std::fmt::Display for Ed25519Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::InvalidPublicKey => write!(f, "invalid Ed25519 public key"),
            Self::InvalidSignature => write!(f, "invalid Ed25519 signature format"),
            Self::VerificationFailed => write!(f, "Ed25519 signature verification failed"),
            Self::Manifest(e) => write!(f, "manifest error: {e}"),
        }
    }
}

impl std::error::Error for Ed25519Error {}
