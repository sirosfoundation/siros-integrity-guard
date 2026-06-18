use nix::libc;
use std::io;
use std::os::unix::io::AsRawFd;

/// FS_IOC_MEASURE_VERITY ioctl number.
/// From linux/fsverity.h: _IOWR('f', 133, struct fsverity_digest)
/// = 0xC008_6685 for a 8-byte-header struct.
const FS_IOC_MEASURE_VERITY: libc::c_ulong = 0xC008_6685;

/// Maximum digest size we support (SHA-256 = 32 bytes).
const MAX_DIGEST_SIZE: u16 = 64;

/// fsverity_digest struct layout (from linux/fsverity.h):
/// ```c
/// struct fsverity_digest {
///     __u16 digest_algorithm; // output
///     __u16 digest_size;      // input/output
///     __u8  digest[];         // output, variable length
/// };
/// ```
#[repr(C)]
struct FsVerityDigest {
    digest_algorithm: u16,
    digest_size: u16,
    digest: [u8; MAX_DIGEST_SIZE as usize],
}

/// Attempt to read the fs-verity digest of a file via ioctl.
///
/// Returns the hex-encoded digest on success, or an error if
/// fs-verity is not enabled on the file or filesystem.
pub fn measure(path: &str) -> Result<String, FsVerityError> {
    let file = std::fs::File::open(path)?;
    let fd = file.as_raw_fd();

    let mut digest = FsVerityDigest {
        digest_algorithm: 0,
        digest_size: MAX_DIGEST_SIZE,
        digest: [0u8; MAX_DIGEST_SIZE as usize],
    };

    let ret =
        unsafe { libc::ioctl(fd, FS_IOC_MEASURE_VERITY as libc::c_ulong, &mut digest as *mut _) };

    if ret < 0 {
        let err = io::Error::last_os_error();
        return Err(FsVerityError::Ioctl(err));
    }

    let size = digest.digest_size as usize;
    if size > MAX_DIGEST_SIZE as usize {
        return Err(FsVerityError::InvalidDigestSize(size));
    }

    Ok(hex::encode(&digest.digest[..size]))
}

#[derive(Debug)]
pub enum FsVerityError {
    Io(io::Error),
    Ioctl(io::Error),
    InvalidDigestSize(usize),
}

impl std::fmt::Display for FsVerityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Ioctl(e) => write!(f, "FS_IOC_MEASURE_VERITY ioctl failed: {e}"),
            Self::InvalidDigestSize(s) => write!(f, "invalid digest size: {s}"),
        }
    }
}

impl std::error::Error for FsVerityError {}

impl From<io::Error> for FsVerityError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_measure_nonexistent_file() {
        let result = measure("/nonexistent/file");
        assert!(result.is_err());
    }

    #[test]
    fn test_measure_regular_file_no_verity() {
        // On most filesystems/kernels, a regular file won't have verity enabled.
        // This should fail with ENOTTY or EOPNOTSUPP, which is the expected fallback path.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain");
        std::fs::write(&path, b"test").unwrap();

        let result = measure(path.to_str().unwrap());
        // We expect this to fail — that's the normal case triggering SHA-256 fallback
        assert!(result.is_err());
    }
}
