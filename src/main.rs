mod ed25519;
mod fsverity;
mod manifest;
mod verify;

use clap::Parser;
use std::process;

#[derive(Parser)]
#[command(name = "siros-integrity-guard")]
#[command(about = "Verify signed manifest before exec'ing the protected service")]
#[command(version)]
struct Cli {
    /// Path to the JSON manifest file
    #[arg(long)]
    manifest: String,

    /// Path to the binary to exec after verification
    #[arg(long)]
    exec: String,

    /// Path to the Ed25519 public key file (raw, hex, or SSH format)
    #[arg(long, env = "INTEGRITY_PUBKEY")]
    pubkey: String,

    /// Arguments to pass to the exec'd binary
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

fn main() {
    let cli = Cli::parse();

    // 1. Load manifest
    let manifest = match manifest::Manifest::load(&cli.manifest) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("integrity-guard: failed to load manifest: {e}");
            process::exit(1);
        }
    };

    // 2. Load public key and verify manifest Ed25519 signature
    let pubkey = match ed25519::load_public_key(&cli.pubkey) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("integrity-guard: failed to load public key: {e}");
            process::exit(2);
        }
    };

    let raw_manifest = match std::fs::read(&cli.manifest) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("integrity-guard: failed to read manifest: {e}");
            process::exit(1);
        }
    };

    if let Err(e) = ed25519::verify_manifest_signature(&pubkey, &raw_manifest, &manifest.signature)
    {
        eprintln!("integrity-guard: manifest signature verification failed: {e}");
        process::exit(2);
    }

    // 3. Verify each file in the manifest
    for entry in &manifest.files {
        if let Err(e) = verify::verify_file(&entry.path, &entry.digest) {
            eprintln!(
                "integrity-guard: file verification failed for {}: {e}",
                entry.path
            );
            process::exit(3);
        }
    }

    // 4. Check for debugger attachment
    if is_debugger_attached() {
        eprintln!("integrity-guard: debugger detected, refusing to exec");
        process::exit(4);
    }

    // 5. exec the target binary (never returns on success)
    let exec_path = std::ffi::CString::new(cli.exec.as_str()).unwrap_or_else(|_| {
        eprintln!("integrity-guard: invalid exec path");
        process::exit(5);
    });

    let mut argv: Vec<std::ffi::CString> = Vec::with_capacity(1 + cli.args.len());
    argv.push(exec_path.clone());
    for arg in &cli.args {
        argv.push(std::ffi::CString::new(arg.as_str()).unwrap_or_else(|_| {
            eprintln!("integrity-guard: invalid argument");
            process::exit(5);
        }));
    }

    // This never returns on success
    match nix::unistd::execvp(&exec_path, &argv) {
        Ok(infallible) => match infallible {},
        Err(e) => {
            eprintln!("integrity-guard: execvp failed: {e}");
            process::exit(6);
        }
    }
}

fn is_debugger_attached() -> bool {
    match std::fs::read_to_string("/proc/self/status") {
        Ok(status) => status.lines().any(|line| {
            if let Some(val) = line.strip_prefix("TracerPid:\t") {
                val.trim() != "0"
            } else {
                false
            }
        }),
        Err(_) => false, // /proc not available, skip check
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_debugger_in_test() {
        // In a normal test run, no debugger should be attached
        // (this may fail under a debugger, which is acceptable)
        assert!(!is_debugger_attached());
    }
}
