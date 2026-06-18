# siros-integrity-guard

[![CI](https://github.com/sirosfoundation/siros-integrity-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/siros-integrity-guard/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sirosfoundation/siros-integrity-guard/badge)](https://scorecard.dev/viewer/?uri=github.com/sirosfoundation/siros-integrity-guard)
[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](LICENSE)

Binary integrity wrapper for Common Criteria FPT_TST.1 compliance.

Verifies an Ed25519-signed manifest of file digests before `exec`'ing a
protected service binary. Designed for container entrypoints in the
SIROS ID ecosystem.

## How it works

1. Load a JSON manifest listing files and their expected SHA-256 digests
2. Verify the manifest's Ed25519 signature using a public key file
3. For each file: try `FS_IOC_MEASURE_VERITY` (kernel fs-verity), fall back to userspace SHA-256
4. Check `/proc/self/status` for debugger attachment (`TracerPid`)
5. `execvp()` the target binary — the guard process is replaced entirely

## Manifest format

```json
{
  "version": 1,
  "files": [
    {"path": "/app/server", "digest": "sha256-hex-here"},
    {"path": "/app/config.toml", "digest": "sha256-hex-here"}
  ],
  "signature": "ed25519-signature-hex-here"
}
```

The signature covers the canonical JSON of the `version` and `files` fields
(i.e. the manifest with the `signature` field removed and re-serialized).

Manifests are signed offline using an Ed25519 private key (e.g. on a
YubiHSM2). The guard only needs the 32-byte public key at runtime.

## Usage

```bash
siros-integrity-guard \
  --manifest /app/manifest.json \
  --exec /app/r2ps-server \
  --pubkey /app/integrity.pub \
  -- --listen 0.0.0.0:8080
```

The `--pubkey` flag accepts raw 32-byte binary, 64-char hex, or
`ssh-ed25519` format. It can also be set via the `INTEGRITY_PUBKEY`
environment variable.

### Container entrypoint

```dockerfile
COPY integrity.pub /app/integrity.pub
ENTRYPOINT ["/usr/bin/siros-integrity-guard", \
  "--manifest", "/app/manifest.json", \
  "--exec", "/app/r2ps-server", \
  "--pubkey", "/app/integrity.pub"]
```

## Building

```bash
# Native build
cargo build --release

# Static musl binary (for containers)
cargo build --release --target x86_64-unknown-linux-musl

# Debian package
make deb
```

## Exit codes

| Code | Meaning |
|------|---------|
| 1    | Failed to load manifest |
| 2    | Manifest signature verification failed |
| 3    | File digest verification failed |
| 4    | Debugger detected |
| 5    | Invalid exec path or arguments |
| 6    | execvp failed |

## License

BSD-2-Clause — see [LICENSE](LICENSE).
