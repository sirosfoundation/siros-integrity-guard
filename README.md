# siros-integrity-guard

Binary integrity wrapper for Common Criteria FPT_TST.1 compliance.

Verifies an HSM-signed manifest of file digests before `exec`'ing a
protected service binary. Designed for container entrypoints in the
SIROS ID ecosystem.

## How it works

1. Load a JSON manifest listing files and their expected SHA-256 digests
2. Verify the manifest's HMAC-SHA256 signature via PKCS#11 (HSM)
3. For each file: try `FS_IOC_MEASURE_VERITY` (kernel fs-verity), fall back to SHA-256
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
  "signature": "hmac-sha256-hex-here"
}
```

The signature covers the canonical JSON of the `version` and `files` fields
(i.e. the manifest with the `signature` field removed).

## Usage

```bash
siros-integrity-guard \
  --manifest /app/manifest.json \
  --exec /app/r2ps-server \
  --pkcs11-module /usr/lib/softhsm/libsofthsm2.so \
  --pkcs11-slot 0 \
  --pkcs11-pin 1234 \
  --key-label integrity-guard \
  -- --listen 0.0.0.0:8080
```

### Container entrypoint

```dockerfile
ENTRYPOINT ["/usr/bin/siros-integrity-guard", \
  "--manifest", "/app/manifest.json", \
  "--exec", "/app/r2ps-server", \
  "--pkcs11-module", "/usr/lib/softhsm/libsofthsm2.so"]
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
