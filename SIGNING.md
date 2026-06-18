# Signed Build Manifests with Sigsum Transparency

## Overview

Every Docker image built by our standard `docker-build-push.yml` workflow gets its
image digest Ed25519-signed and logged to [Sigsum](https://sigsum.org) — a public
transparency log for signed checksums. This happens automatically with zero changes
to individual Dockerfiles.

Services that additionally need **runtime integrity verification** (FPT_TST.1) can
opt into `siros-integrity-guard`, which verifies an Ed25519-signed file manifest
before exec'ing the protected binary.

## Two Layers

| Layer | What | How | Opt-in |
|-------|------|-----|--------|
| **Supply chain** (all images) | Image digest was produced by our CI | Signer runner Ed25519-signs the digest, submits to Sigsum | Default — built into `docker-build-push.yml` |
| **Runtime** (security-critical services) | File contents inside container | `siros-integrity-guard` checks signed manifest at ENTRYPOINT | Per-service — add integrity-guard to Dockerfile + use `sign-manifest.yml` |

## Layer 1: Image Digest Signing (all images)

The existing `docker-build-push.yml` reusable workflow gains a second job:

```
┌─ GitHub-hosted runner ─────────────────┐
│ Job 1: build-and-push                  │
│  • Build Docker image                  │
│  • Push to GHCR                        │
│  • Trivy CVE scan                      │
│  • Output: image digest (sha256:...)   │
└──────────────────┬─────────────────────┘
                   │ digest
                   ▼
┌─ Self-hosted signer (YubiHSM2) ───────┐
│ Job 2: sign-image                      │
│  • sigsum-submit --raw-hash <digest>   │
│  • Upload .proof artifact              │
└────────────────────────────────────────┘
```

**What Sigsum logs**: The Docker image content-addressable digest (e.g.
`sha256:a94890...`), Ed25519-signed by the YubiHSM2 key. This creates a public,
tamper-evident record of every image we've ever built.

**No Dockerfile changes needed**. The `docker/build-push-action` already outputs
`steps.build.outputs.digest`. The sign job just takes that hash and signs it.

**Verification** by anyone:

```bash
# Extract digest from a running container or GHCR
DIGEST=$(docker inspect ghcr.io/sirosfoundation/go-trust:latest --format '{{.RepoDigests}}')

# Verify the Sigsum proof (offline — no network needed)
echo -n "$DIGEST_HEX" | sigsum-verify --raw-hash \
  -k siros-integrity.pub -P sigsum-generic-2025 image.proof
```

**Monitoring** on a separate machine detects any unauthorized signatures:

```bash
sigsum-monitor --interval 60s -P sigsum-generic-2025 siros-integrity.pub
```

### Sigsum Two-Step Submission

Sigsum supports separating signing from submission, which maps to our split-runner
architecture:

1. **Signer runner** (air-gapped from internet, has YubiHSM2): Creates and signs the
   request via `sigsum-submit -k key --raw-hash`. The signing key is accessed via
   `ssh-agent` backed by the YubiHSM2 PKCS#11 module.

2. The signer runner also has internet access (needed for GitHub API), so it can
   submit directly. If we later want true air-gap, `sigsum-submit` supports creating
   the signed request offline, then submitting it from another machine.

## Layer 2: Runtime Integrity (opt-in)

For services requiring FPT_TST.1 (e.g. go-r2ps-service, goFF), the build pipeline
adds a signing step between build and Docker image creation:

```
Build binary → Compute SHA-256 → Generate unsigned manifest
  → sign-manifest.yml (signer runner signs + Sigsum logs manifest hash)
  → Build Docker image with signed manifest + pubkey inside
```

At container startup:

```
ENTRYPOINT: siros-integrity-guard
  ├── Load manifest.json
  ├── Load integrity-pubkey.pub (Ed25519 public key, 32 bytes)
  ├── Verify Ed25519 signature on manifest
  ├── For each file: verify SHA-256 (or fs-verity)
  ├── Check /proc/self/status TracerPid (anti-debug)
  └── execvp(target-binary, args...)
```

No HSM needed at runtime — only the 32-byte public key.

## Key Management (YubiHSM2)

| Key ID | Algorithm | Purpose |
|--------|-----------|---------|
| 0x0020 | RSA-4096  | GPG signing for APT repository |
| 0x0030 | Ed25519   | Image digest signing, manifest signing, Sigsum |

Both non-extractable. Same signer runner, same YubiHSM2 device. The Ed25519 key is
exposed to `sigsum-submit` via `ssh-agent` + PKCS#11.

## CC Certification Impact

- **FPT_TST.1** (Self-testing): Layer 2 — integrity-guard verifies Ed25519-signed
  manifests at container startup.
- **FCS_COP.1** (Cryptographic operation): Ed25519 (FIPS 186-5). Signing key
  protected by YubiHSM2 (FIPS 140-2 Level 3).

## Implementation Checklist

1. Generate Ed25519 key `0x0030` on the YubiHSM2
2. Install Sigsum tools on the signer runner
3. Configure `ssh-agent` with YubiHSM2 PKCS#11 for the Ed25519 key
4. Add `sign-image` job to `docker-build-push.yml`
5. Publish Ed25519 public key on siros.org
6. Start `sigsum-monitor` on a separate machine
7. For services needing runtime integrity: add integrity-guard + `sign-manifest.yml`
