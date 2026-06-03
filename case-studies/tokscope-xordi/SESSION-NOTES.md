# TokScope Xordi Audit Session Notes

**Date:** 2026-02-12 (updated 2026-03-03)
**Status:** v1.1.3F Audit Complete — Stage 1 Achieved

## Pitfalls Encountered (Documentation Gaps)

### 1. Compose Hash Verification - SOLVED

**The pitfall:** We couldn't reproduce the compose hash because we were saving/parsing the `app_compose` as a JSON object.

**Root cause:** The `app_compose` in `tcb_info` is already a JSON **string**. Don't parse and re-serialize - hash the raw string directly:

```python
compose_hash = sha256(app_compose_str.encode('utf-8')).hexdigest()
```

**Added to LEARNINGS.md:** Section 11

### 2. phala cvms attestation is useless for auditing

**The pitfall:** We tried `phala cvms attestation` and got 404.

**Root cause:** This command only works for apps YOU own. For third-party auditing, use 8090 endpoint.

**Added to:** LEARNINGS.md Section 11, AUDIT-GUIDE.md Step 0

### 3. Git branch HEAD ≠ deployed commit

**The pitfall:** Branch HEAD (`e4ffe87`) had security issues, but deployed commit (`58ad3f2`) was fixed.

**Root cause:** Git branches diverge from deployed versions. Always trace: compose hash → image tag → commit SHA.

**Added to LEARNINGS.md:** Section 12

### 4. Trust-center verifier doesn't build

**The pitfall:** Tried to build trust-center verifier Docker image, got dcap-qvl Rust compilation errors.

```
error[E0464]: multiple candidates for `rlib` dependency `webpki` found
```

**Root cause:** dcap-qvl has dependency conflicts with webpki. Needs upstream fix.

**Workaround:** Use trust.phala.com for full attestation, verify-compose-hash.py for compose hash.

**Added to LEARNINGS.md:** Section 13

### 5. Reproducible build verification steps undocumented

**The pitfall:** Report said "Reproducible Build | PASS" but we didn't actually try to reproduce.

**Added to LEARNINGS.md:** Section 14 - How to Actually Verify Reproducible Builds

### 6. Image refs via allowed_envs = audit blind spot

**The pitfall:** Tried to verify reproducible build but discovered image refs are `${VAR}` in allowed_envs.

**Root cause:** When docker_compose_file uses `image: ${TOKSCOPE_ENCLAVE_IMAGE}` and that var is in allowed_envs, the actual image digest is an operator secret - NOT exposed anywhere auditors can see.

```yaml
# What's in compose_hash:
image: ${TOKSCOPE_ENCLAVE_IMAGE}

# What auditors need but can't see:
TOKSCOPE_ENCLAVE_IMAGE=ghcr.io/org/app@sha256:abc123...
```

**Impact:**
- Can't verify what image is running
- Can't do reproducible build verification
- Operator could deploy any image

**Added to LEARNINGS.md:** Section 15 - Image References via allowed_envs

### 7. Reproducible builds don't actually reproduce

**The pitfall:** Even though images are publicly hosted on GHCR with tags like `v1.1.0-58ad3f2`, rebuilding from source at the same commit with the same build args produces different images.

**Method:** Pulled published images, checked out commit `58ad3f2`, ran `docker buildx build` with `--build-arg SOURCE_DATE_EPOCH=1770749076 --build-arg DEBIAN_SNAPSHOT=20240330T000000Z --output type=docker,rewrite-timestamp=true`, compared layer diff IDs.

**Results:**

| Image | Base layers (1-5) | Build layers (6+) | Verdict |
|-------|-------------------|-------------------|---------|
| tokscope-enclave-api | 5/5 match | 0/11 match | **FAIL** |
| tokscope-browser-manager | 5/5 match | 0/6 match | **FAIL** |
| tokscope-browser | N/A | N/A | **Not attempted** (`:latest` base) |

**Root causes:**

1. **`DEBIAN_SNAPSHOT` is declared but never used.** The build arg is set as an env var inside the container, but the Dockerfile never reconfigures `/etc/apt/sources.list` to point at `snapshot.debian.org/$DEBIAN_SNAPSHOT`. The `apt-get update` still hits live `deb.debian.org`.

2. **Python pip packages have no version pins.** `Dockerfile.api` runs `pip3 install fastapi pydantic pycryptodome protobuf` without `==version`. We got `fastapi-0.129.0`, `pydantic-2.12.5`, `pycryptodome-3.23.0`, `protobuf-6.33.5` — different from whatever was current on Feb 10.

3. **Browser base image unpinned.** `Dockerfile.browser` uses `ghcr.io/m1k1o/neko/chromium:latest` — fundamentally unreproducible.

4. **Transitive apt deps unpinned.** `Dockerfile.browser-manager` pins top-level packages (`docker.io=20.10.24+dfsg1-1+deb12u1+b3`) but transitive deps like `libssl3` pull whatever version is current.

**What the build system gets right:** digest-pinned base images for api/manager, `SOURCE_DATE_EPOCH`, `rewrite-timestamp=true`, `package-lock.json` for npm. The scaffolding is there but package manager determinism is missing.

**Published image digests (for reference):**
- `ghcr.io/account-link/tokscope-enclave-api:v1.1.0-58ad3f2` → `sha256:f1716ac387073cb82260a567af659bc00c47255dbcb0ab8ce6e5b45f1414b370`
- `ghcr.io/account-link/tokscope-browser-manager:v1.1.0-58ad3f2` → `sha256:43247997f642d5f129a3aca811e50699ed6087cd3c680a8f7e58628d43e317d8`
- `ghcr.io/account-link/tokscope-browser:v1.1.0-58ad3f2` → `sha256:8229cb8e27196203eea4586910eee88dc04f9bf5f4cd9ae4f28d664d217c0c0a`

## Data Sources for Third-Party Auditing

1. **8090 endpoint:** `https://<app-id>-8090.<cluster>.phala.network/`
   - Contains `<textarea readonly>` with full tcb_info JSON (HTML-encoded)
   - Includes: app_compose, event_log, compose_hash, RTMRs, etc.

2. **Trust Center UI:** `https://trust.phala.com/app/<app-id>`
   - Visual verification status

3. **`phala cvms attestation`:** ❌ Only works for apps you OWN - useless for third-party auditing

## Tools Created

- `tools/verify-compose-hash.py` - Fetches 8090 page and verifies compose hash

## Files Updated This Session

1. `LEARNINGS.md` - Sections 11-14 added/updated
2. `framework/AUDIT-GUIDE.md` - Added "Step 0: Fetch Deployed Configuration"
3. `README.md` - Added verification tools section
4. `tools/verify-compose-hash.py` - Created verification script

## Key URLs

- 8090 Metadata: https://f44389ef4e953f3c53847cc86b1aedc763978e83-8090.dstack-pha-prod9.phala.network/
- Trust Center: https://trust.phala.com/app/f44389ef4e953f3c53847cc86b1aedc763978e83
- Source: https://github.com/Account-Link/teleport-tokscope/tree/tokscope-xordi
- Deployed commit: `58ad3f2` (from tag `v1.1.0-58ad3f2`, NOT branch HEAD)

## v1.1.3F Audit Session (2026-03-03)

### What Changed

Complete redeployment to a new app ID on `dstack-base-prod5`. Both previous blocking issues resolved:
- **Image refs:** Hardcoded `@sha256:` digests (removed `${VAR}` pattern and 3 image env vars from allowed_envs)
- **KMS:** Migrated from Pha KMS → Base KMS (on-chain compose hash registry)
- **Multi-instance:** Main TEE + Auth Worker, both sharing keys via Base KMS
- **Release dashboard:** `prod2-release.xordi.io` with live API history at `staging-api.xordi.io`
- **New endpoint:** `/tee-info` exposes app_id, compose_hash, instance_id, tcb_info publicly

### New Pitfall: Image Tags as Build Hashes

The deployed images have tags like `b94ee5df64d4` that are NOT git commit SHAs — they don't exist in the repo. They appear to be Docker build hashes from the CI pipeline. The actual source commit is `bbc38c5d2a68` on branch `deployed-v1.1.3F`. This makes source tracing require branch inspection rather than tag-to-commit mapping.

### New Pitfall: Trust Center Lag

New app IDs don't get Trust Center reports immediately. `trust.phala.com/app/bc81bb62...` returned "not yet generated" on deployment day. Need to recheck.

### Verification Method

1. Fetched `staging-api.xordi.io/api/release/current` — got both instance IDs and compose hashes
2. Hit 8090 endpoints for both instances — confirmed matching compose hashes, got container digests
3. Verified all 3 image digests pullable from GHCR via `skopeo inspect`
4. Matched image tags to `deployed-v1.1.3F` branch via creation timestamps
5. Reviewed diff: `deployed-v1.1.2...deployed-v1.1.3F` (5 commits, 8 files)

### Key URLs (v1.1.3F)

- Release Dashboard: https://prod2-release.xordi.io/
- Main TEE 8090: https://66b5218676531da2be9966adb0eb9c8bc901f183-8090.dstack-base-prod5.phala.network/
- Auth Worker 8090: https://83e8ce96dbef6c03c5a0e1c5f66309271c9cdfa6-8090.dstack-base-prod5.phala.network/
- Trust Center: https://trust.phala.com/app/bc81bb624b69729a3fb6e51e08426e8b726be0c7
- Source: https://github.com/Account-Link/teleport-tokscope/tree/deployed-v1.1.3F

## References Used

- `~/projects/dstack/dstack-tutorial/SESSION-NOTES.md` - Has compose hash formula
- `refs/trust-center/packages/verifier/` - Verification implementation (build broken)
- `@phala/dstack-sdk` - getComposeHash() function
