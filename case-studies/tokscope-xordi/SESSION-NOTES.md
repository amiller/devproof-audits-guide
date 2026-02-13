# TokScope Xordi Audit Session Notes

**Date:** 2026-02-12
**Status:** Verification Complete

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

## References Used

- `~/projects/dstack/dstack-tutorial/SESSION-NOTES.md` - Has compose hash formula
- `refs/trust-center/packages/verifier/` - Verification implementation (build broken)
- `@phala/dstack-sdk` - getComposeHash() function
