# TokScope Xordi TEE Verification Report

**Report Date:** 2026-02-12
**App ID:** `f44389ef4e953f3c53847cc86b1aedc763978e83`
**Domain:** `release.xordi.io`
**dstack Version:** 0.5.3
**Source:** https://github.com/Account-Link/teleport-tokscope (branch: `tokscope-xordi`)

---

## Quick Status

| Check | Status | Notes |
|-------|--------|-------|
| TEE Attestation | PASS | Trust Center verification completed |
| Hardware Integrity | PASS | Intel TDX quote valid |
| Transparency Log | **FAIL** | Pha KMS (no public upgrade log) |
| Reproducible Build | **UNVERIFIABLE** | Images are `${VAR}` in allowed_envs - actual digests hidden |
| Source Provenance | **UNVERIFIABLE** | Can't trace from hidden image to source |

**Stage Assessment: 0 (Ruggable)** - Pha KMS only, image refs are operator secrets

---

## What Is TokScope?

TokScope is a TikTok data sampling tool that runs in a TEE. It captures TikTok sessions (cookies, tokens) and provides access to the ForYouPage feed. The enclave:
1. Spawns headless Chromium browsers
2. Captures TikTok QR code logins
3. Stores encrypted session cookies
4. Makes authenticated API calls to TikTok

This handles **sensitive user credentials** (TikTok session tokens).

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        TEE ENCLAVE (dstack)                         │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │  API Server  │───▶│ tee-crypto   │───▶│ XORDI_API_URL        │  │
│  │  (server.ts) │    │ (encrypt w/  │    │ (store encrypted     │  │
│  │              │    │  dstack key) │    │  cookies)            │──┼──▶ Xordi Backend
│  │  captures    │    │              │    │                      │  │    (external)
│  │  TikTok      │    │ ✓ FIXED      │    │  Later: retrieve &   │  │
│  │  cookies     │    │              │    │  decrypt for API use │  │
│  └──────────────┘    └──────────────┘    └──────────────────────┘  │
│                                                                     │
│  ┌──────────────┐                                                   │
│  │ Browser Mgr  │  Spawns Chromium containers for QR login          │
│  └──────────────┘                                                   │
└─────────────────────────────────────────────────────────────────────┘
```

**Data Flow:**
1. User scans TikTok QR code in enclave browser
2. Enclave captures session cookies (plaintext inside TEE)
3. `teeCrypto.encryptCookies()` encrypts cookies
4. Encrypted blob sent to `XORDI_API_URL` for persistent storage
5. Later: enclave retrieves encrypted blob, decrypts, uses for TikTok API

---

## Encryption Key: FIXED in Production

**Initial finding:** Branch HEAD (`e4ffe87`) had a hardcoded fallback encryption key in `tee-crypto.js`.

**Verification:** The deployed commit (`58ad3f2`, visible in release tags `v1.1.0-58ad3f2`) contains the fix:

**tee-crypto.js at 58ad3f2:**
```javascript
setDStackKey(derivedKeyBuffer) {
  this.encryptionKey = derivedKeyBuffer;
  this._usingDStackKey = true;
  console.log('🔐 TEE crypto upgraded to DStack-derived key');
}
```

**server.ts at 58ad3f2:**
```javascript
// initDStack() derives separate cookie key
const cookieKeyResult = await client.getKey('cookie-encryption', 'aes');
const cookieKey = Buffer.from(cookieKeyResult.key).slice(0, 32);
teeCrypto.setDStackKey(cookieKey);
```

**Status:** Production uses TEE-derived keys. The branch HEAD has older code (git history diverged), but the deployed version is correct.

**Note:** The fallback key still exists for migration of old data encrypted before the fix.

---

## Secondary Gap: Pha KMS (No Public Upgrade Log)

**Problem:** Deployment is on `dstack-pha-prod9.phala.network` (Phala Cloud), not Base KMS.

**Impact:** Cannot answer "what compose hash was running on Feb 1?" - no on-chain transparency log.

**Fix:** Migrate to Base KMS:
```yaml
x-dstack:
  kms: base
```

---

## Design Choices (Not Gaps)

### XORDI_API_URL in allowed_envs

This is the backend database URL. **With proper encryption**, this would be fine - the operator receives only encrypted blobs they can't decrypt.

The issue is the encryption key fallback, not the configurable URL. Fix the key derivation and this becomes a non-issue.

### Debug Screenshot Variables

`DEBUG_SCREENSHOT_BASE_URL` is in `allowed_envs` but implementation not found in codebase - possibly unused/future feature.

### Image References Are Operator Secrets

**Critical:** All images are referenced via `${VAR}` in docker_compose_file:
- `${TOKSCOPE_ENCLAVE_IMAGE}`
- `${TOKSCOPE_BROWSER_MANAGER_IMAGE}`
- `${TOKSCOPE_BROWSER_IMAGE}`

These vars are in `allowed_envs`, meaning their values are operator secrets set in the Phala Cloud dashboard. **Auditors cannot see what images are actually deployed.**

The build system may produce reproducible images, but we cannot verify:
1. What image digest is running
2. Whether it matches the claimed source commit

### Proxy Configuration

WireGuard/proxy vars are for routing TikTok requests through VPN to avoid rate limiting. Traffic is TLS-encrypted to TikTok servers, so MITM risk is limited. The real credentials (cookies) are in HTTP headers, protected by TLS.

---

## What's Done Right (in the codebase, but unverifiable in deployment)

1. **Deterministic build system** in repo with digest pinning - BUT actual deployed images are hidden
2. **API Dockerfile uses digest pinning:** `node:18-slim@sha256:f9ab18e354...` - in repo
3. **SOURCE_DATE_EPOCH for reproducibility** - in CI
4. **Security hardening in compose template:** `read_only`, `no-new-privileges`, `tmpfs`
5. **Commit SHA in image tags:** Traceable provenance (v1.1.0-58ad3f2) - in repo
6. **server.ts uses dstack SDK** for session encryption key derivation
7. **Endpoint whitelist** in `/api/tiktok/execute` - only approved TikTok APIs allowed

**Caveat:** Items 1-3, 5 are unverifiable because image refs are operator secrets.

---

## Verification Steps

### 1. Check Trust Center
```bash
# Status: completed
curl -s "https://trust.phala.com/api/app/f44389ef4e953f3c53847cc86b1aedc763978e83" | jq '.status'
```

### 2. Check 8090 Metadata
```bash
curl -s "https://f44389ef4e953f3c53847cc86b1aedc763978e83-8090.dstack-pha-prod9.phala.network/" | jq '.compose_hash, .allowed_envs'
```

**Compose Hash:** `a9e4ac8a171804992e14078ef6edcc6f9467b5aa731a503c908e3a3057e6f9ea`

### 3. Review Source
```bash
git clone https://github.com/Account-Link/teleport-tokscope
git checkout 58ad3f2  # Deployed commit (branch HEAD differs!)
# Review: tokscope-enclave/tee-crypto.js (setDStackKey method)
# Review: tokscope-enclave/server.ts (initDStack calls setDStackKey)
```

**Note:** Branch HEAD (`tokscope-xordi`) has diverged from deployed commit. Always verify against the commit SHA in release tags (`v1.1.0-58ad3f2`).

---

## Path to Stage 1

| Fix | Effort | Impact |
|-----|--------|--------|
| ~~Fix tee-crypto.js key derivation~~ | ~~Low~~ | ✅ Fixed in deployed version |
| **Hardcode image digests in compose** | Low | Auditors can verify actual images |
| **Migrate to Base KMS** | Medium | Public upgrade log |

**Blocking issues:**
1. **Image refs are hidden:** `${TOKSCOPE_ENCLAVE_IMAGE}` is an operator secret. Must hardcode in compose.
2. **Pha KMS:** No public upgrade log. Can't answer "what ran last week?"

Until image digests are hardcoded in docker_compose_file, reproducible build verification is impossible.

---

## References

- Trust Center: https://trust.phala.com/app/f44389ef4e953f3c53847cc86b1aedc763978e83
- 8090 Metadata: https://f44389ef4e953f3c53847cc86b1aedc763978e83-8090.dstack-pha-prod9.phala.network/
- Source: https://github.com/Account-Link/teleport-tokscope/tree/tokscope-xordi
- Release Status: https://release.xordi.io/
