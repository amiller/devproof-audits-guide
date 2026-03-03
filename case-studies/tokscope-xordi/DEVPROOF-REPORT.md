# TokScope Xordi TEE Verification Report

**Report Date:** 2026-02-21 (updated from 2026-02-12)
**App ID:** `f44389ef4e953f3c53847cc86b1aedc763978e83`
**Domain:** `release.xordi.io`
**dstack Version:** 0.5.3
**OS Image Hash:** `2d24d302cc8686d6a0ece71a6afef55c506bc8591e3bcc1ec3eb5323d77582c4`
**Source:** https://github.com/Account-Link/teleport-tokscope (branch: `tokscope-xordi`)
**Deployed Commit:** `535fba0` (v1.1.2, 2026-02-20)
**Previous Audit Commit:** `58ad3f2` (v1.1.0, 2026-02-12)

---

## Quick Status

| Check | Status | Notes |
|-------|--------|-------|
| TEE Attestation | PASS | Trust Center verification completed |
| Hardware Integrity | PASS | Intel TDX quote valid, event log verified |
| Docker Images Public | **PASS** (new) | All 3 images pullable from GHCR |
| Reproducible Build Infra | **IMPROVED** | Apt snapshot pinning, pip version pins, digest-pinned base images |
| Transparency Log | **FAIL** | Still Pha KMS (no public upgrade log) |
| Image Refs in Compose | **FAIL** | Still `${VAR}` — actual deployed digests hidden from auditors |
| Source-to-Image Chain | **UNVERIFIABLE** | Can't trace from hidden image refs to source |

**Stage Assessment: 0 (Ruggable)** — image refs are operator secrets, Pha KMS only

---

## What Is TokScope?

TokScope is a TikTok data sampling tool running in a TEE. It captures TikTok sessions (cookies, tokens) and provides ForYouPage feed access. The enclave:
1. Spawns headless Chromium browsers via browser-manager
2. Captures TikTok QR code logins
3. Encrypts session cookies with TEE-derived keys
4. Stores encrypted blobs via XORDI_API_URL
5. Retrieves and decrypts cookies for authenticated TikTok API calls

Handles **sensitive user credentials** (TikTok session tokens).

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
│  │  TikTok      │    │ ✓ TEE keys   │    │  Later: retrieve &   │  │
│  │  cookies     │    │              │    │  decrypt for API use │  │
│  └──────────────┘    └──────────────┘    └──────────────────────┘  │
│                                                                     │
│  ┌──────────────┐    ┌──────────────┐                               │
│  │ Browser Mgr  │───▶│ Neko/Chrome  │  Spawns browser containers    │
│  │ (privileged) │    │ (per-session)│  for QR login                 │
│  └──────────────┘    └──────────────┘                               │
└─────────────────────────────────────────────────────────────────────┘
```

**Components (v1.1.2):**

| Component | Image Tag | Commit | Digest |
|-----------|-----------|--------|--------|
| tokscope-enclave-api | v1.1.2-535fba0 | 535fba0 | sha256:42df0d04b6a5aa943def31b15b549a32cdfa34b359b47f1474467e16af3e6bc1 |
| tokscope-browser-manager | v1.1.2-535fba0 | 535fba0 | sha256:c30f89398fdb99314e2c08ae5ff137d586c11b27554ccc5b9a70ffb2a7af89a5 |
| tokscope-browser | v1.1.2-535fba0 | 535fba0 | (pulled, see verification) |
| borgcube-playwright | deployed-v1.1.2 | 1b0ce85 | N/A (source-mounted) |

---

## Changes Since Previous Audit (58ad3f2 → 535fba0)

4 commits between audited versions:

| Commit | Date | Summary |
|--------|------|---------|
| bbafd17 | 2026-02-13 | Pin apt snapshots, pip versions, base image digest for reproducibility |
| 8696434 | 2026-02-19 | Add `/auth/destroy/:authSessionId` endpoint for external cleanup |
| b8b7be8 | 2026-02-19 | Make WireGuard bucket count configurable via `WIREGUARD_BUCKET_COUNT` |
| 535fba0 | 2026-02-20 | Fix browser-manager apt version pins, read `FALLBACK_KEY_MATERIAL` from env |

### Files Changed

| File | Change |
|------|--------|
| tokscope-enclave/Dockerfile.api | Apt snapshot pinning, pip version pins |
| tokscope-enclave/Dockerfile.browser | Base image pinned by digest (was `:latest`) |
| tokscope-enclave/Dockerfile.browser-manager | Apt snapshot pinning, removed exact apt version pins (snapshot handles it) |
| tokscope-enclave/server.ts | New `/auth/destroy` endpoint |
| tokscope-enclave/browser-manager.ts | Configurable `WIREGUARD_BUCKET_COUNT` |
| tokscope-enclave/tee-crypto.js | `FALLBACK_KEY_MATERIAL` reads from env |
| scripts/build-deterministic.sh | Naming fixes, double-build verification |

---

## Findings

### Finding 1: Image Refs Still Hidden (CRITICAL, unchanged)

All three container images in `docker_compose_file` use `${VAR}` references:
```yaml
image: ${TOKSCOPE_ENCLAVE_IMAGE}
image: ${TOKSCOPE_BROWSER_MANAGER_IMAGE}
image: ${TOKSCOPE_BROWSER_IMAGE}
```

These variables are in `allowed_envs`, meaning their values are **operator secrets** set in the Phala Cloud dashboard. Auditors cannot verify what images are actually running from the compose hash alone.

The release page at `release.xordi.io` *claims* the images are `v1.1.2-535fba0`, and we verified these are public and pullable. But nothing in the attested compose hash binds those specific images to the deployment.

**Status:** Unchanged from previous audit. Still the primary blocker for Stage 1.

**Fix:** Hardcode image references (with digests) in docker-compose.yml.

---

### Finding 2: No Transparency Log (MEDIUM, unchanged)

Deployment is on `dstack-pha-prod9.phala.network` using Pha KMS. No on-chain upgrade log exists.

- Previous compose hash: `a9e4ac8a171804992e14078ef6edcc6f9467b5aa731a503c908e3a3057e6f9ea`
- Current compose hash: `eefe5f4d7285a8cdb530eb8be711ddeeed7de6c8a03f6397d037b8f37066677b`
- No public record of when the transition happened

**Status:** Unchanged. Cannot answer "what compose hash was running on Feb 15?"

**Fix:** Migrate to Base KMS (on-chain compose hash registry) for public upgrade transparency. KMS type is set via the `app-compose.json` manifest (`key_provider` field), not in docker-compose.yml.

---

### Finding 3: XORDI_API_URL in allowed_envs (LOW, reassessed)

The operator controls where encrypted cookie blobs are sent. Previous audit noted this as acceptable given proper encryption — the operator receives only AES-256-GCM encrypted blobs they cannot decrypt (key is TEE-derived via dstack SDK).

The dstack boot sequence event log confirms key derivation happens before containers start:
```
key-provider  → KMS connection established
system-ready  → containers start after this
```

`initDStack()` in server.ts derives the cookie encryption key via `client.getKey('cookie-encryption', 'aes')` over the local dstack socket, which is deterministically available by boot sequence.

**Status:** Non-issue given working TEE key derivation. The operator gets encrypted blobs they can't decrypt.

---

### Finding 4: FALLBACK_KEY_MATERIAL Now Configurable (LOW, design observation)

New in v1.1.2: `FALLBACK_KEY_MATERIAL` reads from env and is in `allowed_envs`.

```javascript
// Before (58ad3f2):
const FALLBACK_KEY_MATERIAL = 'tee-enclave-key-material-32chars';
// After (535fba0):
const FALLBACK_KEY_MATERIAL = process.env.FALLBACK_KEY_MATERIAL || 'tee-enclave-key-material-32chars';
```

**Not exploitable in practice.** The dstack guest agent socket is guaranteed available before containers start (confirmed via event log boot sequence: `key-provider` → `system-ready` → docker-compose up). The `initDStack()` call in server.ts succeeds deterministically, upgrading the encryption key to a TEE-derived key.

The fallback path exists for:
1. Local development outside a TEE
2. Migrating old cookies encrypted before dstack key integration
3. `decryptCookiesWithFallback()` tries fallback key only when dstack key fails to decrypt (backward compat)

Making it configurable via env is for staging/testing convenience. If the operator changes it, old cookies encrypted with the original hardcoded constant would **fail** to decrypt — it breaks migration, not enables attacks.

---

### Finding 5: Browser Manager is Privileged (MEDIUM, noted)

```yaml
browser-manager:
    cap_add:
      - SYS_ADMIN
    privileged: true
```

The browser-manager container runs as privileged with SYS_ADMIN cap to spawn Docker containers (it manages per-session Chromium instances via Docker socket). This is architecturally necessary but expands the attack surface within the TEE.

---

## What Improved in v1.1.2

### Reproducible Build Infrastructure

Significant progress toward reproducible builds:

1. **Apt snapshot pinning:** Dockerfiles now pin to `snapshot.debian.org` for deterministic package versions
2. **Pip version pinning:** Python deps pinned exactly (`fastapi==0.104.1`, `pycryptodome==3.19.0`, etc.)
3. **Base image digest pinning:** Browser Dockerfile changed from `ghcr.io/m1k1o/neko/chromium:latest` to `@sha256:23472d1adf85a0e170c56326f58928bfa716c7ade0ef9d87d54af15116c8639c`
4. **SOURCE_DATE_EPOCH:** Set in image build (`1771625554`)
5. **Double-build verification:** `build-deterministic.sh` builds twice and compares hashes
6. **Images now public:** All three images pullable from `ghcr.io/account-link/`

**Caveat:** These improvements are unverifiable in the deployment because image refs are `${VAR}`. We can pull and inspect the claimed images, but can't prove they're what's running.

### New Endpoint: Auth Container Cleanup

`POST /auth/destroy/:authSessionId` — allows external cleanup of browser containers. Has UUID regex validation. Low-risk addition.

---

## Live Deployment Data (2026-02-21)

### Compose Hash
```
eefe5f4d7285a8cdb530eb8be711ddeeed7de6c8a03f6397d037b8f37066677b
```

### allowed_envs (22 variables)
```
XORDI_API_KEY                    # Backend auth
XORDI_API_URL                    # Backend URL (encrypted blobs only)
MIGRATION_TRIGGER_KEY            # Cookie migration
PROXY_MODE                       # VPN routing
WIREGUARD_HOST                   # VPN config
WIREGUARD_BASE_PORT              # VPN config
WG_PROXY_USER                    # VPN auth
WG_PROXY_PASS                    # VPN auth
ENABLE_DEBUG_SCREENSHOTS         # Debug feature
DEBUG_SCREENSHOT_TTL_MS          # Debug config
DEBUG_SCREENSHOT_BASE_URL        # Debug config
MIN_POOL_SIZE                    # Browser pool
DOCKER_NETWORK                   # Container networking
NEKO_DESKTOP_SCREEN              # Browser display
NEKO_DESKTOP_SCALING             # Browser display
BROWSER_CPU_LIMIT                # Resource limits
BROWSER_MEMORY_LIMIT             # Resource limits
BROWSER_MEMORY_RESERVATION       # Resource limits
FALLBACK_KEY_MATERIAL            # Legacy key (non-exploitable, see Finding 4)
TOKSCOPE_ENCLAVE_IMAGE           # ← CRITICAL: hides deployed image
TOKSCOPE_BROWSER_MANAGER_IMAGE   # ← CRITICAL: hides deployed image
TOKSCOPE_BROWSER_IMAGE           # ← CRITICAL: hides deployed image
```

### Boot Event Log Summary
```
system-preparing  → TEE boot
app-id            → f44389ef4e953f3c53847cc86b1aedc763978e83
compose-hash      → eefe5f4d7285a8cdb530eb8be711ddeeed7de6c8a03f6397d037b8f37066677b
instance-id       → d52b512ed435fea5c706318b98d54b5edb340058
boot-mr-done      → measurement registers finalized
mr-kms            → 7eb8f89cf5067da82fe5a8321dd6dbd08681c25165dbd0ab3cefc26bbd028855
os-image-hash     → 2d24d302cc8686d6a0ece71a6afef55c506bc8591e3bcc1ec3eb5323d77582c4
key-provider      → KMS with public key registered
system-ready      → containers start after this point
```

Confirms dstack socket is available before container startup. Key derivation is deterministic.

---

## Security Hardening (Verified in Compose)

```yaml
# tokscope-enclave:
security_opt: [no-new-privileges:true]
read_only: true
tmpfs: [/tmp:size=100M,noexec,nosuid,nodev, ...]
```

Browser-manager is `privileged: true` (necessary for Docker-in-Docker).

---

## Verification Checklist

| Check | Status | Notes |
|-------|--------|-------|
| Docker images pullable | ✅ | All 3 images public on GHCR |
| Image tags match commit | ✅ | v1.1.2-535fba0 traceable to git commit |
| Commit exists on GitHub | ✅ | 535fba0 = "Fix browser-manager apt version pins..." |
| Image labels/metadata | ⚠️ | No OCI labels set (no revision/version labels) |
| Compose hash reproducible | ❌ | Image refs are `${VAR}`, can't reproduce without operator secrets |
| Image digest reproducible | ⚠️ | Build infra improved, but untested (needs `build-deterministic.sh` run) |
| SOURCE_DATE_EPOCH set | ✅ | `1771625554` in image env |
| Base images pinned by digest | ✅ | Browser: `neko/chromium@sha256:23472d...` |
| Apt packages reproducible | ✅ | Snapshot pinning added |
| TEE attestation valid | ✅ | Trust Center reports "completed" |
| On-chain transparency log | ❌ | Pha KMS, no Base KMS |
| Boot sequence verified | ✅ | Event log confirms key-provider before system-ready |

---

## Path to Stage 1

| Fix | Effort | Impact | Status |
|-----|--------|--------|--------|
| ~~Docker images public~~ | ~~Low~~ | ~~External verification~~ | ✅ Done in v1.1.2 |
| ~~Reproducible build infra~~ | ~~Medium~~ | ~~Deterministic images~~ | ✅ Done in v1.1.2 |
| **Hardcode image digests in compose** | Low | Auditors can verify what's running | ❌ Blocking |
| **Migrate to Base KMS** | Medium | Public on-chain upgrade log | ❌ Blocking |
| Add OCI image labels | Low | Source traceability in image metadata | Not started |
| Verify reproducible builds end-to-end | Medium | Prove source → image chain | Not started |

**Blocking issues (same as previous audit):**
1. Image refs hidden behind `${VAR}` — must hardcode with digests
2. Pha KMS — must migrate to Base KMS for transparency

---

## References

- Trust Center: https://trust.phala.com/app/f44389ef4e953f3c53847cc86b1aedc763978e83
- 8090 Metadata: https://f44389ef4e953f3c53847cc86b1aedc763978e83-8090.dstack-pha-prod9.phala.network/
- Source: https://github.com/Account-Link/teleport-tokscope/tree/tokscope-xordi
- Release Status: https://release.xordi.io/
- Deployed Commit: https://github.com/Account-Link/teleport-tokscope/commit/535fba0
- Previous Audit Commit: https://github.com/Account-Link/teleport-tokscope/commit/58ad3f2
