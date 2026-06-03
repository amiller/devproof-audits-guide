# TokScope Xordi TEE Verification Report

**Report Date:** 2026-03-03 (updated from 2026-02-21)
**App ID:** `bc81bb624b69729a3fb6e51e08426e8b726be0c7`
**Previous App ID:** `f44389ef4e953f3c53847cc86b1aedc763978e83` (decommissioned)
**Domain:** `prod2-release.xordi.io`
**dstack Version:** 0.5.3
**OS Image Hash:** `2d24d302cc8686d6a0ece71a6afef55c506bc8591e3bcc1ec3eb5323d77582c4`
**Source:** https://github.com/Account-Link/teleport-tokscope (branch: `deployed-v1.1.3F`)
**Deployed Images Built:** 2026-03-03T02:09:14Z
**Previous Audit:** v1.1.2, commit `535fba0` (2026-02-21)

---

## Quick Status

| Check | Status | Notes |
|-------|--------|-------|
| TEE Attestation | PASS | Both instances attesting on dstack-base-prod5 |
| Hardware Integrity | PASS | Intel TDX, shared MRTD across instances |
| Docker Images Public | PASS | All 3 images pullable from GHCR |
| Image Refs in Compose | **PASS** (new!) | Hardcoded `@sha256:` digests — no more `${VAR}` |
| Transparency Log | **PASS** (new!) | Base KMS — on-chain compose hash registry |
| Compose Hash Hygiene | **WARN** | 7 hashes authorized, 0 removed — old versions still valid |
| Multi-Instance Architecture | **NEW** | Main TEE + Auth Worker sharing keys via Base KMS |
| Release Dashboard | **NEW** | `prod2-release.xordi.io` with deployment history |
| Source-to-Image Chain | **PARTIAL** | Image tags are build hashes, not git commit SHAs |
| Trust Center Report | **PENDING** | "Not yet generated" for new app ID |

**Stage Assessment: 1 (Verifiable)** — both previous blocking issues resolved

---

## What Changed Since v1.1.2

This is a **complete redeployment**, not an incremental update:

| Aspect | v1.1.2 (old) | v1.1.3F (new) |
|--------|-------------|---------------|
| App ID | `f44389ef...` | `bc81bb62...` |
| Infrastructure | `dstack-pha-prod9` | `dstack-base-prod5` |
| KMS | Pha KMS (no transparency) | **Base KMS** (on-chain) |
| Instance count | 1 | **2** (main-tee + auth-worker) |
| Image refs | `${VAR}` in allowed_envs | **Hardcoded `@sha256:` digests** |
| allowed_envs count | 22 | **19** (removed 3 image vars + FALLBACK_KEY_MATERIAL) |
| Compose hash | `eefe5f4d...` | `4dfce633...` |
| Source branch | `tokscope-xordi` | `deployed-v1.1.3F` |
| Release dashboard | `release.xordi.io` (static) | `prod2-release.xordi.io` (live API) |

### Code Changes (v1.1.2 → v1.1.3F)

5 commits, 8 files changed:

| File | Change |
|------|--------|
| tokscope-enclave/server.ts | `AUTH_ONLY_MODE` guards on data endpoints, `/tee-info` endpoint, screenshot cleanup fix, Set-based cookie lookups |
| lib/browser-automation-client.ts | Performance fix (Set.has() for cookie name lookups) |
| enclave-tools/* | dstack interaction guide updates, monitor, launch, compose hash tools |
| docs/auditing.md | Documentation updates |

---

## Architecture Overview (v1.1.3F)

```
┌───────────────────────────────────────────────────────────┐
│                   Base KMS (on-chain)                      │
│            compose hash: 4dfce633...                        │
│     ┌─────────────────┴──────────────────┐                 │
│     │                                     │                 │
│  ┌──▼──────────────────┐   ┌──────────────▼──────────┐     │
│  │   MAIN TEE          │   │   AUTH WORKER            │     │
│  │   (base-prod5)      │   │   (base-prod5)           │     │
│  │                     │   │                          │     │
│  │  tokscope-enclave   │   │  tokscope-enclave        │     │
│  │  browser-manager    │   │  AUTH_ONLY_MODE=true     │     │
│  │  browser pool       │   │  browser-manager         │     │
│  │                     │   │  browser pool             │     │
│  │  Data endpoints: ✅  │   │  Data endpoints: ❌ 503   │     │
│  │  Auth endpoints: ✅  │   │  Auth endpoints: ✅       │     │
│  └─────────────────────┘   └──────────────────────────┘     │
└───────────────────────────────────────────────────────────┘
```

Both instances share the **same compose hash** (Base KMS ensures key sharing).
Auth worker returns 503 on data endpoints — only handles QR login flows.

---

## Finding Status (Previous Findings)

### Finding 1: Image Refs Hidden Behind `${VAR}` — **RESOLVED**

Images are now hardcoded with `@sha256:` digests in the compose:

| Component | Deployed Digest |
|-----------|----------------|
| tokscope-enclave-api | `@sha256:8cd25f91b8a055bf77fae1e4e73ba5d6007544c8e68c1e8c5768e1ad008c6600` |
| tokscope-browser-manager | `@sha256:5079ab671dc245483cae264e84e007cfd5854db99df54f4af3471d725444aa57` |
| tokscope-browser | `@sha256:4580123ba4d0243f970705f81dfb16f1470e87c607b5eef1b8810f56f26d0cab` |

These digests are **bound to the compose hash** — the attestation now proves which images run.

The three `${VAR}` image variables (`TOKSCOPE_ENCLAVE_IMAGE`, `TOKSCOPE_BROWSER_MANAGER_IMAGE`, `TOKSCOPE_BROWSER_IMAGE`) have been **removed from allowed_envs**.

### Finding 2: No Transparency Log — **RESOLVED**

Migrated from Pha KMS to **Base KMS**. Both instances report `kms_type: base`. The release dashboard at `prod2-release.xordi.io` queries `staging-api.xordi.io` and shows:

| Event | Timestamp | Compose Hash |
|-------|-----------|-------------|
| initial_deploy | 2026-03-02T04:20:40Z | `25ff6b1f...` |
| release | 2026-03-03T18:19:40Z | `4dfce633...` |
| worker_registered | 2026-03-03T19:54:39Z | `4dfce633...` |

On-chain registry now provides public compose hash history.

**Note:** Trust Center report at `trust.phala.com/app/bc81bb62...` says "not yet generated." This is a timing issue — the app was deployed today.

### Finding 3: XORDI_API_URL in allowed_envs — **UNCHANGED (LOW)**

Still present. Still non-exploitable per original assessment (encrypted blobs only).

### Finding 4: FALLBACK_KEY_MATERIAL — **RESOLVED**

`FALLBACK_KEY_MATERIAL` has been **removed from allowed_envs** entirely. No longer operator-configurable.

### Finding 5: Browser Manager is Privileged — **UNCHANGED (MEDIUM)**

Still `privileged: true` with `SYS_ADMIN`. Still architecturally necessary.

---

## New Findings

### Finding 6: Image Tags Are Build Hashes, Not Git Commits (LOW)

The deployed images have tags that don't correspond to git commit SHAs:

| Image | Tag | Git Commit? |
|-------|-----|-------------|
| tokscope-enclave-api | `b94ee5df64d4` | Not found in repo |
| tokscope-browser-manager | `07fcc5d5fe1b` | Not found in repo |
| tokscope-browser | `22db105d0c20` | Not found in repo |

These appear to be Docker build hashes or CI identifiers. The `deployed-v1.1.3F` branch HEAD is `bbc38c5d2a68` (2026-03-03T02:09:14Z) which matches the image creation timestamps exactly. The v1.1.3 tagged images (`v1.1.3-dc73a25`) have **different digests** from what's deployed — the deployed images are from a later commit (`bbc38c5d`).

**Impact:** Source tracing requires going through the branch rather than image tags. Not a security issue since image digests are now hardcoded in compose.

### Finding 7: AUTH_ONLY_MODE as Operator-Controlled Role Split (OBSERVATION)

`AUTH_ONLY_MODE` is in `allowed_envs` and controls which endpoints are active:
- `false` (main-tee): All endpoints active
- `true` (auth-worker): Data endpoints return 503, only auth/QR flows work

This is a clean architectural pattern. The guard is applied to 5 data endpoints in server.ts. The same code runs on both instances — role is determined by env var. Both instances share keys via Base KMS, so auth cookies encrypted on the worker can be decrypted on the main TEE.

### Finding 8: Trust Center Report Pending (NOTE)

`trust.phala.com/app/bc81bb624b69729a3fb6e51e08426e8b726be0c7` returns "not yet generated." Expected for a same-day deployment. Should be rechecked.

### Finding 9: 14 Compose Hashes Authorized On-Chain, 0 Removed (MEDIUM)

The Base KMS contract at `0xbc81bb624b69729a3fb6e51e08426e8b726be0c7` has **14 `ComposeHashAdded` events and 0 `ComposeHashRemoved` events**, across 7 unique compose hashes:

| # | Compose Hash | First Authorized | Notes |
|---|-------------|------------------|-------|
| 1 | `b8054112...` | Mar 1 19:52 UTC | Early testing |
| 2 | `974e37c8...` | Mar 2 00:21 UTC | Early testing |
| 3 | `0a39f013...` | Mar 2 00:25 UTC | Early testing |
| 4 | `09b989d6...` | Mar 2 00:31 UTC | Early testing (added twice) |
| 5 | `25ff6b1f...` | Mar 2 01:17 UTC | Matches `initial_deploy` in release dashboard |
| 6 | `283968d2...` | Mar 2 02:29 UTC | Previous release (added 4×) |
| 7 | **`4dfce633...`** | **Mar 3 03:07 UTC** | **Currently deployed** (added 4×) |

All 7 hashes remain active — `removeComposeHash()` has never been called. This means the contract owner could redeploy any previous compose hash and the Base KMS would still issue keys for it.

**How removal works:** The `DstackApp` contract (source: `dstack/kms/auth-eth/contracts/DstackApp.sol`) stores a `mapping(bytes32 => bool) public allowedComposeHashes`. The owner calls:

```solidity
// Add — KMS will issue keys for this compose hash
function addComposeHash(bytes32 composeHash) external onlyOwner {
    allowedComposeHashes[composeHash] = true;
    emit ComposeHashAdded(composeHash);
}

// Remove — KMS will STOP issuing keys for this compose hash
function removeComposeHash(bytes32 composeHash) external onlyOwner {
    allowedComposeHashes[composeHash] = false;
    emit ComposeHashRemoved(composeHash);
}
```

When a TEE instance boots, the KMS calls `isAppAllowed(bootInfo)` which checks `allowedComposeHashes[bootInfo.composeHash]`. If `false`, the KMS refuses to derive keys and the instance can't start.

**Impact:** The 6 old compose hashes (including early testing versions with potentially different security properties) could be redeployed. The operator should call `removeComposeHash()` for all non-current hashes.

**Note:** Duplicate `ComposeHashAdded` events for the same hash (e.g., hash #7 added 4 times) likely result from each instance registration triggering the event, or from redeployments. The mapping is idempotent — adding the same hash twice has no additional effect.

**Audit gap:** The raw `app_compose` JSON for the 6 old compose hashes is not available. The on-chain contract stores only the `bytes32` hash, not the content. The deployed `app_compose` is generated at deploy time by `phala deploy` (which transforms the git docker-compose template, replacing `build:` contexts with `image:` refs and adding dstack metadata). Without the operator's deploy logs or the raw app_compose for each version, we cannot audit what code those old hashes authorized. Calling `removeComposeHash()` on all non-current hashes would eliminate this gap.

---

## On-Chain Contract Analysis

**Contract:** `0xbc81bb624b69729a3fb6e51e08426e8b726be0c7` on Base
**Type:** `DstackApp` (UUPS upgradeable proxy)
**Source:** Not verified on Basescan (same pattern as NEAR chat audit)
**RPC:** `https://base-mainnet.public.blastapi.io`

The contract implements:
- `addComposeHash(bytes32)` / `removeComposeHash(bytes32)` — manage allowed app versions
- `addDevice(bytes32)` / `removeDevice(bytes32)` — manage allowed hardware
- `isAppAllowed(AppBootInfo)` — called by KMS at boot to authorize TEE instances
- `disableUpgrades()` — permanently prevents contract proxy upgrades
- `allowAnyDevice` — boolean, when true skips device allowlist check

**Governance note:** All mutating functions are `onlyOwner`. The contract owner has full control over which compose hashes and devices are authorized. This is standard for Stage 1 but means the operator remains trusted for upgrade governance.

---

## Live Deployment Data (2026-03-03)

### Instances

| Instance | Type | ID | RTMR3 |
|----------|------|----|-------|
| main-tee | Main | `66b52186...` | `d8f217bd...` |
| auth-worker | Worker | `83e8ce96...` | `a80bda1b...` |

**Shared values** (both instances):
- Compose hash: `4dfce6330424eddc4c3a607ce6766b3d080427608e3843b6283e12fca78fcd52`
- MRTD: `f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077`
- RTMR1: `19d16ecd33220ee15965b4fb28a0661e85ec4cad0a20d920bf4028f58ad014b262af3c9b0530f283e7d032e7bdca6308`
- RTMR2: `05ac95f479e23db627217ce58b2587483c9ee4f374a7d8ebee3b812b8cfd8fd8fca04696369c33bd5279590d83e713c0`
- OS Image Hash: `2d24d302cc8686d6a0ece71a6afef55c506bc8591e3bcc1ec3eb5323d77582c4`
- Device ID: `c84e73c6...` (same physical machine)

**Different per instance:** RTMR0, RTMR3, MR Aggregated, Instance ID (expected — unique per VM)

### allowed_envs (19 variables)

```
AUTH_ONLY_MODE                   # Role selection (main vs auth-only)
XORDI_API_KEY                    # Backend auth
XORDI_API_URL                    # Backend URL (encrypted blobs only)
MIGRATION_TRIGGER_KEY            # Cookie migration
PROXY_MODE                       # VPN routing
WG_PROXY_USER                    # VPN auth
WG_PROXY_PASS                    # VPN auth
WIREGUARD_HOST                   # VPN config
WIREGUARD_BASE_PORT              # VPN config
MIN_POOL_SIZE                    # Browser pool
DOCKER_NETWORK                   # Container networking
NEKO_DESKTOP_SCREEN              # Browser display
NEKO_DESKTOP_SCALING             # Browser display
BROWSER_CPU_LIMIT                # Resource limits
BROWSER_MEMORY_LIMIT             # Resource limits
BROWSER_MEMORY_RESERVATION       # Resource limits
ENABLE_DEBUG_SCREENSHOTS         # Debug feature
DEBUG_SCREENSHOT_TTL_MS          # Debug config
DEBUG_SCREENSHOT_BASE_URL        # Debug config
```

**Removed from v1.1.2:** `TOKSCOPE_ENCLAVE_IMAGE`, `TOKSCOPE_BROWSER_MANAGER_IMAGE`, `TOKSCOPE_BROWSER_IMAGE`, `FALLBACK_KEY_MATERIAL`

---

## Verification Checklist

| Check | Status | Notes |
|-------|--------|-------|
| Docker images pullable | ✅ | All 3 images public on GHCR |
| Image digests in compose | ✅ | Hardcoded `@sha256:` — bound to compose hash |
| Compose hash verifiable | ✅ | Can be reproduced from raw app_compose string |
| Image digests match running containers | ✅ | 8090 container list confirms deployed digests |
| Base KMS active | ✅ | Both instances report `kms_type: base` |
| Both instances share compose hash | ✅ | `4dfce633...` on both |
| Auth worker properly restricted | ✅ | Data endpoints return 503 |
| Source branch identified | ✅ | `deployed-v1.1.3F`, HEAD `bbc38c5d` |
| Image tags traceable to commits | ⚠️ | Tags are build hashes, not commit SHAs |
| Trust Center attestation | ⏳ | Report pending generation |
| Reproducible build end-to-end | ❓ | Not tested this revision |

---

## Path Forward

| Item | Status | Notes |
|------|--------|-------|
| ~~Hardcode image digests~~ | ✅ | Done |
| ~~Migrate to Base KMS~~ | ✅ | Done |
| ~~Remove image vars from allowed_envs~~ | ✅ | Done |
| Trust Center report generation | ⏳ | Awaiting automatic generation |
| OCI image labels | Not started | Tags are build hashes, no `org.opencontainers.image.revision` |
| Reproducible build verification | Not tested | Build infra from v1.1.2 presumably still in place |
| Git tag for deployment | Suggested | Tag `deployed-v1.1.3F` branch commit for reference |

**Stage 1 is achieved.** The two blocking issues (hidden image refs, no transparency log) are both resolved. Remaining items are incremental improvements.

---

## References

- Release Dashboard: https://prod2-release.xordi.io/
- Release API: https://staging-api.xordi.io/api/release/current
- Trust Center: https://trust.phala.com/app/bc81bb624b69729a3fb6e51e08426e8b726be0c7
- Main TEE 8090: https://66b5218676531da2be9966adb0eb9c8bc901f183-8090.dstack-base-prod5.phala.network/
- Auth Worker 8090: https://83e8ce96dbef6c03c5a0e1c5f66309271c9cdfa6-8090.dstack-base-prod5.phala.network/
- Source: https://github.com/Account-Link/teleport-tokscope/tree/deployed-v1.1.3F
- Branch HEAD: https://github.com/Account-Link/teleport-tokscope/commit/bbc38c5d2a68
- Previous Deployment (decommissioned): App ID `f44389ef...` on `dstack-pha-prod9`

---

## Revision History

| Date | Version | Changes |
|------|---------|---------|
| 2026-02-12 | v1.0 | Initial audit of v1.1.0 (commit 58ad3f2) |
| 2026-02-21 | v1.1 | Updated for v1.1.2 (commit 535fba0), noted reproducible build improvements |
| 2026-03-03 | v2.0 | Complete redeployment: new app ID, Base KMS, hardcoded image digests, multi-instance architecture. **Stage 0 → Stage 1.** |
