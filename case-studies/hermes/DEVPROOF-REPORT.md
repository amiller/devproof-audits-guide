# Hermes TEE Best Practices Audit

**Audit Date:** 2026-02-10
**Auditor:** @socrates1024 (with Claude Opus)
**App ID:** `db82f581256a3c9244c4d7129a67336990d08cdf`
**Comparison:** [xordi-release-process](https://github.com/Account-Link/xordi-release-process/)

---

## Executive Summary

Hermes runs in a TEE on Phala Cloud with solid architecture for protecting secrets and pending entries. However, several gaps exist in the **verification chain** and **transparency logging** that prevent users from independently auditing what code has run.

| Category | Status | Notes |
|----------|--------|-------|
| TEE Attestation | ✅ PASS | KMS validates, Trust Center shows 30 objects |
| Hardware Isolation | ✅ PASS | Intel TDX, keys never leave enclave |
| Transparency Log | ❌ FAIL | Pha KMS - no public upgrade events |
| Reproducible Builds | ❌ FAIL | Unpinned base images, npm ci |
| Source-to-Image Chain | ⚠️ PARTIAL | SHA tags exist but image not pinned by digest |
| Upgrade History | ❌ FAIL | No record of which versions deployed when |

---

## Current Deployment Analysis

### What's Attested (from 8090 page)

```
compose_hash:   7bd518dfe5aa1c4a00c36fa580dfe14b891b77ff2c6e59c51d3f723db3983152
os_image_hash:  e18f5407b33e3c9ce7db827f2d351c98cc7a3fe9814ae6607280162e88bec010
device_id:      05c73429bc3868cca111bcf158ad59167b1f0c0d2dd8e0b98839d59e5cf0222d
key_provider:   kms (Phala)
```

### Image History (Docker Hub)

30 versions pushed since Jan 16, 2026. Current: `hermes:126d663` (sha256:5dc4f101...)

**Gap:** No record of which versions were actually deployed to the TEE, or when.

---

## Gaps & Recommendations

### 1. No Transparency Log (CRITICAL)

**Problem:** Hermes uses Pha KMS which does not publish upgrade events publicly.

**Impact:** Users cannot verify deployment history. An operator could:
1. Deploy malicious code
2. Exfiltrate data
3. Redeploy legitimate code
4. No evidence trail exists

**Fix:** Switch to Base on-chain KMS. From xordi docs:
> "To be publicly visible you need to use onchain kms... The pha kms is reserved for other customers who don't want to publish the update events"

**Implementation:**
```bash
# Deploy with Base KMS
phala cvms upgrade --app-id $APP_ID --compose docker-compose.yml --kms base
```

This creates an on-chain record for every compose hash update.

---

### 2. Image Reference by Tag, Not Digest

**Problem:** Current compose references image by git tag:
```yaml
image: docker.io/generalsemantics/hermes:126d663
```

**Impact:** The tag can be overwritten. The attestation includes `compose_hash` but not the Docker image digest directly.

**Fix:** Pin to digest in compose:
```yaml
image: docker.io/generalsemantics/hermes@sha256:5dc4f101c5f031710ca53fee97c57336b1b5f85d8044bdaa4d19031196a1466e
```

**Note:** dstack-ingress already does this correctly:
```yaml
image: socrates1024/dstack-ingress:20251231-namecheap-fix@sha256:a11cdeaa58efc75f...
```

---

### 3. Non-Reproducible Builds

**Problem:** Dockerfile uses unpinned images:
```dockerfile
FROM node:20-alpine  # Can change any time
RUN npm ci           # Depends on registry state
```

**Impact:** Same source can produce different image hashes. Cannot verify builds independently.

**Fix:**
```dockerfile
# Pin base image to digest
FROM node:20-alpine@sha256:<specific-digest>

# Verify lockfile integrity
COPY package-lock.json ./
RUN npm ci --ignore-scripts
```

**Advanced:** Use Nix or `apko` for fully reproducible builds.

---

### 4. No Source-to-Image Chain Documentation

**Problem:** GitHub Actions outputs digest, but no documented link to:
- Git commit SHA
- Docker image digest
- TEE compose hash
- Deployment timestamp

**Impact:** Users cannot trace running code back to source.

**Fix:** Add release checklist (see xordi RELEASE-CHECKLIST.md):

| Item | Value |
|------|-------|
| Git Commit SHA | |
| Docker Image Digest | |
| Compose Hash | |
| App ID | |
| Trust Center URL | |
| On-Chain TX Hash | |
| Deployment Timestamp | |

---

### 5. Consider GHCR for Image Hosting

**Current:** Docker Hub (`generalsemantics/hermes`)

**Recommended:** GitHub Container Registry (`ghcr.io/jameslbarnes/hermes`)

**Benefits:**
- Automatic Sigstore signatures via GitHub Actions
- Build provenance attestations (SLSA)
- Direct link between commit and image
- No separate Docker Hub credentials

**Implementation:** Update `.github/workflows/build.yml`:
```yaml
env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}
```

---

### 6. Missing VERIFICATION-REPORT.md

**Problem:** No public document explaining how to verify the deployment.

**Fix:** Create `VERIFICATION-REPORT.md` following xordi pattern:
- Trust Center URL
- Current compose hash
- Verification steps for third parties
- Trust boundaries diagram
- Known gaps and mitigations

---

## HTTP Layer Issues (Lower Priority)

Also identified during audit - not TEE-specific but worth fixing:

| Issue | Severity | Location |
|-------|----------|----------|
| Hardcoded JWT secret fallback | HIGH | http.ts:691 |
| No rate limiting | HIGH | All endpoints |
| No request body size limit | HIGH | http.ts:6263 |
| Debug DNS endpoints unprotected | HIGH | http.ts:6106 |
| Container runs as root | MEDIUM | Dockerfile |
| CORS `Access-Control-Allow-Origin: *` | MEDIUM | http.ts:3277 |

See full HTTP audit in separate issue.

---

## Bug Found in Logs

Missing Firestore composite index causing query failures:

```
Error: 9 FAILED_PRECONDITION: The query requires an index.
```

**Fix:** Create composite index for `inReplyTo + timestamp` on the `entries` collection:
https://console.firebase.google.com/v1/r/project/hivemind-476519/firestore/indexes?create_composite=...

---

## Persistent Private Data

| Data | Location | Encrypted | Survives Restart |
|------|----------|-----------|------------------|
| Pending entries | `/data/pending-recovery.json` | ✅ TEE volume | ✅ (graceful) |
| Secret keys | Memory only | N/A | ❌ |
| Published entries | Firestore | ❌ Public | ✅ |
| TLS certs | `cert-data` volume | ✅ TEE volume | ✅ |

The `hermes-data:/data` and `cert-data` volumes use ZFS on encrypted TEE storage.

Verified from logs:
```
[Storage] Restored 5 pending entries, 0 pending conversations
[Recovery] Volume OK: /data is writable - pending entries will survive restarts
```

---

## Trust Center Analysis

**URL:** https://trust.phala.com/app/db82f581256a3c9244c4d7129a67336990d08cdf

### What Trust Center Shows

| Field | Value |
|-------|-------|
| App Created | 2025-12-14 20:34:03 UTC |
| Last Updated | 2026-02-10 23:55:00 UTC |
| Last Attestation | 2026-02-10 01:17:29 UTC |
| Status | Completed (30 objects verified) |
| dstack Version | 0.5.5 |

### What Trust Center Does NOT Show

| Question | Status |
|----------|--------|
| Upgrade history | ❌ Not exposed |
| Previous compose hashes | ❌ Not stored publicly |
| When `126d663` was deployed | ❌ Unknown |
| What version ran on Jan 20th | ❌ Cannot answer |

**The Trust Center only shows current state, not history.** The `updated` timestamp tells us *something* changed on 2026-02-10, but not what previous versions ran or when.

### Pha KMS vs Base KMS

| Feature | Pha KMS (current) | Base KMS (recommended) |
|---------|-------------------|------------------------|
| Current attestation | ✅ | ✅ |
| Key derivation in TEE | ✅ | ✅ |
| **Public upgrade log** | ❌ | ✅ On-chain events |
| **Retroactive audit** | ❌ | ✅ Query any block |

With Base KMS, every `phala cvms upgrade` emits an on-chain event with the new compose_hash. This enables:
- "What compose_hash was active at block X?"
- Trace compose_hash → docker-compose.yml → image tag → git commit
- Full retrospective audit even after app shutdown

---

## Recommended Priority

### Immediate (Required for Trust)
1. [ ] Switch to Base on-chain KMS
2. [ ] Pin Docker image by digest in compose
3. [ ] Create VERIFICATION-REPORT.md

### Short-Term
4. [ ] Pin base images in Dockerfile
5. [ ] Migrate to GHCR
6. [ ] Add release checklist

### Medium-Term
7. [ ] Achieve fully reproducible builds
8. [ ] Document upgrade history on-chain
9. [ ] Add `USER node` to Dockerfile

---

## Verification Flow (Target State)

```
SOURCE CODE (GitHub)
       │
       │ git commit SHA
       ▼
DOCKER IMAGE (GHCR)
       │
       │ image@sha256:... in compose
       ▼
DOCKER-COMPOSE.YML
       │
       │ sha256sum
       ▼
COMPOSE HASH ◄──────────── ATTESTATION (port 8090)
       │                          │
       │                          │ TDX Quote
       ▼                          ▼
BASE CONTRACT ◄──────────── INTEL TDX
(transparency log)          (hardware root)
```

---

## References

- [Trust Center](https://trust.phala.com/app/db82f581256a3c9244c4d7129a67336990d08cdf) (if exists)
- [8090 Metadata](https://db82f581256a3c9244c4d7129a67336990d08cdf-8090.dstack-pha-prod9.phala.network/)
- [xordi-release-process](https://github.com/Account-Link/xordi-release-process/)
- [dstack Verification Docs](https://docs.phala.com/dstack/verification)
