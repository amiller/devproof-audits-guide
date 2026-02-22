# Hermes TEE Best Practices Audit

**Initial Audit:** 2026-02-10
**Updated:** 2026-02-20
**Auditor:** @socrates1024 (with Claude Opus)
**App ID:** `db82f581256a3c9244c4d7129a67336990d08cdf`
**Custom Domain:** `hermes.teleport.computer`
**Comparison:** [xordi-release-process](https://github.com/Account-Link/xordi-release-process/)

---

## Executive Summary

Hermes runs in a TEE on Phala Cloud with solid architecture for protecting secrets and pending entries. However, several gaps exist in the **verification chain** and **transparency logging** that prevent users from independently auditing what code has run.

**2026-02-20 update:** The compose hash has changed since the initial audit, confirming active upgrades with no public record. CT log and DNS analysis provides baseline data for ongoing monitoring.

**2026-02-22 correction:** The domain binding "gap" previously reported was overstated. CT logging is mandatory for all publicly trusted certs, so domain redirect attacks are always detectable. See [corrected analysis](../../framework/DOMAIN-BINDING-GAP.md).

| Category | Status | Notes |
|----------|--------|-------|
| TEE Attestation | ✅ PASS | KMS validates, Trust Center shows 30 objects |
| Hardware Isolation | ✅ PASS | Intel TDX, keys never leave enclave |
| Transparency Log | ❌ FAIL | Pha KMS - no public upgrade events |
| Reproducible Builds | ❌ FAIL | Unpinned base images, npm ci |
| Source-to-Image Chain | ⚠️ PARTIAL | SHA tags exist but image not pinned by digest |
| Upgrade History | ❌ FAIL | No record of which versions deployed when |
| Domain Binding | ✅ PASS | Custom domain redirect detectable via mandatory CT logging |

---

## Current Deployment Analysis

### What's Attested (from 8090 page)

As of 2026-02-20:

```
compose_hash:   a8105997bfe1010d620679c18894aec23b5056b2ac1311048810ce14271362e3
os_image_hash:  e18f5407b33e3c9ce7db827f2d351c98cc7a3fe9814ae6607280162e88bec010
instance_id:    84a195b87dacc0d7e3fbd501d9d02e38194abbe9
key_provider:   kms (Phala)
dstack_version: 0.5.5
kernel:         6.9.0-dstack
image:          docker.io/generalsemantics/hermes:a3cf0e6
```

### Compose Hash Change Detected

| Field | Feb 10 (initial audit) | Feb 20 (follow-up) | Changed? |
|-------|----------------------|---------------------|----------|
| compose_hash | `7bd518...3152` | `a81059...62e3` | **YES** |
| os_image_hash | `e18f54...c010` | `e18f54...c010` | No |
| image tag | `hermes:126d663` | `hermes:a3cf0e6` | **YES** |
| dstack version | 0.5.5 | 0.5.5 | No |

The compose hash changed because the image tag was updated from `126d663` (pushed Feb 7) to `a3cf0e6` (pushed Feb 18). Because Hermes uses Pha KMS, there is **no public record** of when this upgrade happened or what intermediate versions may have been deployed.

### Image History (Docker Hub)

50+ tags pushed since Jan 14, 2026. Active development with frequent commits.

Selected timeline:

| Date | Tag | Digest (prefix) |
|------|-----|-----------------|
| 2026-01-14 | `c4abb6a` | `004cb5...` |
| 2026-01-16 | `659d768` | `7af949...` |
| 2026-01-22 | `63fb71b` | `6a656a...` |
| 2026-02-02 | `v4`/`latest` | `3fbe66...` |
| 2026-02-07 | `126d663` ← initial audit | `5dc4f1...` |
| 2026-02-12 | `aa6e1b4` | `8e5d51...` |
| 2026-02-17 | `55fa7a7`, `a3c16f0`, `4c86882` | various |
| 2026-02-18 | `a3cf0e6` ← current | `6df525...` |

**Gap:** No record of which of these 50+ versions were actually deployed to the TEE, or when. Any of them could have been deployed and reverted without evidence.

---

## Custom Domain Analysis (NEW — 2026-02-20)

### DNS Configuration

```
hermes.teleport.computer
  CNAME → db82f581256a3c9244c4d7129a67336990d08cdf-3000.dstack-pha-prod9.phala.network

_dstack-app-address.hermes.teleport.computer
  TXT   → "db82f581256a3c9244c4d7129a67336990d08cdf:443"
```

The CNAME points to the app's port 3000 (raw HTTP), while the `_dstack-app-address` TXT record directs the dstack gateway to route TLS traffic to port 443 (dstack-ingress sidecar inside the TEE).

### Domain Binding Gap

The mapping from `hermes.teleport.computer` to app_id `db82f5...` is controlled entirely by DNS. The domain owner can change the `_dstack-app-address` TXT record at any time to point to a different app_id. The dstack gateway follows DNS without any on-chain or attested verification of the binding.

This is a **dstack architectural gap**, not specific to Hermes. See [DOMAIN-BINDING-GAP.md](../../framework/DOMAIN-BINDING-GAP.md) for full analysis.

**Attack scenario:**
1. Change TXT record → different app_id (malicious TEE app)
2. Gateway routes `hermes.teleport.computer` to the malicious app
3. Malicious app obtains a Let's Encrypt cert (it's a valid TEE)
4. Revert TXT record → original app_id
5. No on-chain evidence

### Certificate Transparency Analysis

4 certificates ever issued for `hermes.teleport.computer` (all Let's Encrypt):

| Issued | Expires | Issuer | Serial (prefix) |
|--------|---------|--------|-----------------|
| 2025-12-31 18:37 | 2026-03-31 | LE E7 | `06ffce...` |
| 2026-01-02 01:21 | 2026-04-02 | LE E8 | `05adf0...` |
| 2026-01-02 02:24 | 2026-04-02 | LE E7 | `0629e6...` |
| 2026-01-02 02:41 | 2026-04-02 | LE E7 | `054f46...` |

All 4 certs were issued within a ~32 hour window (Dec 31 – Jan 2), consistent with initial setup. No new certs issued since Jan 2 — no evidence of domain redirect attacks.

**CT monitoring recommendation:** Set up alerts on [crt.sh](https://crt.sh/?q=hermes.teleport.computer) or [Certspotter](https://sslmate.com/certspotter/) for new certificate issuance on `hermes.teleport.computer`. A new cert outside the normal 60-day renewal window is a red flag.

### CAA Records

`phala.network` has restrictive CAA:
```
CAA 0 issue    "letsencrypt.org;validationmethods=dns-01;accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/2677326931"
CAA 0 issuewild "letsencrypt.org;validationmethods=dns-01;accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/2677326931"
```

Only Let's Encrypt, only DNS-01 validation, pinned to a specific ACME account. This prevents non-TEE impersonation of the built-in `*.phala.network` subdomains. However, CAA on `phala.network` does **not** protect `hermes.teleport.computer` — that domain's CAA is controlled by whoever owns `teleport.computer`.

### Phala Cloud Infrastructure (from CT Logs)

CT log enumeration of `*.phala.network` wildcard certs revealed 47 dstack clusters:

- **By chain:** `dstack-pha-*` (Phala), `dstack-base-*` (Base), `dstack-eth-*` (Ethereum)
- **By purpose:** prod, GPU, testnet, partner integrations (Ritual, Vana, Zama, Succinct)
- **Hermes cluster:** `dstack-pha-prod9` — 2 certs issued, live since Sept 2025

Individual app IDs are **not** visible in CT logs because clusters use wildcard certs. CT enumeration works for custom domains only.

---

## Gaps & Recommendations

### 1. No Transparency Log (CRITICAL)

**Problem:** Hermes uses Pha KMS which does not publish upgrade events publicly.

**Impact:** Users cannot verify deployment history. An operator could:
1. Deploy malicious code
2. Exfiltrate data
3. Redeploy legitimate code
4. No evidence trail exists

**Confirmed 2026-02-20:** The compose hash changed between Feb 10 and Feb 20 (image `126d663` → `a3cf0e6`). No public record of when this upgrade occurred.

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
image: docker.io/generalsemantics/hermes:a3cf0e6
```

**Impact:** The tag can be overwritten. The attestation includes `compose_hash` but not the Docker image digest directly.

**Fix:** Pin to digest in compose:
```yaml
image: docker.io/generalsemantics/hermes@sha256:6df5258940ac2a705d77f0a4c045efcf215b1e25b8eed737d0705552b3a31c3a
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

### 7. Custom Domain Trust Model (CORRECTED 2026-02-22)

**~~Original finding (retracted):~~** Previously reported as a domain binding "gap" where redirect attacks leave no evidence.

**Corrected analysis:** A domain redirect attack requires the attacker to obtain a new TLS cert (the old cert's private key is locked in the original TEE's encrypted volume). All publicly trusted CAs must log to CT. Therefore domain redirect attacks are **always detectable** via CT monitoring.

**Trust tiers:**
- **Browser users:** CT monitoring detects redirect attacks (set up Certspotter alerts for `hermes.teleport.computer`)
- **Client SDKs:** Should perform attested TLS, making the domain just a discovery mechanism

**Inherent limit:** The domain registrar can seize `teleport.computer`. This is the standard DNS trust boundary, not a dstack-specific issue.

See [Custom Domain Trust Model](../../framework/DOMAIN-BINDING-GAP.md) for full analysis.

---

### 8. Evidences Are Ephemeral (NEW 2026-02-22)

**Problem:** The `/evidences/` endpoint only serves current state. On redeploy, the old `quote.json`, cert PEM, and `sha256sum.txt` are overwritten. No history is preserved.

**What `/evidences/` contains:**

| File | Purpose |
|------|---------|
| `quote.json` | TDX attestation quote; `report_data` = SHA256(sha256sum.txt) |
| `sha256sum.txt` | Manifest: SHA256 of acme-account.json + cert PEM |
| `cert-hermes.teleport.computer.pem` | TLS cert (public key bound to quote via manifest) |
| `acme-account.json` | ACME account URI (LE acct 2928213986) |

**Binding chain:** TDX Quote → report_data → SHA256(manifest) → SHA256(cert PEM) → TLS public key. This proves the TLS cert was issued from inside this TEE. Note: this uses a custom path (plain SHA256, zero-padded), not dstack's standard `QuoteContentType::RaTlsCert` (SHA512-tagged).

**Impact:** Even with Base KMS logging compose_hash changes on-chain, the TLS cert attestation binding is lost on redeploy. An auditor cannot verify which TLS cert was attested at a previous point in time.

**Fix:** Commit evidences to git on every redeploy:
```
evidences/
  2026-01-02/
    quote.json
    sha256sum.txt
    cert-hermes.teleport.computer.pem
    acme-account.json
  2026-02-18/
    ...
```

This is complementary to Base KMS: on-chain gives you compose_hash history, git gives you the full attestation artifacts.

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
| When `a3cf0e6` was deployed | ❌ Unknown |
| What version ran on Jan 20th | ❌ Cannot answer |
| Domain binding history | ❌ Not tracked |

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
4. [ ] Set up CT monitoring for `hermes.teleport.computer`
5. [ ] Commit `/evidences/` snapshots to git on every redeploy (quote.json, sha256sum.txt, cert PEM, acme-account.json)

### Short-Term
6. [ ] Pin base images in Dockerfile
7. [ ] Migrate to GHCR
8. [ ] Add release checklist
9. [ ] Set up DNS monitoring for `_dstack-app-address` TXT record

### Medium-Term
9. [ ] Achieve fully reproducible builds
10. [ ] Document upgrade history on-chain
11. [ ] Add `USER node` to Dockerfile

### Optional Enhancement
12. [ ] Embed app_id in TLS certs for richer CT audit trail (see [Custom Domain Trust Model](../../framework/DOMAIN-BINDING-GAP.md))

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
       │
       │
       ▼
CUSTOM DOMAIN (hermes.teleport.computer)
       │
       │ DNS TXT → app_id (mutable, but redirect requires new cert → CT logged)
       ▼
USER BROWSER (CT monitoring) / CLIENT SDK (attested TLS)
```

---

## Audit Log

| Date | Event |
|------|-------|
| 2026-02-10 | Initial audit. compose_hash `7bd518...`, image `hermes:126d663` |
| 2026-02-20 | Follow-up. compose_hash changed to `a81059...`, image now `hermes:a3cf0e6`. CT log analysis: 4 certs issued (Dec 31 – Jan 2), no new issuance since. DNS analysis: domain binding via mutable TXT record. Originally identified as "domain-binding architectural gap." |
| 2026-02-22 | Retraction: domain binding "gap" was overstated. CT logging is mandatory for all publicly trusted certs, so domain redirect attacks always produce evidence. Reframed as trust model description with two tiers (browser/CT vs client SDK/attested TLS). New finding: `/evidences/` are ephemeral — quote.json and cert PEM overwritten on redeploy. report_data binding chain verified: TDX Quote → SHA256(manifest) → SHA256(cert PEM) → TLS pubkey. Recommend committing evidences to git on every release. |

---

## References

- [Trust Center](https://trust.phala.com/app/db82f581256a3c9244c4d7129a67336990d08cdf)
- [8090 Metadata](https://db82f581256a3c9244c4d7129a67336990d08cdf-8090.dstack-pha-prod9.phala.network/)
- [CT Logs for hermes.teleport.computer](https://crt.sh/?q=hermes.teleport.computer)
- [Domain Binding Gap Analysis](../../framework/DOMAIN-BINDING-GAP.md)
- [xordi-release-process](https://github.com/Account-Link/xordi-release-process/)
- [dstack Verification Docs](https://docs.phala.com/dstack/verification)
- [dstack Zero-Trust TLS Whitepaper](https://docs.phala.com/dstack/design-documents/whitepaper#zero-trust-tls-protocol)
