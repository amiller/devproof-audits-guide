# [App Name] TEE Verification Report

**Report Date:** YYYY-MM-DD
**App ID:** `<app-id>`
**Domain:** `<app-domain>`
**dstack Version:** X.X.X

---

## Quick Status

| Check | Status | Notes |
|-------|--------|-------|
| TEE Attestation | PASS/FAIL | Trust Center verification |
| Hardware Integrity | PASS/FAIL | Intel TDX quote |
| Transparency Log | PASS/FAIL | Base KMS = PASS, Pha KMS = FAIL |
| Reproducible Build | PASS/FAIL | Can rebuild from source? |
| Source Provenance | PASS/FAIL | Commit → image → compose chain documented? |

---

## What's Verified

### Cryptographically Proven
- Hardware isolation (Intel TDX enclave)
- Specific code running (MRTD, RTMRs match compose hash)
- KMS key binding (keys derived in TEE)

### NOT Proven (Trust Required)
- Code behavior (what does it actually do?)
- Source-to-image chain (is the source what's running?)
- Upgrade history (what ran before?)

---

## Current Gaps

### Gap 1: [Title]

**Problem:** [Description]

**Impact:** [What can go wrong]

**Fix:** [How to address]

---

## Trust Boundaries

```
              TRUSTED COMPUTE BASE (TCB)
    ┌─────────────────────────────────────────────┐
    │                                             │
    │   ┌───────────────────────────────────┐     │
    │   │         Intel TDX Hardware        │     │
    │   │   ┌───────────────────────────┐   │     │
    │   │   │      Your App Enclave     │   │     │
    │   │   │                           │   │     │
    │   │   └───────────────────────────┘   │     │
    │   │               │                   │     │
    │   │       ┌───────┴───────┐           │     │
    │   │       │  dstack SDK   │           │     │
    │   │       │  :8090 meta   │           │     │
    │   │       └───────────────┘           │     │
    │   └───────────────────────────────────┘     │
    │                   │                         │
    │           ┌───────┴───────┐                 │
    │           │  Phala KMS    │                 │
    │           └───────────────┘                 │
    └─────────────────────────────────────────────┘
```

---

## Verification Steps

### 1. Check Trust Center

Visit: https://trust.phala.com/app/<app-id>

- [ ] Status shows "Completed"
- [ ] Attestation is recent

### 2. Check 8090 Metadata

```bash
curl https://<app-id>-8090.<cluster>.phala.network/
```

- [ ] compose_hash matches expected
- [ ] dstack version is current

### 3. Review Source

```bash
git clone <repo-url>
# Review for: configurable URLs, dev fallbacks, etc.
```

---

## References

- Trust Center: https://trust.phala.com/app/<app-id>
- 8090 Metadata: https://<app-id>-8090.<cluster>.phala.network/
- Source Repository: <repo-url>
