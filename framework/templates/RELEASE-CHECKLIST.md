# DevProof Release Checklist

**Purpose:** Prescriptive release process ensuring transparency and attestation for every deployment.

**Key Principle:** A deployment is NOT complete until transparency logging is verified.

---

## Pre-Release

### 1. Code Preparation

- [ ] All changes committed to release branch
- [ ] Commit SHA: `____________________________________________`
- [ ] CI passes (tests, linting, security scan)
- [ ] No secrets in source code
- [ ] No configurable URLs that handle user data (hardcode them)

### 2. Docker Image Build

**Pin base images by digest, set reproducibility flags.**

```bash
export SHA=$(git rev-parse --short HEAD)
export SOURCE_DATE_EPOCH=0

docker buildx build \
  --build-arg SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH \
  --output type=registry,rewrite-timestamp=true \
  -t yourorg/app:$SHA \
  .
```

- [ ] Base image pinned: `FROM node:20-alpine@sha256:...`
- [ ] `SOURCE_DATE_EPOCH` set for reproducibility
- [ ] Image pushed to registry
- [ ] Record image digest: `sha256:____________________________________________`

### 3. Compose File Verification

- [ ] Image uses digest (not tag): `image: yourorg/app@sha256:...`
- [ ] No `${VAR}` for URLs that handle user data
- [ ] Review `allowed_envs` - no security-sensitive variables
- [ ] KMS set to `base` for transparency: `x-dstack: kms: base`

---

## Deployment

### 4. Deploy to dstack/Phala Cloud

**CRITICAL: Use Base on-chain KMS for transparency logging**

```bash
# New deployment
phala cvms create \
  --name app-prod \
  --compose docker-compose.yml \
  --vcpu 4 \
  --memory 8192

# OR upgrade existing
phala cvms upgrade \
  --app-id <APP_ID> \
  --compose docker-compose.yml
```

- [ ] Deployment command succeeded
- [ ] Record App ID: `____________________________________________`
- [ ] Record CVM ID: `____________________________________________`

### 5. Health Check

- [ ] Service responding: `curl https://<domain>/health`
- [ ] Basic functionality verified
- [ ] No errors in first 5 minutes of logs

---

## Transparency Verification (MANDATORY)

**A deployment is NOT complete until these steps are verified.**

### 6. Trust Center

Visit: `https://trust.phala.com/app/<APP_ID>`

- [ ] Status: "Completed"
- [ ] Attestation timestamp is after deployment
- [ ] Compose hash matches expected

### 7. On-Chain Verification

**This is the critical step for Stage 1 compliance.**

```bash
# Check compose hash on Base
cast call $APP_CONTRACT "getComposeHashes()" --rpc-url $BASE_RPC

# Query upgrade events
cast logs --address $APP_CONTRACT --from-block $DEPLOY_BLOCK "ComposeHashAdded(bytes32)" --rpc-url $BASE_RPC
```

- [ ] Compose hash appears in on-chain registry
- [ ] Transaction hash: `____________________________________________`
- [ ] **If Pha KMS:** ⚠️ STOP - Pha KMS does not log publicly. Switch to Base KMS.

### 8. Document Chain of Trust

Record in DEPLOYMENTS.md:

| Item | Value |
|------|-------|
| Git Commit SHA | |
| Docker Image Digest | |
| Compose Hash | |
| App ID | |
| Trust Center URL | |
| Base TX Hash | |
| Timestamp | |

---

## Post-Release

### 9. Update Documentation

- [ ] Update DEPLOYMENTS.md with new entry
- [ ] Update DEVPROOF-REPORT.md if gaps changed
- [ ] Create GitHub Release with attestation links

### 10. Notify Stakeholders

- [ ] Post deployment notice with:
  - Commit SHA
  - Trust Center link
  - BaseScan link to compose hash event

---

## Emergency Rollback

If issues discovered:

1. **Do NOT panic-deploy** - creates unverified code
2. Identify last known-good compose hash
3. Deploy that specific version
4. Follow FULL checklist (including transparency)
5. Document the incident

---

## Quick Reference

```bash
# Check current deployment
phala cvms info --app-id <APP_ID>

# Get attestation
phala cvms attestation --app-id <APP_ID>

# Check 8090 metadata
curl https://<APP_ID>-8090.<cluster>.phala.network/

# Query on-chain compose hashes
cast call $APP_CONTRACT "getComposeHashes()" --rpc-url https://sepolia.base.org
```

---

## Why This Process Matters

Without this checklist:
- Deployments happen without transparency logging
- No evidence of what code is running
- Cannot prove developer is constrained

With this checklist:
- Every deployment creates on-chain record
- Users can verify upgrade history
- Evidence exists that code matches source
- **Stage 1 DevProof achieved**
