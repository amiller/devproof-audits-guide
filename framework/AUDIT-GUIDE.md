# dstack App Audit Guide

Quick reference for auditing dstack/Phala TEE applications.

## Step 0: Fetch Deployed Configuration

**Important:** You don't need account access to audit a dstack app. All metadata is public via the 8090 endpoint.

```bash
# Verify compose hash and fetch app_compose
./tools/verify-compose-hash.py <app-id> <cluster>

# Example:
./tools/verify-compose-hash.py f44389ef4e953f3c53847cc86b1aedc763978e83 dstack-pha-prod9
```

This gives you:
- `compose_hash` - the attested configuration hash
- `app_compose` - the full deployed configuration including:
  - `docker_compose_file` - what containers are running
  - `allowed_envs` - what the operator can configure
  - `pre_launch_script` - what runs before the app starts
  - `features`, `kms_enabled`, etc.

**Note:** `phala cvms attestation` only works for apps you own - useless for third-party auditing.

For full attestation verification, use the trust-center:
- UI: `https://trust.phala.com/app/<app-id>`
- API: `@phala/dstack-verifier` package

## The Core Question

**Can the operator exfiltrate user data or compromise privacy guarantees?**

TEE protects against the cloud provider, but the *operator* (whoever deploys the docker-compose) controls:
- Environment variables in `allowed_envs`
- Secrets injected at runtime
- Which docker image version to deploy

## Critical Checks

### 1. Configuration Control (Most Common Vulnerability)

**Pattern**: Any URL that routes user data MUST be hardcoded in docker-compose.yml, NOT in allowed_envs or code defaults.

```bash
# Find all configurable URLs in code
grep -r "base_url\|api_url\|endpoint\|_URL" --include="*.py" --include="*.ts" --include="*.js"

# Check what's in docker-compose.yml environment section
cat docker-compose.yml | grep -A 50 "environment:"

# Check for pydantic settings or env loading
grep -r "BaseSettings\|environ\|getenv\|process.env" --include="*.py" --include="*.ts"
```

**Red flags**:
- `LLM_BASE_URL`, `API_URL`, `BACKEND_URL` not hardcoded
- URLs with defaults in code that could be overridden via env
- `allowed_envs` in dstack config containing URL variables

**Good pattern**:
```yaml
environment:
  - API_URL=https://trusted-service.com/v1  # Hardcoded, not ${API_URL}
```

### 2. External Network Calls

**Pattern**: Trace every outbound HTTP call to understand data flow.

```bash
# Python
grep -rn "httpx\|requests\|aiohttp\|fetch\|urllib" --include="*.py"

# JavaScript/TypeScript
grep -rn "fetch\|axios\|http\.\|https\." --include="*.ts" --include="*.js"

# Look for where user data goes
grep -rn "user_prompt\|message\|content\|payload" --include="*.py" --include="*.ts"
```

For each external call, document:
1. What data is sent
2. Is the destination hardcoded or configurable?
3. What credentials are included?

### 3. Attestation Verification

**Check**: Is the signing key cryptographically bound to the TDX quote?

```bash
# Find attestation/verification code
grep -rn "attestation\|verify\|quote\|report_data" --include="*.py" --include="*.ts"

# Look for signature verification
grep -rn "recover_message\|verify_signature\|ecdsa\|secp256k1" --include="*.py"
```

**Questions to answer**:
- Does the code verify TDX quotes independently or trust an API?
- Is `signing_address` extracted FROM the quote, or just bundled alongside?
- Are hash mismatches accepted? (search for "mismatch" or "known issue")

### 4. Build Reproducibility

**FIRST: Check if you can even verify the image:**
```bash
# Get deployed app_compose
./tools/verify-compose-hash.py <app-id> <cluster>

# Look at docker_compose_file - are images hardcoded or ${VAR}?
# BAD (unverifiable): image: ${MY_APP_IMAGE}
# GOOD (verifiable):  image: ghcr.io/org/app@sha256:abc123...
```

If images are `${VAR}` references in allowed_envs: **STOP - reproducible build verification is impossible.** The actual image digests are operator secrets.

**If images ARE hardcoded in compose:**
```bash
# Check Dockerfile
cat Dockerfile | grep -E "FROM|SOURCE_DATE_EPOCH|apt-get|pip install"

# Check CI for reproducibility flags
cat .github/workflows/*.yml | grep -E "rewrite-timestamp|SOURCE_DATE_EPOCH|buildx"
```

**Red flags**:
- `FROM image:tag` without `@sha256:digest`
- No `SOURCE_DATE_EPOCH` set
- `apt-get update` without snapshot pinning
- No `--rewrite-timestamp` in buildx
- `image: ${VAR}` where VAR is in allowed_envs (audit blind spot)

### 5. Storage and Secrets

```bash
# Find what's stored
grep -rn "database\|sqlite\|postgres\|redis\|storage\|persist" --include="*.py" --include="*.ts"

# Find secret handling
grep -rn "secret\|key\|token\|password\|credential" --include="*.py" --include="*.ts"

# Check for fallbacks (bad pattern)
grep -rn "fallback\|default\|dev_mode\|development" --include="*.py" --include="*.ts"
```

### 6. Smart Contract Verification (if applicable)

```bash
# Find contract addresses
grep -rn "0x[a-fA-F0-9]{40}" --include="*.py" --include="*.ts" --include="*.json"

# Check for on-chain verification
grep -rn "compose_hash\|app_id\|authorized" --include="*.py" --include="*.ts"
```

For any contracts found:
1. Is source verified on block explorer?
2. What compose hashes are authorized?
3. Who controls upgrades?

## Audit Output Template

```markdown
# [Project Name] Audit

## Summary Table
| Component | Status | Notes |
|-----------|--------|-------|
| Config Control | ✅/⚠️/❌ | Details |
| Attestation | ✅/⚠️/❌ | Details |
| Build Reproducibility | ✅/⚠️/❌ | Details |
| Storage | ✅/⚠️/❌ | Details |

## Critical Issues
### 1. [Issue Title]
**Severity**: CRITICAL/HIGH/MEDIUM
**File**: path/to/file.py:line
**Problem**: Description
**Impact**: What can attacker do
**Fix**: How to fix

## Data Flow
[Diagram showing user data path and trust boundaries]

## Recommendations
1. Immediate (Critical)
2. High Priority
3. Medium Priority
```

## Common Vulnerabilities by Frequency

1. **Operator-configurable URLs** (most common) - XORDI, TEE-Totalled pattern
2. **Unverified backend attestation** - MODEL_DISCOVERY_SERVER_URL pattern
3. **Non-reproducible builds** - Almost universal
4. **Accepted hash mismatches** - "Known issue" comments
5. **Development fallbacks in production** - `_dev_mode()` functions
6. **Unverified smart contracts** - On-chain but not source-verified

## Trust Model Reminder

```
Cloud Provider (AWS/GCP) ─── TEE protects against this
        │
    Operator ─────────────── TEE does NOT protect against this
        │                    (controls docker-compose, secrets, image version)
        │
    dstack/Phala ─────────── Provides TEE runtime, attestation
        │
    Application Code ─────── What we're auditing
        │
    External Services ────── RedPill, databases, APIs
```

The operator is often the threat model gap. Users trust the TEE, but the operator controls what runs in it.
