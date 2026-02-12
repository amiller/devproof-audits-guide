---
name: dstack-audit
description: This skill should be used when the user asks to "audit a dstack app", "audit a TEE application", "review TEE security", "check for operator exfiltration", "verify attestation binding", "audit Phala app", "check compose configuration", or mentions dstack, TEE audit, or confidential computing security review.
version: 1.0.0
---

# dstack/Phala TEE Application Audit

Audit toolkit for assessing security of applications running in dstack/Phala Trusted Execution Environments.

## Core Question

**Can the operator exfiltrate user data or compromise privacy guarantees?**

TEE protects against cloud providers, but operators control:
- Environment variables in `allowed_envs`
- Secrets injected at runtime
- Which docker image version to deploy

## Audit Workflow

### Phase 1: Gather Deployment Data

Collect from live deployment or documentation:
- `app_id` and `compose_hash` from attestation
- Docker image digest
- Any on-chain contract addresses

Compare against DEPLOYMENTS.md or equivalent documentation.

### Phase 2: Run Automated Checks

Execute the audit script to find common issues:

```bash
./scripts/audit-checks.sh /path/to/repo
```

Or run checks manually using Grep tool with patterns from `references/search-patterns.md`.

### Phase 3: Manual Review

For each finding from automated checks:

1. **Configuration Control**: Trace each configurable URL to understand data flow
2. **Attestation Verification**: Check if signing keys are cryptographically bound to TDX quotes
3. **Build Reproducibility**: Verify Dockerfile has pinned images and SOURCE_DATE_EPOCH
4. **Storage Analysis**: Understand what data persists and where

### Phase 4: Generate Report

Use the template in `references/report-template.md` to structure findings.

## Critical Vulnerability Patterns

### 1. Operator-Configurable URLs (Most Common)

**Pattern**: URLs routing user data loaded from environment variables.

```python
# VULNERABLE: Operator can override via env
llm_base_url: str = "https://api.redpill.ai/v1"  # pydantic default

# SAFE: Hardcoded in docker-compose.yml
environment:
  - LLM_BASE_URL=https://api.redpill.ai/v1  # Not ${LLM_BASE_URL}
```

**Check**: Search for `base_url`, `api_url`, `endpoint`, `_URL` in code, then verify each is hardcoded in docker-compose.yml.

### 2. Unverified Backend Attestation

**Pattern**: Code fetches attestation but doesn't verify cryptographic binding.

```python
# VULNERABLE: Trusts API to bundle correct signing_address
attestation = fetch_attestation()
signing_address = attestation["signing_address"]  # No binding check
```

**Check**: Look for attestation verification code and verify it extracts/validates signing key FROM the TDX quote report_data.

### 3. Hash Mismatch Acceptance

**Pattern**: Code accepts responses where request/response hash doesn't match signature.

```python
# VULNERABLE: "Known issue" comments
if computed_hash != expected_hash:
    logger.debug("Known API issue, accepting anyway")  # BAD
```

**Check**: Search for "known issue", "mismatch", "ignore" near verification code.

### 4. Development Fallbacks in Production

**Pattern**: Mock/dev code paths reachable in production.

```python
# VULNERABLE: Fallback returns fake data
def get_attestation():
    if not tee_available:
        return {"status": "dev_mode", ...}  # Could mask failures
```

**Check**: Search for `dev_mode`, `fallback`, `mock`, `development` in attestation code.

## Trust Model

```
Cloud Provider ─── TEE protects here
      │
  Operator ─────── TEE does NOT protect (controls compose, secrets, image)
      │
  dstack/Phala ─── Provides TEE runtime
      │
  Application ──── What we audit
      │
  External APIs ── RedPill, databases, etc.
```

## Quick Reference: What Must Be Hardcoded

In docker-compose.yml (NOT in allowed_envs or code defaults):
- Any URL that receives user data
- Any URL that provides attestation/verification
- Model names for TEE-protected inference
- Backend service endpoints

## Additional Resources

### Reference Files

- **`references/search-patterns.md`** - Grep patterns for common vulnerabilities
- **`references/checklist.md`** - Comprehensive audit checklist
- **`references/report-template.md`** - Structured report template

### Scripts

- **`scripts/audit-checks.sh`** - Automated vulnerability scanning
