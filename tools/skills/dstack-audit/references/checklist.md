# dstack Audit Checklist

## Pre-Audit Information Gathering

- [ ] Clone/access source repository
- [ ] Identify docker-compose.yml location
- [ ] Identify Dockerfile(s)
- [ ] Locate main application entry point
- [ ] Find attestation/verification code
- [ ] Note any DEPLOYMENTS.md or deployment docs

## 1. Configuration Control (CRITICAL)

### 1.1 URL Configuration
- [ ] List all external URLs in codebase
- [ ] For each URL, determine if configurable via:
  - [ ] Environment variable
  - [ ] pydantic settings default
  - [ ] Hardcoded in compose
- [ ] Verify URLs handling user data are HARDCODED in docker-compose.yml
- [ ] Check `allowed_envs` in dstack config (if present)

### 1.2 Critical URLs to Check
- [ ] LLM/AI service endpoints
- [ ] Backend API URLs
- [ ] Model discovery URLs
- [ ] Authentication service URLs
- [ ] Any URL receiving user content

### 1.3 docker-compose.yml Review
- [ ] List all environment variables
- [ ] Identify which use `${VAR}` syntax (operator-configurable)
- [ ] Verify critical URLs don't use `${VAR}` syntax
- [ ] Check for `allowed_envs` section

## 2. Attestation Verification

### 2.1 TDX Quote Verification
- [ ] Locate TDX quote verification code
- [ ] Check if verification uses external service (Phala, Intel)
- [ ] Verify signing key is EXTRACTED from quote report_data
- [ ] Check for binding between signing_address and TDX quote

### 2.2 Signature Verification
- [ ] Find response signature verification code
- [ ] Check if hash comparison is performed
- [ ] Look for "known issue" or mismatch acceptance
- [ ] Verify signature covers request AND response

### 2.3 Attestation Flow
- [ ] Is attestation required at startup?
- [ ] Is attestation required per-request?
- [ ] What happens if attestation fails?
- [ ] Are there development fallbacks?

## 3. Build Reproducibility

### 3.1 Dockerfile
- [ ] Base image pinned by digest (`@sha256:xxx`)
- [ ] `SOURCE_DATE_EPOCH` set
- [ ] No `apt-get update` without snapshot
- [ ] Dependencies pinned (requirements.txt, package-lock.json)

### 3.2 CI/CD Pipeline
- [ ] Uses `--rewrite-timestamp` in buildx
- [ ] Builds link to git commit
- [ ] Image digests recorded
- [ ] Compose hash derivation documented

### 3.3 Verification
- [ ] Can rebuild from source and get same digest?
- [ ] Are build artifacts linked to source commits?
- [ ] Is compose_hash derivation reproducible?

## 4. Data Flow Analysis

### 4.1 User Data Path
- [ ] Trace user input from entry to storage/processing
- [ ] Identify all external services receiving user data
- [ ] Check if any external calls are to configurable URLs

### 4.2 Secret Handling
- [ ] List all secrets/API keys
- [ ] Check how secrets are injected (env vars, KMS, etc.)
- [ ] Verify secrets not logged
- [ ] Check production log suppression

### 4.3 Storage
- [ ] What data is persisted?
- [ ] Where is it stored (memory, disk, database)?
- [ ] Is sensitive data encrypted at rest?
- [ ] What happens to data on crash/restart?

## 5. Development/Production Separation

### 5.1 Mode Detection
- [ ] How is dev vs prod determined?
- [ ] What behaviors differ?
- [ ] Are there fallback code paths?

### 5.2 Fallback Patterns
- [ ] Search for `dev_mode`, `fallback`, `mock`
- [ ] Check if fallbacks are reachable in production
- [ ] Verify hard failures on attestation issues (no graceful degradation)

## 6. Smart Contract Verification (if applicable)

### 6.1 Contract Identification
- [ ] List all contract addresses
- [ ] Identify chain (Ethereum, Base, Sapphire, etc.)
- [ ] Note contract purposes

### 6.2 Verification Status
- [ ] Is source verified on block explorer?
- [ ] What compose hashes are authorized?
- [ ] Who controls upgrades/authorization?

### 6.3 Historical Versions
- [ ] Query ComposeHashAdded/Removed events
- [ ] How many versions authorized historically?
- [ ] Can operator downgrade to old version?

## 7. External Dependencies

### 7.1 Third-Party Services
- [ ] List all external API calls
- [ ] For each: is endpoint hardcoded?
- [ ] What credentials are sent?
- [ ] What data is sent?

### 7.2 Trust Assumptions
- [ ] Document which services are trusted
- [ ] Note any unverified trust (e.g., Phala API)
- [ ] Identify single points of failure

## Post-Audit

- [ ] Generate findings report using template
- [ ] Classify findings by severity
- [ ] Provide specific fix recommendations
- [ ] Note verification status for each claim
