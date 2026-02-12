# Stage 1: Dev-Proof Checklist

From ERC-733. **Fail any requirement = Stage 0.**

## Required for Stage 1

### 1. On-Chain Attestation
- [ ] TEE attestation verified on-chain (not just Trust Center)
- [ ] Uses Base KMS (public upgrade log) OR equivalent transparency
- [ ] Compose hash recorded in immutable ledger

**How to verify:**
```bash
# Check KMS type in compose
grep -i "kms:" docker-compose.yml
# Should be: x-dstack: kms: base

# Query on-chain registry for compose hash history
cast call $APP_CONTRACT "getComposeHashes()" --rpc-url $BASE_RPC
```

### 2. Auditable Code
- [ ] Source code is public (GitHub, etc.)
- [ ] OR formal verification with published proofs
- [ ] OR reputable third-party audit with published report

**How to verify:**
```bash
# Check if repo exists and is public
curl -s https://api.github.com/repos/$OWNER/$REPO | jq '.private'
# Should be: false
```

### 3. Reproducible Code Measurement
- [ ] Base images pinned by digest (`@sha256:...`)
- [ ] `SOURCE_DATE_EPOCH` set for deterministic timestamps
- [ ] Lock files committed (`package-lock.json`, `uv.lock`, etc.)
- [ ] Build instructions documented

**How to verify:**
```bash
# Check Dockerfile for pinned base
grep "FROM.*@sha256" Dockerfile

# Check for reproducibility flags
grep "SOURCE_DATE_EPOCH\|rewrite-timestamp" .github/workflows/*.yml
```

### 4. Developer Has No Access to Secrets
- [ ] No hardcoded fallback keys
- [ ] No `DEV_MODE` that bypasses KMS
- [ ] Keys derived deterministically from TEE (via `getKey()`)
- [ ] No operator-accessible secret injection

**How to verify:**
```bash
# Search for fallbacks
grep -rn "fallback\|dev_mode\|hardcoded\|default.*key" --include="*.py" --include="*.ts"

# Check allowed_envs in compose
grep -A 20 "allowed_envs" docker-compose.yml
# Should NOT contain SECRET, KEY, TOKEN variables
```

### 5. Upgrade Process with Notice Period
- [ ] Timelock on compose hash changes (e.g., 7 days)
- [ ] OR DAO governance for upgrades
- [ ] Users can withdraw before changes take effect
- [ ] Upgrade history publicly queryable

**How to verify:**
```bash
# Check AppAuth contract for timelock
cast call $APP_CONTRACT "getTimelock()" --rpc-url $BASE_RPC

# Query upgrade events
cast logs --from-block 0 --address $APP_CONTRACT "ComposeHashAdded(bytes32)" --rpc-url $BASE_RPC
```

### 6. No Centralized Infrastructure Dependency
- [ ] No Vercel/Cloudflare for serving (or served from TEE)
- [ ] No centralized database outside TEE
- [ ] No API keys that could be revoked to break the app
- [ ] TEE vendor is only centralized dependency

**How to verify:**
```bash
# Check for external service dependencies
grep -rn "vercel\|cloudflare\|firebase\|supabase" --include="*.yml" --include="*.json"

# Check where frontend is served from
curl -sI https://$APP_DOMAIN | grep -i "server\|via"
```

### 7. No Backdoors or Debug Paths
- [ ] No `debug=True` in production
- [ ] No admin endpoints without TEE-enforced auth
- [ ] No "break glass" recovery keys
- [ ] No logging of sensitive data

**How to verify:**
```bash
# Search for debug flags
grep -rn "debug.*true\|DEBUG\|admin\|break.glass" --include="*.py" --include="*.ts"

# Check for sensitive logging
grep -rn "log.*password\|log.*token\|log.*secret\|console.log.*key" --include="*.py" --include="*.ts"
```

---

## The Operator Gap Test

The critical question: **Can the operator exfiltrate user data?**

```bash
# Find all URLs that handle user data
grep -rn "base_url\|api_url\|endpoint\|_URL" --include="*.py" --include="*.ts"

# For each URL found, check if it's hardcoded in compose
grep "$URL_NAME" docker-compose.yml

# If it appears as ${VAR} or is in allowed_envs, it's operator-configurable
# That's a FAIL for Stage 1
```

**Good:**
```yaml
environment:
  - API_URL=https://trusted.com/v1  # Hardcoded
```

**Bad:**
```yaml
environment:
  - API_URL=${API_URL}  # Operator can override

# OR in allowed_envs
x-dstack:
  allowed_envs:
    - API_URL  # Operator can set at runtime
```

---

## Quick Assessment

Run this to get a quick Stage assessment:

```bash
#!/bin/bash
# devproof-check.sh

echo "=== DevProof Stage 1 Quick Check ==="

# 1. KMS Type
echo -n "KMS Type: "
grep -q "kms: base" docker-compose.yml && echo "✅ Base (on-chain)" || echo "❌ Not Base"

# 2. Image Pinning
echo -n "Image Pinning: "
grep -q "@sha256:" docker-compose.yml && echo "✅ Digest pinned" || echo "❌ Tag only"

# 3. Configurable URLs
echo -n "Configurable URLs: "
URLS=$(grep -c '\${.*URL' docker-compose.yml 2>/dev/null || echo 0)
[ "$URLS" -eq 0 ] && echo "✅ None found" || echo "❌ $URLS found"

# 4. Allowed Envs
echo -n "Allowed Envs: "
grep -q "allowed_envs" docker-compose.yml && echo "⚠️ Present (review needed)" || echo "✅ None"

# 5. Reproducibility
echo -n "Reproducibility: "
grep -q "SOURCE_DATE_EPOCH" Dockerfile 2>/dev/null && echo "✅ Flags present" || echo "❌ Missing"

echo ""
echo "For full Stage 1 verification, review each section above."
```

---

## Stage 1 → Stage 2 Requirements

Once Stage 1 is achieved, Stage 2 adds:

- [ ] Multi-TEE deployment for redundancy
- [ ] Responsive to TCB updates (security patches)
- [ ] No vendor lock-in (redundant across Intel TDX, AMD SEV, Nitro)
- [ ] Permissionless operation (anyone can run a node)
- [ ] Forward secrecy & data opt-out

See ERC-733 for full Stage 2/3 requirements.
