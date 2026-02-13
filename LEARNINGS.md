# DevProof Learnings

Patterns from verifying TEE application trust models. Not security bugs—**trust model gaps**.

The goal is [ERC-733 Stage 1](references/erc733-summary.md): proving the developer cannot rug users.

---

## 1. The Operator Gap (Why Most Apps Are Stage 0)

**The most important thing:** TEE protects against the cloud provider, not the operator.

Users see attestation and think they're safe. But the operator who runs `phala cvms create` controls:
- The docker-compose.yml (what code runs)
- Environment variables in `allowed_envs` (runtime configuration)
- When to upgrade (and to which version)

Attestation proves *what* is running, but not *who* configured it or *why*.

**Example (xordi-toy-example):** The app claimed "token cannot access DMs." But `MOCK_API_URL` was in `allowed_envs`. An operator could point it to their own server, receive the token, and use it to access DMs via the real API. The attestation would still verify.

---

## 2. Configurable URLs Are the #1 Vulnerability

Every audit found the same pattern: a URL that handles user data is configurable via environment variable.

| App | Vulnerable URL | Impact |
|-----|----------------|--------|
| xordi-toy-example | `MOCK_API_URL` | Token exfiltration |
| tee-totalled | `LLM_BASE_URL` | Message exfiltration |
| hermes | Hardcoded (good) | N/A |

**The fix:** Hardcode URLs in docker-compose.yml, not as `${VAR}` references.

```yaml
# BAD: operator can override
environment:
  - API_URL=${API_URL}

# GOOD: baked into compose hash
environment:
  - API_URL=https://trusted-service.com/v1
```

If a URL MUST be configurable, it should NOT handle user data.

---

## 3. Pha KMS vs Base KMS

Phala offers two KMS options:

| Feature | Pha KMS | Base KMS |
|---------|---------|----------|
| Attestation validation | ✓ | ✓ |
| Key derivation in TEE | ✓ | ✓ |
| **Public upgrade log** | ✗ | ✓ On-chain |
| **Retroactive audit** | ✗ | ✓ Query any block |

With Pha KMS, the Trust Center shows current state only. You can see what's running NOW, but not what ran last week.

With Base KMS, every `phala cvms upgrade` emits an on-chain event. You can query: "What compose hash was active at block X?" This enables full retroactive audit.

**Recommendation:** Use Base KMS for any app that claims transparency.

---

## 4. "Open Source" vs "Auditable"

Being on GitHub is helpful but not sufficient. The real questions:

1. **Can I inspect the deployed artifact?** (docker pull + inspect)
2. **Can I trace from artifact to source?** (compose hash → image digest → git commit)
3. **Can I reproduce the artifact from source?** (reproducible builds)

**Example (Primus):** Core code is closed source (87MB jar, native .so blobs). But we could still:
- Extract and read `application.yaml`
- Understand the config structure
- Identify trust gaps (like the default Anvil private key)

Auditability doesn't require source access. It requires artifact inspectability.

---

## 5. Almost Nothing Is Reproducible

Every app we audited failed reproducibility:

- Base images unpinned (`FROM node:20-alpine` instead of `@sha256:...`)
- No `SOURCE_DATE_EPOCH` for timestamps
- `apt-get update` without snapshot pinning
- Missing `--rewrite-timestamp` in buildx

This means: same source → different image hash. You can't independently verify that the running image matches the source you reviewed.

**Minimum viable reproducibility:**
```dockerfile
FROM node:20-alpine@sha256:abc123...
ENV SOURCE_DATE_EPOCH=0
```

---

## 6. The "Known Issue" Anti-Pattern

Multiple apps had code that accepted failures with comments like:

```python
# Known issue: hash mismatch, see GitHub issue #42
if hash != expected:
    logger.warning("Hash mismatch, continuing anyway")
```

This is a security hole labeled as a bug. The comment makes it feel acknowledged, but the behavior is still wrong.

**Pattern to grep for:**
```bash
grep -rn "known issue\|mismatch\|workaround\|TODO.*security" --include="*.py" --include="*.ts"
```

---

## 7. Trust Center Shows Current State Only

Phala's Trust Center (`trust.phala.com/app/<id>`) shows:
- Current compose hash
- Current attestation status
- When last updated

It does NOT show:
- Previous compose hashes
- Upgrade history
- What version ran on a specific date

This is fine for "is it safe NOW?" but fails for "was it safe THEN?"

The mitigation is Base KMS (on-chain logs) or maintaining a `DEPLOYMENTS.md` with manual records.

---

## 8. Image Tags Can Be Overwritten

```yaml
# Dangerous: tag can change
image: myapp:v1.0

# Safe: digest is immutable
image: myapp@sha256:abc123...
```

A tag like `hermes:126d663` looks like a commit hash, but it's still a mutable pointer. The operator could push a different image to that tag.

**Interesting:** In hermes, the main app used tag reference, but `dstack-ingress` was correctly pinned to digest. Inconsistent practices within the same compose file.

---

## 9. Dev Fallbacks Survive to Production

Common pattern:
```python
def get_key():
    if os.environ.get("DEV_MODE"):
        return "hardcoded-dev-key"
    return fetch_from_kms()
```

The `DEV_MODE` check might seem safe, but:
- Is `DEV_MODE` in `allowed_envs`?
- Could an operator set it?
- What if the KMS call fails - does it fall back?

**Grep pattern:**
```bash
grep -rn "dev_mode\|development\|fallback\|mock" --include="*.py" --include="*.ts"
```

---

## 10. What Good Looks Like

From xordi-release-process `toy-example-app`:

- **Base KMS** for on-chain transparency logs
- **DEPLOYMENTS.md** with human-readable upgrade history
- **Image pinned by digest** in compose
- **CI audit** (`grep -r "direct_message"` verified on every build)
- **VERIFICATION-REPORT.md** documenting gaps and trust boundaries

The app was still vulnerable (configurable URL), but the transparency tooling was exemplary. You could at least SEE what was deployed and when.

---

## 11. Compose Hash Verification (For Third-Party Auditors)

**Important:** `phala cvms attestation` only works for apps YOU own. For third-party auditing, use the 8090 metadata endpoint.

**The Formula:**
```
compose_hash = sha256(app_compose_json_string)
```

**How to fetch app_compose (third-party auditing):**
```bash
# Fetch the 8090 metadata page
curl -s "https://<app-id>-8090.<cluster>.phala.network/"

# The tcb_info is in a <textarea readonly> element
# Extract and decode HTML entities to get JSON
# app_compose is a field in that JSON
```

**Verification script:** `tools/verify-compose-hash.py`
```bash
./tools/verify-compose-hash.py <app-id> [cluster]
# Example:
./tools/verify-compose-hash.py f44389ef4e953f3c53847cc86b1aedc763978e83 dstack-pha-prod9
```

**The app_compose JSON includes:**
- `docker_compose_file`: the raw docker-compose.yaml content
- `allowed_envs`: environment variables the operator can set
- `features`: enabled dstack features (e.g., `["kms"]`)
- `kms_enabled`, `public_logs`, `public_sysinfo`, etc.
- `pre_launch_script`: script that runs before docker-compose up

**Key insight:** The compose_hash is computed from the **exact JSON string** of app_compose. This means:
- You CAN verify the hash matches what's attested
- The app_compose content IS the audit artifact (inspect it, don't just hash it)
- Image tags in docker_compose_file may be `${VAR}` references - check allowed_envs

**What to audit in app_compose:**
1. `allowed_envs` - can operator inject malicious config?
2. `docker_compose_file` - are URLs hardcoded or `${VAR}` references?
3. `pre_launch_script` - any suspicious commands?
4. Image references - pinned by digest or using env vars?

**Advanced verification tools:**
- `@phala/dstack-verifier` package (trust-center repo): Full attestation verification
- Trust Center UI: `https://trust.phala.com/app/<app-id>`

---

## 12. Git Branch HEAD vs Deployed Commit

**Pitfall:** The git branch you're reviewing may not match what's deployed.

```
Branch HEAD (e.g., tokscope-xordi) → may contain newer/older code
Deployed commit (in image tag) → what's actually running in TEE
```

**Example (tokscope-xordi):**
- Branch HEAD (`e4ffe87`): Had hardcoded fallback encryption key
- Deployed version (`58ad3f2` from tag `v1.1.0-58ad3f2`): Key derivation fixed

**How to trace correctly:**
1. Get compose hash from 8090 endpoint
2. Find image tag in `docker_compose_file` within app_compose
3. Image tag often contains commit SHA (e.g., `v1.1.0-58ad3f2`)
4. Checkout THAT commit, not branch HEAD

```bash
# Wrong
git checkout tokscope-xordi
# Right
git checkout 58ad3f2
```

---

## 13. Trust-Center Verifier Build Issues

**Reality:** The trust-center verifier Docker build fails out of the box.

```
# packages/verifier Dockerfile requires:
# - dcap-qvl: TDX quote verification (Rust)
# - dstack-mr-cli: RTMR computation (Rust)
# - qemu-tdx: ACPI table extraction (C++)
```

**dcap-qvl fails with:**
```
error[E0464]: multiple candidates for `rlib` dependency `webpki` found
error: could not compile `dcap-qvl` (lib) due to 10 previous errors
```

**Workarounds:**
1. Use **trust.phala.com** for attestation verification (recommended)
2. Use **verify-compose-hash.py** for compose hash verification only
3. Wait for pre-built Docker images from Phala team

**What you CAN verify without trust-center:**
- Compose hash (sha256 of app_compose string)
- app_compose contents (allowed_envs, docker_compose_file, features)
- Image digests (docker pull + inspect)

**What REQUIRES trust-center or trust.phala.com:**
- TDX quote verification (cryptographic attestation)
- RTMR computation (OS measurement)
- Full TCB verification chain

---

## 15. Image References via allowed_envs (Audit Blind Spot)

**Critical gap:** When `docker_compose_file` uses `${VAR}` for image references and that var is in `allowed_envs`, auditors CANNOT verify what image is running.

**Example (tokscope-xordi):**
```yaml
# In docker_compose_file:
image: ${TOKSCOPE_ENCLAVE_IMAGE}
image: ${TOKSCOPE_BROWSER_MANAGER_IMAGE}

# In allowed_envs:
["TOKSCOPE_ENCLAVE_IMAGE", "TOKSCOPE_BROWSER_MANAGER_IMAGE", ...]
```

**What compose_hash proves:**
- The TEMPLATE is correct (`${TOKSCOPE_ENCLAVE_IMAGE}`)
- The allowed_envs list is correct

**What compose_hash does NOT prove:**
- What image digest is actually running
- Whether the image was built from the claimed source

**The problem:** Operator sets these values in the Phala Cloud dashboard. They're secrets. Not exposed in:
- 8090 endpoint tcb_info
- Trust Center UI
- event_log

**Implications:**
1. You can audit the app's compose template but not the actual deployment
2. Operator could deploy a malicious image with same name/tag
3. Reproducible build verification is impossible without the actual image digest

**Better pattern:** Hardcode image digests in docker_compose_file:
```yaml
# BAD (operator-controlled):
image: ${MY_APP_IMAGE}

# GOOD (auditable):
image: ghcr.io/org/app@sha256:abc123...
```

**If allowed_envs MUST include images:** The operator should publish a DEPLOYMENTS.md or on-chain record showing which image digests they configured.

---

## 14. How to Actually Verify Reproducible Builds

Saying "builds are reproducible" requires demonstrating it.

**Step 1: Get the deployed image digest**
```bash
# From app_compose docker_compose_file
image: ghcr.io/org/app@sha256:abc123...
```

**Step 2: Clone and checkout the exact commit**
```bash
git clone <repo>
git checkout <commit-sha>  # From image tag, NOT branch HEAD
```

**Step 3: Rebuild with reproducibility flags**
```bash
# Check Dockerfile for:
# - Base image pinned by digest
# - SOURCE_DATE_EPOCH set
# - No apt-get update without pinning

docker buildx build \
  --platform linux/amd64 \
  --output type=docker \
  --build-arg SOURCE_DATE_EPOCH=0 \
  -t test-rebuild .
```

**Step 4: Compare digests**
```bash
docker inspect --format='{{.Id}}' test-rebuild
# Should match the deployed digest
```

**Common reasons for mismatch:**
- Base image not pinned (`FROM node:20` vs `@sha256:...`)
- Timestamps not normalized (missing SOURCE_DATE_EPOCH)
- `apt-get update` pulls different package versions
- Build context includes `.git` or other variable files

**What "reproducible" means:**
- Same source → same image digest
- ANY developer can verify the deployed binary matches the reviewed source

---

## Stage 1 Quick Check

For any dstack app (fail any = Stage 0):

1. [ ] Are URLs handling user data hardcoded in compose (not `${VAR}`)?
2. [ ] Is the image pinned by digest in docker_compose_file (not `${IMAGE_VAR}` in allowed_envs)?
3. [ ] Does it use Base KMS (for transparency logs)?
4. [ ] Is there a DEPLOYMENTS.md or on-chain history?
5. [ ] Are builds reproducible (pinned base images, SOURCE_DATE_EPOCH)?
6. [ ] Any "known issue" comments around security checks?
7. [ ] Any dev fallbacks that could be triggered in production?
8. [ ] Are you reviewing the deployed commit (not branch HEAD)?
9. [ ] Can you trace: compose_hash → docker_compose_file → image digest → source commit?
