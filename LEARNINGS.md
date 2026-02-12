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

## Stage 1 Quick Check

For any dstack app (fail any = Stage 0):

1. [ ] Are URLs handling user data hardcoded in compose (not `${VAR}`)?
2. [ ] Is the image pinned by digest (not tag)?
3. [ ] Does it use Base KMS (for transparency logs)?
4. [ ] Is there a DEPLOYMENTS.md or on-chain history?
5. [ ] Are builds reproducible (pinned base images, SOURCE_DATE_EPOCH)?
6. [ ] Any "known issue" comments around security checks?
7. [ ] Any dev fallbacks that could be triggered in production?
