# NEAR Private Chat: Attestation Verification Gap Analysis

**Date:** 2026-04-03
**Pinned to:** `prod-20260402-003658` (commit [`2cb48d2c54da`](https://github.com/nearai/cloud-api/tree/2cb48d2c54da794217ee31f730dbbf94b977c8f0))
**Prior audit:** 2026-01-09 (commit [`80e73e25`](https://github.com/nearai/cloud-api/tree/80e73e254485c4d59c19335eb33c1e98035bafac))

---

## 1. Architecture Overview

NEAR Private Chat claims "verifiably private" AI conversations. The system runs in Intel TDX Trusted Execution Environments (TEEs) using the dstack framework. The architecture has four layers:

```
┌─────────────────────────────────────────────────────────────────────┐
│  User Browser                                                       │
│  Sends chat messages via HTTPS                                      │
└────────────────────────┬────────────────────────────────────────────┘
                         │ TLS (Let's Encrypt cert bound to TDX quote)
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  dstack-ingress CVM          (app_id: 000b2d32...ed6dea69)         │
│  TLS termination + nginx reverse proxy                              │
│  Attestation: /evidences/ (TLS cert hash = TDX report_data)        │
└────────────────────────┬────────────────────────────────────────────┘
                         │ Tailscale VPC (encrypted mesh)
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  chat-api CVMs               (app_id: f723e96a...2113f63b0c)       │
│  Rust chat backend (not Open WebUI)                                 │
│  OPENAI_BASE_URL=https://cloud-api.near.ai/v1  ← HARDCODED        │
│  Attestation: /v1/attestation/report                                │
└────────────────────────┬────────────────────────────────────────────┘
                         │ HTTPS to cloud-api.near.ai (via ingress)
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  cloud-api CVM               (app_id: f550fdfb...4a4431ae)         │
│  Inference routing gateway                                          │
│  Reads inference_url from database per model                        │
│  Attestation: /v1/attestation/report                                │
└────────────────────────┬────────────────────────────────────────────┘
                         │ HTTPS to inference_url (operator-configured)
                         ▼
┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┐
  vLLM / SGLang backends                                              
  Run models, return completions                                      
  Expose /v1/attestation/report                                       
  ← ATTESTATION FETCHED BUT NEVER VERIFIED BY CLOUD-API              
└ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┘
```

The top three layers form the **outer boundary** — verifiable by users via attestation endpoints. The bottom layer is the **inner boundary** — where user conversations are sent to inference backends that cloud-api does not cryptographically verify.

---

## 2. The Outer Boundary (What Works)

This section documents the verified trust chain from browser to cloud-api. Each link is independently verifiable.

### 2.1 TLS → TEE Binding

The TLS certificate served at `private.near.ai` is cryptographically bound to the dstack-ingress TEE attestation:

1. dstack-ingress generates a Let's Encrypt certificate inside the TEE
2. It hashes all evidence files (including the TLS cert) into `sha256sum.txt`
3. The SHA256 of `sha256sum.txt` becomes the `report_data` in the TDX quote

```bash
# Verify the binding
EVIDENCE_HASH=$(curl -s https://private.near.ai/evidences/sha256sum.txt | sha256sum | cut -d' ' -f1)
QUOTE_DATA=$(curl -s https://private.near.ai/evidences/quote.json | python3 -c "import sys,json; print(json.load(sys.stdin)['report_data'][:64])")
[ "$EVIDENCE_HASH" = "$QUOTE_DATA" ] && echo "MATCH" || echo "MISMATCH"
```

**Source:** [`dstack-ingress-vpc/scripts/generate-evidences.sh`](https://github.com/nearai/dstack-ingress-vpc)

### 2.2 chat-api → cloud-api Routing

`OPENAI_BASE_URL` is hardcoded in the docker-compose embedded in the attestation:

```bash
curl -s https://private.near.ai/v1/attestation/report | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
ac=json.loads(d['chat_api_gateway_attestation']['info']['tcb_info']['app_compose'])
dcf=ac['docker_compose_file']
for line in dcf.split('\n'):
    if 'OPENAI_BASE_URL' in line: print(line.strip())
print('In allowed_envs:', 'OPENAI_BASE_URL' in ac.get('allowed_envs',[]))
"
# OPENAI_BASE_URL=https://cloud-api.near.ai/v1
# In allowed_envs: False
```

Because `OPENAI_BASE_URL` is NOT in `allowed_envs`, the operator cannot change it at runtime. It is baked into the compose hash, which is checked by the dstack KMS on boot.

### 2.3 Compose Hash Enforcement

Each CVM's code is locked to a specific compose hash registered on-chain in a DstackApp contract on Base. The dstack KMS will not release encryption keys to a CVM whose compose hash is not whitelisted. This means the operator cannot silently change the running code.

**Limitation:** The contracts are not source-verified on Basescan, so we cannot confirm the governance logic (who can add new hashes, whether there's a backdoor). See the main report for details.

### 2.4 What Users Can Verify

A user can independently verify:
- The TLS cert they're connected to matches the one attested by the TEE
- The code running in chat-api is locked to a specific compose hash
- That compose hash hardcodes `OPENAI_BASE_URL=https://cloud-api.near.ai/v1`
- cloud-api is also attested and locked to a compose hash

**What users cannot verify:** What happens after cloud-api receives their request — specifically, which vLLM backends receive their conversation data.

---

## 3. The Inner Boundary (The Gap)

This section traces the exact code path by which user conversations are routed to inference backends, and demonstrates that no cryptographic verification occurs.

### 3.1 How cloud-api Discovers Backends

Previously (before 2026-03-26), cloud-api used `MODEL_DISCOVERY_SERVER_URL` — a runtime-configurable environment variable — to poll an external discovery service for backend addresses. [PR #513](https://github.com/nearai/cloud-api/pull/513) removed this, replacing it with database-driven routing.

Now, each model has an `inference_url` column in the database, set by the operator. The provider pool loads these on startup and refreshes periodically:

**[`inference_provider_pool/mod.rs:1328-1450`](https://github.com/nearai/cloud-api/blob/2cb48d2c54da794217ee31f730dbbf94b977c8f0/crates/services/src/inference_provider_pool/mod.rs#L1328-L1450)** — `load_inference_url_models()`

```
For each (model_name, inference_url) from database:
  1. If URL unchanged from last load → reuse existing VLlmProvider
  2. If new URL → create VLlmProvider::new(url, api_key)
  3. Probe attestation: fetch signing public keys from backend
  4. Add provider to model_to_providers and pubkey_to_providers maps
```

The `inference_url` values are controlled entirely by the database, which is controlled by the operator. The compose hash does not constrain them.

### 3.2 How a Chat Request Reaches a Backend

When a user sends a message, the request flows through:

**Step 1: HTTP handler** ([`completions.rs:305-527`](https://github.com/nearai/cloud-api/blob/2cb48d2c54da794217ee31f730dbbf94b977c8f0/crates/api/src/routes/completions.rs#L305-L527))
- Validates API key, extracts encryption headers, converts to internal request

**Step 2: Completions service** ([`completions/mod.rs:1004-1165`](https://github.com/nearai/cloud-api/blob/2cb48d2c54da794217ee31f730dbbf94b977c8f0/crates/services/src/completions/mod.rs#L1004-L1165))
- Resolves model name, checks quota, calls `inference_provider_pool.chat_completion_stream()`

**Step 3: Provider selection** ([`inference_provider_pool/mod.rs:572-776`](https://github.com/nearai/cloud-api/blob/2cb48d2c54da794217ee31f730dbbf94b977c8f0/crates/services/src/inference_provider_pool/mod.rs#L572-L776))
- Looks up providers for the requested model
- If E2EE: filters by `model_pub_key` (the signing key the client chose)
- Applies round-robin load balancing
- Retries on 5xx/timeout with fallback to next provider

**Step 4: Backend request** ([`vllm/mod.rs:~408+`](https://github.com/nearai/cloud-api/blob/2cb48d2c54da794217ee31f730dbbf94b977c8f0/crates/inference_providers/src/vllm/mod.rs))
- Creates HTTP POST to `{inference_url}/v1/chat/completions`
- Sends the user's full conversation as JSON body
- Streams SSE response back

At no point in this chain is the backend's identity cryptographically verified. The only gate is: "does this URL appear in the database?"

### 3.3 The Attestation Fetch (Zero Verification)

When cloud-api loads a backend, it fetches an attestation report from it. Here is the complete implementation:

**[`vllm/mod.rs:307-376`](https://github.com/nearai/cloud-api/blob/2cb48d2c54da794217ee31f730dbbf94b977c8f0/crates/inference_providers/src/vllm/mod.rs#L307-L376)** — `get_attestation_report()`

```rust
// Simplified — full code at the permalink above
async fn get_attestation_report(&self, model, signing_algo, nonce, ...) 
    -> Result<serde_json::Map<String, Value>, AttestationError> 
{
    let url = format!("{}/v1/attestation/report?{}", self.config.base_url, query);
    let response = self.client.get(&url).headers(headers).send().await?;
    
    if !response.status().is_success() {
        return Err(AttestationError::FetchError(...));
    }
    
    let attestation_report = response.json().await?;  // Parse JSON, return it
    Ok(attestation_report)
}
```

This function:
- Sends an HTTP GET to the backend
- Parses the JSON response
- Returns the parsed JSON

It does **not**:
- Validate any TDX quote signature
- Check `compose_hash` against expected values
- Check `app_id` against a whitelist
- Verify that the `signing_public_key` is bound to a TDX quote
- Perform any cryptographic operation whatsoever

To confirm this is not done elsewhere, we searched the entire `inference_provider_pool` module for `compose_hash`, `app_id`, `verify_quote`, and `tdx`. **Zero matches.**

### 3.4 Signing Keys Are Trust-on-First-Use

After fetching the attestation report, cloud-api extracts the `signing_public_key` and stores it:

**[`inference_provider_pool/mod.rs:244-289`](https://github.com/nearai/cloud-api/blob/2cb48d2c54da794217ee31f730dbbf94b977c8f0/crates/services/src/inference_provider_pool/mod.rs#L244-L289)** — `fetch_signing_public_keys_for_both_algorithms()`

```rust
if let Some(attestation_report) = Self::fetch_attestation_report_with_retry(...) {
    has_valid_attestation = true;
    if let Some(signing_public_key) = attestation_report
        .get("signing_public_key")
        .and_then(|v| v.as_str())
    {
        pub_key_updates.push((signing_public_key.to_string(), provider.clone()));
    }
}
```

The `signing_public_key` is read directly from the untrusted JSON response and stored in the `pubkey_to_providers` map. Any server can claim any public key.

### 3.5 `has_valid_attestation` Is Discarded

The function returns a tuple `(pub_key_updates, has_valid_attestation)`. At the call sites, the second value is discarded:

**[`inference_provider_pool/mod.rs:1371`](https://github.com/nearai/cloud-api/blob/2cb48d2c54da794217ee31f730dbbf94b977c8f0/crates/services/src/inference_provider_pool/mod.rs#L1371)**

```rust
let (pub_keys, _) = Self::fetch_signing_public_keys_for_both_algorithms(
    &serving_provider, &model_name, &url,
).await;
```

The `_` means the value is intentionally ignored. A provider is added to the pool regardless of whether attestation succeeded or failed.

### 3.6 What This Means in Practice

The operator (or anyone with database write access) can:

1. **Route conversations to a logging server:** Set `inference_url` to a server that records all requests, then forwards them to a real vLLM backend. cloud-api will accept it as long as the server returns valid-looking JSON from `/v1/attestation/report`.

2. **Substitute a different model:** Point `inference_url` to a server running a different model (or no model at all). Responses would come from whatever the server returns.

3. **Compromise E2EE:** The E2EE system relies on `signing_public_key` from the backend attestation. Since this key is trust-on-first-use from unverified JSON, a MITM server can present its own key. Clients encrypting to that key would be encrypting to the attacker.

A malicious backend needs only to:
- Accept POST requests at `/v1/chat/completions` (proxy to real backend)
- Return any valid JSON at `/v1/attestation/report` (copy a real report, change the signing key)

---

## 4. The Design Intent

Examining the team's own issues and PRs reveals how they frame attestation:

**The team treats attestation as a data-export service.** cloud-api *provides* attestation data to clients via `/v1/attestation/report`. The expectation is that *clients* verify the attestation, not that cloud-api verifies its backends. This is consistent with the dstack framework's design: "Users can cryptographically verify exactly what's running."

**But this model has a gap at the inner boundary.** The client can verify that cloud-api is running in a TEE with a known compose hash. The client *cannot* verify which vLLM backends cloud-api routes to — that decision happens inside cloud-api based on database state. The client must trust cloud-api to route correctly, and cloud-api does not verify its backends.

**The team acknowledged this gap:**

> [Issue #224](https://github.com/nearai/cloud-api/issues/224) (2025-12-03, still open): "cloud-api should verify the attestation quotes from the models and only add the verified model nodes into the list. The verification can be done with the help of Verification SDK in Rust that we're going to release in next few weeks."

Four months later, Issue #224 remains open. The verification SDK has not been released.

---

## 5. External Verification: Phala's private-ai-verifier

[`Phala-Network/private-ai-verifier`](https://github.com/Phala-Network/private-ai-verifier) is a Python SDK that verifies TEE attestations for confidential AI services, including NEAR AI. Its NearAI verifier (`confidential_verifier/verifiers/nearai.py`) implements multi-component verification:

1. **dstack quote validation** — sends `{quote, event_log, vm_config}` to a local `dstack-verifier` sidecar (DCAP QVL)
2. **Compose hash check** — computes `SHA256(app_compose.encode("utf-8"))` and compares against `compose_hash` from dstack `app_info`
3. **Report data nonce binding** — verifies `report_data[0:32] = signing_address (padded)`, `report_data[32:64] = nonce`
4. **NVIDIA GPU attestation** — decodes NRAS JWT tokens, checks `x-nvidia-overall-att-result`

This proves that **client-side verification of the outer boundary is technically feasible** — the tooling exists and works. A user running this SDK can confirm that dstack-ingress, chat-api, and cloud-api are legitimate TEE instances running attested code.

### 5.1 What It Cannot Fix

The verifier checks the components that NEAR exposes via `/v1/attestation/report`. It cannot observe or constrain cloud-api's routing decisions. The operator controls the database that maps models to `inference_url` values, and nothing in the architecture — inside or outside the CVM — constrains those choices. An external verifier can confirm cloud-api is the real cloud-api; it cannot confirm where cloud-api sends your conversation.

This is the same gap described in Section 3, viewed from the other direction: even a sophisticated external verifier hits the same wall.

### 5.2 Caveats in the Verifier Itself

The private-ai-verifier has its own trust shortcuts:

- **JWT signature verification disabled** — both NVIDIA GPU tokens and Intel Trust Authority JWTs are decoded with `verify_signature: False`. Multiple TODO comments acknowledge this.
- **dstack-verifier sidecar trusted without authentication** — the SDK sends attestation data to `localhost:8080` and trusts whatever comes back.
- **Tinfoil golden measurements** trust Tinfoil's GitHub proxy as the source of truth for Sigstore bundles.

These are reasonable for a development-stage SDK, but mean the verifier is not yet production-grade for high-stakes verification.

---

## 6. PR Timeline

| Date | Event | Security Impact |
|------|-------|-----------------|
| 2025-10-14 | [PR #39](https://github.com/nearai/cloud-api/pull/39): Fix API endpoint security vulnerability | Early security awareness |
| 2025-10-21 | [Issue #46](https://github.com/nearai/cloud-api/issues/46): "As a client, how to perform attestation" | Empty body — no client verification docs written |
| 2025-11-03 | [Issue #130](https://github.com/nearai/cloud-api/issues/130): TDX report data doesn't match expected value | Attestation correctness bugs |
| 2025-12-03 | [Issue #224](https://github.com/nearai/cloud-api/issues/224): "cloud-api should only add verified model nodes" | **Team acknowledges the gap** |
| 2025-12-04 | [Issue #203](https://github.com/nearai/cloud-api/issues/203): Signing address mismatch | Signature verification impossible |
| 2025-12-24 | [PR #298](https://github.com/nearai/cloud-api/pull/298): E2EE introduced | signing_public_key = TOFU from unverified JSON |
| 2025-12-30 | [Issue #307](https://github.com/nearai/cloud-api/issues/307): Need real provider tests | Mocks can't catch attestation mismatches |
| 2026-01-09 | **Our initial audit** | MODEL_DISCOVERY_SERVER_URL runtime-configurable |
| 2026-01-12 | [Issue #309](https://github.com/nearai/cloud-api/issues/309): Multiple instances have different signing keys | Consistency problem compounds verification gap |
| 2026-02-20 | [PR #415](https://github.com/nearai/cloud-api/pull/415): Reproducible builds workflow | Build verification, not runtime verification |
| 2026-02-27 | [PR #457](https://github.com/nearai/cloud-api/pull/457): Docker image signing with cosign | Image integrity, not backend verification |
| 2026-03-02 | [PR #458](https://github.com/nearai/cloud-api/pull/458): Gate DEV mode attestation bypass | **Previously, `DEV=true` disabled attestation in production** |
| 2026-03-12 | [PR #484](https://github.com/nearai/cloud-api/pull/484)/[#486](https://github.com/nearai/cloud-api/pull/486): TLS fingerprint in attestation | More data for clients to verify; no server-side verification |
| 2026-03-13 | [PR #482](https://github.com/nearai/cloud-api/pull/482): Inference pool resilience | Failed attestation keeps existing providers (doesn't evict) |
| 2026-03-13 | [PR #485](https://github.com/nearai/cloud-api/pull/485): Add inference_url column | Groundwork for discovery server removal |
| 2026-03-19 | [PR #501](https://github.com/nearai/cloud-api/pull/501): Redact user data from error responses | **Closed without merging** — backend errors still leak conversations |
| 2026-03-26 | [PR #513](https://github.com/nearai/cloud-api/pull/513): Remove discovery server | ~1000 lines removed; inference_url from DB; **attestation verification not added** |
| 2026-04-02 | `prod-20260402-003658` deployed | Current production; gap persists |
| 2026-04-03 | Issue #224 still open | 4 months since acknowledgment |

---

## 7. Old vs New Comparison

PR #513 changed how backends are discovered, but not how they are trusted:

| Aspect | Jan 2026 (pre-PR#513) | Apr 2026 (post-PR#513) | |
|--------|----------------------|------------------------|-|
| Backend discovery | `MODEL_DISCOVERY_SERVER_URL` env var | `inference_url` from database | **Improved** — no longer a single runtime env var |
| Who controls routing | Anyone who sets env var | Database admin | **Improved** — requires DB access |
| TDX quote validation | None | None | **Unchanged** |
| compose_hash/app_id check | None | None | **Unchanged** |
| Signing key trust model | TOFU from unverified JSON | TOFU from unverified JSON | **Unchanged** |
| `has_valid_attestation` | Computed and checked | Computed and **discarded** (`_`) | **Worse** |
| DEV mode bypass | `DEV=true` disables attestation in prod | Compile-time only (PR #458) | **Fixed** |
| `MODEL_DISCOVERY_SERVER_URL` | Active, in allowed_envs | Vestigial — still in allowed_envs but code ignores it | Cosmetic risk |

---

## 8. Verification Commands

All claims in this document can be independently verified:

```bash
# 1. Current production compose hash
curl -s https://private.near.ai/v1/attestation/report | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['cloud_api_gateway_attestation']['info']['compose_hash'])"
# Expected: 11369675e793061bbe1c4176cec902df45cea455922f86ee234d8332e32cdf93

# 2. MODEL_DISCOVERY_SERVER_URL still in allowed_envs
curl -s https://private.near.ai/v1/attestation/report | \
  python3 -c "
import sys,json
d=json.load(sys.stdin)
ac=json.loads(d['cloud_api_gateway_attestation']['info']['tcb_info']['app_compose'])
print('MODEL_DISCOVERY_SERVER_URL' in ac['allowed_envs'])
"
# Expected: True

# 3. Confirm Issue #224 is still open
gh api repos/nearai/cloud-api/issues/224 --jq '{state, title}'
# Expected: {"state":"open","title":"Enhancement: cloud-api should only add verified model nodes"}

# 4. Confirm zero attestation verification in source
gh api "repos/nearai/cloud-api/contents/crates/services/src/inference_provider_pool/mod.rs?ref=2cb48d2c54da" \
  --jq '.content' | base64 -d | grep -c "compose_hash\|app_id.*check\|verify_quote\|tdx"
# Expected: 0

# 5. Confirm _has_valid_attestation is discarded
gh api "repos/nearai/cloud-api/contents/crates/services/src/inference_provider_pool/mod.rs?ref=2cb48d2c54da" \
  --jq '.content' | base64 -d | grep "_has_valid_attestation\|pub_keys, _)"
# Expected: matches showing underscore-prefixed variable and (_, _) destructuring
```

---

## 9. Source References

All links pinned to commit `2cb48d2c54da` (`prod-20260402-003658`):

| What | Link |
|------|------|
| Attestation fetch (zero verification) | [`vllm/mod.rs:307-376`](https://github.com/nearai/cloud-api/blob/2cb48d2c54da794217ee31f730dbbf94b977c8f0/crates/inference_providers/src/vllm/mod.rs#L307-L376) |
| Signing key TOFU extraction | [`inference_provider_pool/mod.rs:244-289`](https://github.com/nearai/cloud-api/blob/2cb48d2c54da794217ee31f730dbbf94b977c8f0/crates/services/src/inference_provider_pool/mod.rs#L244-L289) |
| `_has_valid_attestation` discarded | [`inference_provider_pool/mod.rs:1371`](https://github.com/nearai/cloud-api/blob/2cb48d2c54da794217ee31f730dbbf94b977c8f0/crates/services/src/inference_provider_pool/mod.rs#L1371) |
| Provider loading from DB | [`inference_provider_pool/mod.rs:1328-1450`](https://github.com/nearai/cloud-api/blob/2cb48d2c54da794217ee31f730dbbf94b977c8f0/crates/services/src/inference_provider_pool/mod.rs#L1328-L1450) |
| Provider selection / routing | [`inference_provider_pool/mod.rs:572-776`](https://github.com/nearai/cloud-api/blob/2cb48d2c54da794217ee31f730dbbf94b977c8f0/crates/services/src/inference_provider_pool/mod.rs#L572-L776) |
| Team acknowledgment | [Issue #224](https://github.com/nearai/cloud-api/issues/224) |
| DEV bypass fix | [PR #458](https://github.com/nearai/cloud-api/pull/458) |
| Discovery server removal | [PR #513](https://github.com/nearai/cloud-api/pull/513) |
| Client attestation docs (empty) | [Issue #46](https://github.com/nearai/cloud-api/issues/46) |
