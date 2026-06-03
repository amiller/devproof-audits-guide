# Issue draft for `nearai/cloud-api`

**Suggested title:** Silent model substitution — catalog `deepseek-ai/DeepSeek-V3.1` returns a `Qwen/Qwen3.5-122B-A10B` backend; gateway never checks attested `model_name` matches the request

> Filed against `nearai/cloud-api`. Independent of #224 (which is about cryptographic
> verification of the backend) — this is about catalog identity ↔ served model.

---

## Summary

Requesting `deepseek-ai/DeepSeek-V3.1` from `cloud-api.near.ai` returns a TDX-attested response from a backend that is actually serving **`Qwen/Qwen3.5-122B-A10B`** — different model, different weights, different KMS-derived signing key. The gateway silently routes the request and returns the wrong model's attestation; clients (and the model itself, when asked) report Qwen, but no protocol-level error or warning surfaces to the caller.

## Reproduction (single curl + jq, anyone with a `NEAR_API_KEY` can run)

**1. Attested model name (TDX-signed by the backend TD):**

```bash
curl -s "https://cloud-api.near.ai/v1/attestation/report?model=deepseek-ai/DeepSeek-V3.1&nonce=$(openssl rand -hex 32)" \
  -H "Authorization: Bearer $NEAR_API_KEY" | jq -r '.model_attestations[0].model_name'
# → Qwen/Qwen3.5-122B-A10B
```

**2. OpenAI-protocol response (the chat-completions API itself reports the substitution):**

```bash
curl -s "https://cloud-api.near.ai/v1/chat/completions" \
  -H "Authorization: Bearer $NEAR_API_KEY" -H "Content-Type: application/json" \
  -d '{"model":"deepseek-ai/DeepSeek-V3.1","messages":[{"role":"user","content":"What model are you?"}],"max_tokens":300}' \
  | jq '{response_model: .model, content: .choices[0].message.content}'
# → response_model: "Qwen/Qwen3.5-122B-A10B"
# → content: "I am Qwen3.5."
```

**3. Public-Git chain (the inner YAML at the deployed commit confirms HF download is Qwen):**

```bash
curl -s "https://cloud-api.near.ai/v1/attestation/report?model=deepseek-ai/DeepSeek-V3.1&nonce=$(openssl rand -hex 32)" \
  -H "Authorization: Bearer $NEAR_API_KEY" \
  | jq -r '.model_attestations[0].compose_manager_attestation.actions
           | map(select(.action=="compose_up")) | last
           | "https://raw.githubusercontent.com/nearai/cvm-compose-files/\(.commit)/\(.file)"' \
  | xargs curl -s | grep "hf download "
# →     uvx --from 'huggingface_hub[hf_xet]' hf download Qwen/Qwen3.5-122B-A10B
```

So this is not a labeling bug — the inner YAML at the deployed commit (`Qwen3.5-122B.yaml`) consistently downloads Qwen weights, sets `MODEL_NAME=Qwen/Qwen3.5-122B-A10B`, and runs vllm with `--model Qwen/Qwen3.5-122B-A10B`. The `deepseek-ai/DeepSeek-V3.1` row in the `models` table simply has its `inference_url` pointing at this Qwen backend.

## Where the gateway should catch this

[`crates/services/src/inference_provider_pool/mod.rs::PoolBackendVerifier::create_verified_client`](https://github.com/nearai/cloud-api/blob/main/crates/services/src/inference_provider_pool/mod.rs) (around line 131) sends `self.model_name` as the `model` query parameter (line 162), receives the attestation report, and calls `verify_attestation_report` (line 196). The TDX/RTMR3/GPU verification all pass — but the gateway never checks that the report's `model_attestations[].model_name` equals `self.model_name`. Since the backend's `vllm-proxy-rs` honestly reports its loaded model in the response, a one-liner check after `verify_attestation_report` would have refused this binding:

```rust
let returned = report
    .get("model_attestations")
    .and_then(|m| m.as_array()).and_then(|a| a.first())
    .and_then(|m| m.get("model_name")).and_then(|n| n.as_str())
    .unwrap_or("");
if !returned.is_empty() && returned != self.model_name {
    return Err(format!(
        "Backend returned model_name={returned:?} but pool configured for {:?} — \
         silent substitution rejected", self.model_name));
}
```

That would force the gateway to either find a real DeepSeek-V3.1 TD (if the catalog row's `inference_url` is wrong / pointing at a deprecated backend) or 503 with a clear error.

## Why this matters beyond labeling

Per the inner compose, the KMS-derived signing key for the served TD is bound to `(app_id, MODEL_NAME)` where `MODEL_NAME=Qwen/Qwen3.5-122B-A10B`. A user encrypting an E2EE payload to `signing_pubkey` from this attestation is encrypting to the **Qwen3.5 TD's key**, not a DeepSeek TD's key. If the user trusts the attestation's signing-key-to-address binding (which checks out cryptographically), they have no protocol-level signal that the model running is different from what the catalog promised.

This is upstream of the on-chain anchoring concern in #224 — that issue is about whether the gateway verifies *cryptographically*; this is about whether the gateway checks *catalog identity ↔ served model*. They're independently fixable.

## Observed 2026-05-05

- Backend `signing_address=0x6525e128afcffebf7eed05d485d7be983cdae934`
- Inner YAML: `Qwen3.5-122B.yaml @ cc38dabcfac34b6d3873111e33df4ba5e6cc73cf` (file_sha256 `ddc1f3fd16a987171880cbe2957a711ad7b550e546bbffbb2e94c5744df02e71`)
- Outer compose_hash: `0x242a62724303cc32f364da0fc92738706b0078e7587821b7ba3e75488223797b`

## Suggested resolution

1. Add the `model_name`-equality check (or equivalent) to `PoolBackendVerifier::create_verified_client` so a backend's reported `model_name` must equal the requested model.
2. Either remove `deepseek-ai/DeepSeek-V3.1` from the catalog (if it's been deprecated) or update its `inference_url` to point at a real DeepSeek-V3.1 TD.

---

## To file

```bash
gh issue create --repo nearai/cloud-api \
  --title "Silent model substitution: catalog deepseek-ai/DeepSeek-V3.1 returns Qwen/Qwen3.5-122B-A10B; gateway never checks attested model_name matches request" \
  --body-file case-studies/near-ai-private-inference/CLOUD-API-ISSUE-DRAFT-model-substitution.md
```
