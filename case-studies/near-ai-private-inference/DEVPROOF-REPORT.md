# NEAR AI Private Inference - Audit Analysis

**Server-side audit:** 2026-03-25
**Client-side E2EE audit:** 2026-04-19
**Domain:** cloud-api.near.ai
**Core Question:** Can we verify that (a) user prompts/responses remain private and (b) the claimed model is what actually runs?

---

## Executive Summary

| Component | Verifiable? | Notes |
|-----------|-------------|-------|
| TLS termination in TEE | ✅ Yes | Cert managed by certbot inside CVM, SPKI hash bound to attestation |
| Gateway CVM code (cloud-api) | ✅ Yes | Compose hash in RTMR3 via dstack |
| Backend CVM boot compose | ✅ Yes | compose-manager + certbot + datadog attested in mr_config |
| Inner compose (vllm + proxy) | ❌ No | Deployed post-boot, not in RTMR3 — **breaks E2EE trust chain** |
| inference-proxy signing | ✅ Yes | ECDSA + Ed25519 dual signatures, keys from dstack KMS |
| NVIDIA GPU attestation (design) | ✅ Yes | GPU evidence via NRAS, same nonce as TDX quote |
| NVIDIA GPU attestation (live) | ❌ Failing | NRAS returning persistent FAIL verdicts, April 2026 |
| cloud-api → backend routing | ❌ No | Signing keys TOFU from unverified JSON; Issue #224 open 4+ months |
| nearai-cloud-verifier E2EE | ❌ Broken | Fetches signing_public_key without verifying model TDX quote |
| private-ai-verifier E2EE | ❌ Missing | Full TDX chain but no E2EE implementation at all |
| Model weight identity | ❌ No | vLLM downloads from HuggingFace by name, no checksum |
| Operator log access | ❌ No | compose-manager /compose/logs returns raw container output |
| Runtime model switching | ❌ No | Operator can call /compose/up with different model YAML |
| Platform TCB | ⚠️ Outdated | ~80% of requests hit OutOfDate TCB (INTEL-SA-01036 et al) |

---

## Architecture

```
                                    INTERNET
                                        │
                                   HTTPS (sk-...)
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  cloud-api CVM  (Intel TDX)                  nearai/cloud-api                  │
│  Attested: gateway_attestation in /v1/attestation/report                       │
│                                                                                 │
│  MODEL_DISCOVERY_SERVER_URL (runtime env var)                                  │
│  → polls every 5min, creates VLlmProvider per backend                          │
│  → probes /v1/attestation/report at discovery time — NO verification           │
│  → routes chat/completions to provider pool                                    │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                HTTP / HTTPS
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  Backend CVM  (Intel TDX + NVIDIA GPU TEE)                                     │
│                                                                                 │
│  BOOT COMPOSE (attested in mr_config / RTMR3):                                │
│  ├── compose-manager  nearai/compose-manager                                   │
│  │   API: /compose/up, /compose/down, /compose/logs                            │
│  │   Auth: BEARER_TOKEN (operator-controlled)                                  │
│  │   ⚠ Does NOT call emit_event — inner compose NOT measured in RTMR3         │
│  ├── certbot/dns-cloudflare                                                    │
│  └── datadog-agent  (DD_LOGS_CONFIG_CONTAINER_COLLECT_ALL=true)               │
│                                                                                 │
│  INNER COMPOSE (pulled from GitHub by compose-manager, NOT attested):          │
│  ├── nginx (TLS termination)                                                   │
│  ├── inference-proxy  nearai/inference-proxy                                   │
│  │   Handles E2EE: decrypts prompts, signs responses, re-encrypts to client   │
│  │   Keys: SECP256K1 + Ed25519 from dstack KMS                                │
│  │   Attestation report: TDX quote + NVIDIA GPU evidence                      │
│  │   ⚠ Code not in RTMR3 — E2EE decryption runs in unattested container      │
│  ├── vllm-openai  (downloads model weights from HuggingFace by name)          │
│  ├── model-proxy-registrar                                                     │
│  └── dcgm-exporter                                                             │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Findings by Repo

### nearai/cloud-api

**Routing gap — signing keys are TOFU (Critical)**

`cloud-api` probes each backend's `/v1/attestation/report` at discovery time but performs zero cryptographic verification. `get_attestation_report()` sends an HTTP GET, parses JSON, and returns it. `signing_public_key` is read directly from the unverified response and stored as the E2EE key. Any backend that returns plausible JSON is accepted into the provider pool.

`_has_valid_attestation` — the return value of the attestation check — is assigned to `_` (discarded) at [`inference_provider_pool/mod.rs:1371`](https://github.com/nearai/cloud-api/blob/2cb48d2c54da/crates/services/src/inference_provider_pool/mod.rs#L1371). A backend that fails attestation entirely is still added to the pool.

This is the root of the TOFU problem: `MODEL_DISCOVERY_SERVER_URL` is a runtime env var, the operator controls which backends receive requests, and the signing keys those backends advertise are accepted without verification. A malicious backend can claim any public key. Prompts "encrypted" to that key are readable by the backend.

Source: [`vllm/mod.rs:307-376`](https://github.com/nearai/cloud-api/blob/2cb48d2c54da/crates/inference_providers/src/vllm/mod.rs#L307-L376), [`inference_provider_pool/mod.rs:244-289`](https://github.com/nearai/cloud-api/blob/2cb48d2c54da/crates/services/src/inference_provider_pool/mod.rs#L244-L289)

[Issue #224](https://github.com/nearai/cloud-api/issues/224) (open since Dec 2025): "cloud-api should verify the attestation quotes from the models and only add the verified model nodes."

---

### nearai/inference-proxy

**E2EE mechanism — correct design, unattested code**

inference-proxy implements E2EE correctly in design. Each model CVM generates a SECP256K1 keypair at boot via dstack KMS. The public key is published in the attestation report as `signing_public_key`. The Ethereum address (`keccak256(pubkey)[12:]`) is embedded in `report_data[0:32]`, binding the key to the TDX quote.

The encryption scheme is ECIES on SECP256K1:
- Client generates an ephemeral keypair per request
- Encrypts each message: `eph_pubkey(65) || nonce(12) || AES-GCM(HKDF-SHA256(ECDH(eph_priv, model_pub)))`
- Sends headers: `X-Signing-Algo: ecdsa`, `X-Client-Pub-Key: <hex>`, `X-Model-Pub-Key: <hex>`
- inference-proxy decrypts with its private key, runs the prompt through vLLM, encrypts the response to the client's ephemeral key

`report_data` layout:
```
[0:32]  = SHA256(signing_address_bytes || tls_cert_fingerprint_bytes)   (gateway)
        = signing_address padded to 32 bytes                             (model)
[32:64] = raw nonce bytes
```

Source: `src/attestation.rs:472-493`, `src/signing.rs`

**The gap:** inference-proxy is in the inner compose, deployed post-boot by compose-manager. The TDX quote from the model CVM attests to the boot compose (compose-manager + certbot + datadog) — not to inference-proxy. A client who verifies the TDX quote and encrypts to the hardware-bound key has verified that *compose-manager* is running on real hardware. The code that *decrypts their prompt* is unattested.

**GPU attestation — design correct, live status failing**

GPU evidence collected via `cc_admin.collect_gpu_evidence_remote()`. Same nonce used for both TDX quote and GPU evidence (temporal binding). Verified via NVIDIA NRAS at `nras.attestation.nvidia.com/v3/attest/gpu`.

As of April 2026 live testing, NRAS is returning a boolean `False` verdict — not `"PASS"` — persistently across multiple requests and retry attempts. Root cause unknown; likely a backend enrollment or certificate issue on NEAR AI's side. Official verifiers either skip GPU attestation or treat FAIL as non-fatal, masking this.

Source: `src/attestation.rs:725-802`, `gpu_evidence_worker.py`

---

### nearai/compose-manager

**Inner compose not in RTMR3 (Critical)**

compose-manager deploys vllm + inference-proxy after boot via `/compose/up`. It does not call `emit_event()` to extend RTMR3 with the inner compose hash. The only dstack RPCs it makes are `get_quote` calls.

The infrastructure to close this gap exists: dstack's `emit_runtime_event` API is available post-boot and unrestricted, and `verify_tdx()` replays all events including post-boot ones. compose-manager just doesn't use it.

Source: `src/main.rs` — search for dstack socket calls; only `GetQuote` present.

**Operator exfiltration via /compose/logs (Critical)**

`POST /compose/logs` returns raw `docker compose logs` output for any container. No filtering. Only gate is BEARER_TOKEN, which is operator-controlled. If any container logs request/response content, the operator receives it via this endpoint.

Mitigations in place: inference-proxy logs only status codes (not content), `sanitize_validation_errors()` strips input from backend errors, vLLM set to `VLLM_LOGGING_LEVEL=WARNING`. These reduce risk but are not cryptographic guarantees.

Source: `src/main.rs:813-832`

**Runtime model switching (Critical)**

Operator can `POST /compose/down` then `POST /compose/up` with a different YAML file to swap the running model. RTMR3 is unchanged — the boot compose didn't change. MIN_TAG_AGE_HOURS=2 prevents using freshly-created tags but all existing tags pass.

Source: `src/main.rs:663-746`

---

### nearai/cvm-compose-files

**Model weight identity not verified**

vLLM downloads weights from HuggingFace by model name only (e.g. `deepseek-ai/DeepSeek-V3.1`). No revision pinning, no checksum verification. `HF_ENDPOINT` is not set in compose files, defaulting to `huggingface.co` but configurable by operator. Named Docker volume `huggingface_cache` is persistent — weights could be pre-loaded by the operator.

HuggingFace hub library does not auto-verify SHA256 (huggingface_hub issue #2364). inference-proxy has zero weight verification code.

Source: `DeepSeek-V3.1.yaml:93-110`

---

### nearai-cloud-verifier (near-examples/nearai-cloud-verification-example)

**E2EE key accepted without model TDX verification**

`encrypted_chat_verifier.py::fetch_model_public_key` fetches `/v1/attestation/report` and reads `signing_public_key` directly from the JSON response — without calling `check_tdx_quote` on the model attestation. The ECIES implementation (`encrypted_chat_verifier.py`) is correct; the trust chain establishing the key is not.

A gateway that controls the JSON response can substitute any public key. Prompts encrypted to that key are readable by the gateway. This is TOFU at the client layer, compounding the server-side TOFU in cloud-api.

---

### private-ai-verifier (Phala-Network/private-ai-verifier)

**Full TDX verification but no E2EE**

`NearAICloudVerifier` correctly runs the full dstack verification chain — TDX quote, GPU, compose hash, report_data — for both gateway and model attestations. This is the correct approach for establishing trust in the hardware.

But it never reads `signing_public_key` from `model_attestations` and has no E2EE implementation. An audit based solely on this SDK establishes that the TEE is real but does nothing to protect prompt confidentiality in transit.

---

## Client-Side Verification Chain

For a client to establish genuine E2EE, it must verify the following before trusting the signing key. Each step eliminates one class of attack:

| Step | Eliminates |
|------|-----------|
| 1. Gateway TDX quote | Fake gateway (no real TDX) |
| 2. Gateway report_data | Replayed attestation; gateway not bound to this TLS cert |
| 3. TLS cert match | TDX enclave ≠ server answering this HTTPS connection |
| 4. Model TDX quote | Gateway substituting fake model attestation |
| 5. Model report_data | Model attestation not bound to this request nonce |
| 6. GPU attestation | Model running on non-CC GPU |
| 7. Key → address binding | Gateway substituting a fake signing_public_key |
| 8. Compose hash | Model CVM running different image than reported |

**Step 7 in code:**
```python
from eth_keys.datatypes import PublicKey
derived = "0x" + PublicKey(bytes.fromhex(signing_public_key)).to_canonical_address().hex()
assert derived.lower() == signing_address.lower()
```

**Residual gap after all 8 steps:** Steps 4–8 verify the boot compose measurement. inference-proxy (the code that decrypts the prompt) is in the inner compose and is not covered by that measurement. See the compose-manager section above.

A reference implementation of all 8 steps is in `hermes-agent` (`feat/near-ai-attestation` branch, `hermes_cli/attestation.py` + `hermes_cli/e2ee_proxy.py`).

---

## Live Findings (April 2026)

**OutOfDate platform TCB**
~80% of requests hit platforms with `OutOfDate` TCB. Advisories: INTEL-SA-01036, -01079, -01099, -01103, -01111. Known firmware vulnerabilities. Official verifiers accept OutOfDate as valid.

**NRAS persistent FAIL verdicts**
GPU attestation via NRAS returns `False` (not `"PASS"`) consistently across multiple retries. A client enforcing GPU attestation as mandatory cannot complete verification. Official verifiers mask this by skipping GPU or treating FAIL as non-fatal.

---

## Privacy Analysis

**Protected from cloud provider ✅**
TDX hardware guarantees CVM memory is encrypted. TLS terminates inside CVM. Signing keys derived in TEE.

**Not protected from operator ❌**
Operator holds BEARER_TOKEN, controls MODEL_DISCOVERY_SERVER_URL, can access `.decrypted-env` (plaintext secrets on host-shared folder), can access raw logs via /compose/logs, and can switch deployed models without changing RTMR3.

**Not protected via E2EE (currently) ❌**
Even with correct client-side verification, the code that decrypts prompts (inference-proxy) is not measured in RTMR3. NRAS is failing. OutOfDate TCB on ~80% of fleet.

---

## Recommendations

**compose-manager: emit inner compose hash (highest impact)**
Call `emit_event("inner-compose-hash", sha256_of_yaml)` after each `/compose/up`. One small code change; closes the gap between boot attestation and the code that handles decrypted prompts.

**cloud-api: verify backend TDX quotes (Issue #224)**
Run `check_tdx_quote` on each backend's attestation before accepting its signing key into the pool. The `private-ai-verifier` SDK already implements this correctly and can be called from Rust via subprocess or FFI.

**nearai-cloud-verifier: verify model TDX quote before using signing key**
In `fetch_model_public_key`, call `check_tdx_quote(model_attestation)` and verify `report_data` before returning `signing_public_key`. Two lines of code; closes the client-side TOFU gap.

**Fix NRAS registration for model CVMs**
GPU attestation is failing at NRAS. Until fixed, clients enforcing GPU attestation (which they should) cannot verify the fleet.

**Pin HuggingFace endpoint and model revision**
Set `HF_ENDPOINT=https://huggingface.co` explicitly. Pin model weights by git commit hash.

**Restrict Datadog and compose-manager log access**
Set `DD_LOGS_CONFIG_CONTAINER_COLLECT_ALL=false`. Add audit logging and rate-limiting to `/compose/logs`.

---

## Stage Assessment

**Privacy (from cloud provider):** Stage 1–2
Hardware isolation and TLS in TEE verified. Weakened by Datadog and /compose/logs path.

**Privacy (from operator):** Stage 0
Operator controls deployment, holds secrets, can access logs.

**E2EE (prompt confidentiality):** Stage 0 (currently)
Mechanism exists and is correctly designed. Blocked by: inner compose not in RTMR3, NRAS failing, OutOfDate TCB, TOFU key in official SDK.

**Model Identity:** Stage 0
Inner compose not in RTMR3, weights unverified, runtime switching possible.

---

## Source Code

| Component | Repository | Key Files |
|-----------|-----------|-----------|
| cloud-api | [nearai/cloud-api](https://github.com/nearai/cloud-api) | `crates/services/src/inference_provider_pool/mod.rs` |
| inference-proxy | [nearai/inference-proxy](https://github.com/nearai/inference-proxy) | `src/attestation.rs`, `src/signing.rs`, `src/proxy.rs` |
| compose-manager | [nearai/compose-manager](https://github.com/nearai/compose-manager) | `src/main.rs` |
| cvm-compose-files | [nearai/cvm-compose-files](https://github.com/nearai/cvm-compose-files) | `DeepSeek-V3.1.yaml` |
| nearai-cloud-verifier | [near-examples/nearai-cloud-verification-example](https://github.com/near-examples/nearai-cloud-verification-example) | `encrypted_chat_verifier.py`, `model_verifier.py` |
| private-ai-verifier | [Phala-Network/private-ai-verifier](https://github.com/Phala-Network/private-ai-verifier) | `nearai_verifier.py` |
| dstack | [Dstack-TEE/dstack](https://github.com/Dstack-TEE/dstack) | `dstack-attest/src/attestation.rs` |
| reference E2EE impl | hermes-agent `feat/near-ai-attestation` | `hermes_cli/attestation.py`, `hermes_cli/e2ee_proxy.py` |

## Prior Art

- NEAR Private Chat audit: `case-studies/near-private-chat/DEVPROOF-REPORT.md` (2026-01-09)
- Model weight gap first raised: https://x.com/socrates1024/status/1953135192769724843 (2025-08-06)
