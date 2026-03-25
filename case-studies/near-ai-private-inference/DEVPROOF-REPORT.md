# NEAR AI Private Inference - Audit Analysis

**Audited:** 2026-03-25
**Domain:** cloud-api.near.ai
**Core Question:** Can we verify that (a) user prompts/responses remain private and (b) the claimed model is what actually runs?

## Executive Summary

| Component | Verifiable? | Notes |
|-----------|-------------|-------|
| TLS termination in TEE | ✅ Yes | Cert managed by certbot inside CVM, SPKI hash bound to attestation |
| Gateway CVM code (cloud-api) | ✅ Yes | Compose hash in RTMR3 via dstack |
| Backend CVM boot compose | ✅ Yes | compose-manager + certbot + datadog attested in mr_config |
| Inner compose (vllm + proxy) | ❌ No | Deployed by compose-manager AFTER boot, not in RTMR3 |
| inference-proxy signing | ✅ Yes | ECDSA + Ed25519 dual signatures, keys from dstack KMS |
| NVIDIA GPU attestation | ✅ Yes | GPU evidence via NRAS, same nonce as TDX quote |
| cloud-api → backend routing | ❌ No | MODEL_DISCOVERY_SERVER_URL is runtime env var |
| Model weight identity | ❌ No | vLLM downloads from HuggingFace by name, no checksum |
| HuggingFace endpoint | ❌ No | HF_ENDPOINT env var configurable, not attested |
| Operator log access | ❌ No | compose-manager /compose/logs returns raw container output |
| .decrypted-env secrets | ❌ No | Plaintext on host-shared folder, readable by host |
| Runtime model switching | ❌ No | Operator can call /compose/up with different model YAML |

---

## Architecture

```
                                    INTERNET
                                        │
                                   HTTPS (sk-...)
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  cloud-api CVM  (Intel TDX)                                                    │
│  Repo: nearai/cloud-api (Rust/Axum)                                            │
│  Attested: gateway_attestation in /v1/attestation/report                       │
│                                                                                 │
│  MODEL_DISCOVERY_SERVER_URL (runtime env var, NOT in compose)                  │
│  → polls every 5min, creates VLlmProvider per backend                          │
│  → probes attestation at discovery time                                        │
│  → routes chat/completions to provider pool                                    │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                                HTTP (or HTTPS, depends on discovery base_url)
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  Backend CVM  (Intel TDX + NVIDIA GPU TEE)                                     │
│                                                                                 │
│  BOOT COMPOSE (attested in mr_config / RTMR3):                                │
│  ├── compose-manager (nearai/compose-manager, Rust)                            │
│  │   Source: github.com/nearai/compose-manager                                 │
│  │   Config: GITHUB_REPO=nearai/cvm-compose-files                             │
│  │   API: /compose/up, /compose/down, /compose/logs, /docker/*                │
│  │   Auth: BEARER_TOKEN (operator-controlled)                                  │
│  │   Port: 8080 (not exposed through nginx or cloud-api)                      │
│  │   Has own /v1/attestation/report with deployment action history             │
│  │   ⚠ Does NOT call emit_event — inner compose NOT measured in RTMR3         │
│  ├── certbot/dns-cloudflare (TLS cert management)                             │
│  └── datadog-agent (DD_LOGS_CONFIG_CONTAINER_COLLECT_ALL=true)                │
│                                                                                 │
│  INNER COMPOSE (pulled by compose-manager from GitHub, NOT attested):          │
│  ├── nginx (TLS termination, routes to inference-proxy:8000)                   │
│  ├── inference-proxy (nearaidev/vllm-proxy-rs, pinned @sha256)                │
│  │   Source: nearai/inference-proxy (Rust)                                     │
│  │   Signs: "{model_name}:{sha256_request}:{sha256_response}"                 │
│  │   Keys: dstack KMS derived, ECDSA + Ed25519                                │
│  │   Attestation: TDX quote + NVIDIA GPU evidence                             │
│  │   NO model weight verification                                              │
│  ├── vllm-openai (pinned @sha256, downloads model from HuggingFace)           │
│  │   Model: specified in compose command arg (e.g. deepseek-ai/DeepSeek-V3.1) │
│  │   Weights: cached in named Docker volume (persistent, pre-loadable)        │
│  │   HF_ENDPOINT: not set, defaults to huggingface.co, configurable           │
│  ├── model-proxy-registrar (self-registers with completions.near.ai)          │
│  └── dcgm-exporter (GPU metrics)                                              │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Deployment Info

| Service | Image | Pinned? |
|---------|-------|---------|
| compose-manager | `nearaidev/compose-manager@sha256:a3c6e22...` | ✅ By digest in boot compose |
| inference-proxy | `nearaidev/vllm-proxy-rs@sha256:4f6024b...` | ✅ By digest in inner compose |
| vllm-openai | `vllm/vllm-openai@sha256:0dc46f7...` (v0.17.1) | ✅ By digest in inner compose |
| nginx | `nginx@sha256:1d13701...` | ✅ By digest in inner compose |
| datadog-agent | `datadog/agent@sha256:5556fb8...` | ✅ By digest in boot compose |
| certbot | `certbot/dns-cloudflare@sha256:742dbd2...` | ✅ By digest in boot compose |

---

## Data Flow Analysis

### 1. TLS Termination (VERIFIED ✅)

TLS terminates inside the CVM via nginx. Certificates managed by certbot with Cloudflare DNS-01 challenge. inference-proxy computes SPKI hash of the TLS cert and includes it in attestation report_data when `include_tls_fingerprint=true`.

```
report_data = [SHA256(signing_address || cert_fingerprint)][nonce]
```

Source: `inference-proxy/src/attestation.rs:472-493`

Host sees only encrypted TLS traffic. TDX memory encryption prevents host from reading plaintext.

### 2. Attestation Chain (PARTIALLY VERIFIED ⚠️)

**What's measured (boot compose → RTMR3):**
- compose-hash event: SHA256 of boot app-compose.json
- app-id event: first 20 bytes of compose hash
- instance-id, key-provider events
- Measured at: `dstack-util/src/system_setup.rs:1314-1318`

**What's NOT measured (inner compose):**
- compose-manager deploys vllm + inference-proxy AFTER boot
- compose-manager does NOT call `emit_event()` (confirmed: only dstack RPC is `GetQuote`)
- dstack's `emit_runtime_event` API IS available post-boot and unrestricted
- dstack's `verify_tdx()` DOES replay all events including post-boot (`None` stop point)
- **The infrastructure to close this gap exists — compose-manager just doesn't use it**

Source: `compose-manager/src/main.rs` — only 2 dstack calls, both `get_quote`

### 3. NVIDIA GPU Attestation (VERIFIED ✅)

GPU evidence collected locally via `cc_admin.collect_gpu_evidence_remote()` (persistent Python subprocess).
Same nonce used for both TDX quote and GPU evidence (temporal binding).
GPU attestation verified via NVIDIA NRAS at `nras.attestation.nvidia.com/v3/attest/gpu`.

Binding is indirect: TDX proves specific code is running → that code collects local GPU evidence → therefore GPU evidence is from this machine. No direct hardware-level CPU↔GPU cryptographic binding.

Source: `inference-proxy/src/attestation.rs:725-802`, `gpu_evidence_worker.py`

### 4. cloud-api → Backend Routing (NOT VERIFIED ❌)

`MODEL_DISCOVERY_SERVER_URL` is a runtime environment variable. cloud-api polls it every 5 minutes for `{IP:PORT → model_name}` mappings. Probes attestation at discovery time but does not re-verify per request.

Source: `cloud-api/crates/services/src/inference_provider_pool/mod.rs:305-333`

### 5. Model Identity (NOT VERIFIED ❌)

- vLLM downloads weights from HuggingFace by model name (e.g. `deepseek-ai/DeepSeek-V3.1`)
- `HF_ENDPOINT` env var not set in compose, defaults to `https://huggingface.co`, configurable by operator
- HuggingFace hub library does NOT auto-verify SHA256 (huggingface_hub issue #2364)
- Named Docker volume `hugginface_cache` is persistent — operator could pre-load weights
- No model revision pinning (git commit hash) in any compose file
- inference-proxy confirmed: zero weight verification code

Source: `cvm-compose-files/DeepSeek-V3.1.yaml:93-110`

### 6. Runtime Model Switching (NOT PREVENTED ❌)

Operator (holding BEARER_TOKEN) can:
1. `POST /compose/down` — stop current model containers
2. `POST /compose/up` with different `file` (e.g. switch from DeepSeek to Qwen YAML)
3. New containers start with different MODEL_NAME, different vLLM model
4. RTMR3 unchanged — boot compose didn't change

Validation: MIN_TAG_AGE_HOURS=2 (must use git tags ≥2 hours old). All current tags pass.
No auto-deploy on startup — compose-manager starts empty, waits for API calls.

Source: `compose-manager/src/main.rs:663-746` (compose_up handler)

---

## Privacy Analysis

### Protected from cloud provider ✅

TDX hardware guarantees:
- CVM memory encrypted, host cannot read
- TLS terminates inside CVM
- Signing keys derived in TEE via dstack KMS

### Operator exfiltration paths ❌

**compose-manager /compose/logs (CRITICAL):**
- Returns raw `docker compose logs` output for any container
- No filtering or sanitization
- Only gate: BEARER_TOKEN (set by operator)
- Source: `compose-manager/src/main.rs:813-832`

**.decrypted-env on host-shared folder (CRITICAL):**
- dstack decrypts env vars and writes plaintext to `/dstack/.host-shared/.decrypted-env`
- Host can read this — dstack docs acknowledge it
- Contains: DD_API_KEY, BEARER_TOKEN, HUGGING_FACE_HUB_TOKEN
- Source: `dstack/docs/security/cvm-boundaries.md:114-120`

**Datadog agent (MEDIUM-HIGH):**
- DD_LOGS_ENABLED=true, DD_LOGS_CONFIG_CONTAINER_COLLECT_ALL=true
- Collects ALL container logs, sends to operator-controlled endpoint
- Actual risk depends on inference-proxy/vLLM logging discipline

**Mitigations in place:**
- inference-proxy logs only status codes, not content (`proxy.rs` logging analysis)
- Has `sanitize_validation_errors()` to strip input/ctx from backend errors
- cloud-api CLAUDE.md has strict "never log customer data" policy
- vLLM set to VLLM_LOGGING_LEVEL=WARNING in all compose files

**Key trust boundary:** dstack protects from cloud provider (hardware), NOT from operator (software). The operator (NEAR) deployed the compose, set the env vars, holds the BEARER_TOKEN.

---

## Concerns Summary

### Critical Gaps

1. **Inner compose not in RTMR3** — the actual model and proxy containers are deployed post-boot and unmeasured. compose-manager tracks deployment actions in memory but doesn't emit_event to extend RTMR3.

2. **Operator can exfiltrate via /compose/logs** — raw container log access with only BEARER_TOKEN auth. If any component logs request/response content, operator gets it.

3. **.decrypted-env readable by host** — plaintext secrets on shared folder. dstack design choice, not a bug.

4. **Model weights unverified** — HuggingFace download by name, no checksum, configurable endpoint.

5. **Runtime model switching** — operator can switch models via compose-manager API without any change to attestation.

### Moderate Concerns

6. **Datadog agent collects all logs** — overpermissive DD_LOGS_CONFIG_CONTAINER_COLLECT_ALL=true

7. **HuggingFace endpoint redirectable** — HF_ENDPOINT env var not pinned

8. **compose-manager source was only recently public** — limited external review

### Verified Good

9. **TLS in TEE** — cert bound to attestation, host sees only ciphertext
10. **Dual signing** — ECDSA + Ed25519, deterministic, keys from KMS
11. **Docker images pinned by digest** — both boot and inner compose use @sha256
12. **inference-proxy logging discipline** — does not log request/response content
13. **NVIDIA GPU attestation** — genuine hardware, same-nonce binding to TDX

---

## Stage Assessment

Following ERC-733 / DevProof framework:

**Privacy (protection from cloud provider):** Stage 1-2
- Hardware isolation verified (TDX + GPU TEE)
- Code identity verified for boot compose
- TLS terminates inside TEE
- Weakened by: Datadog agent, compose-manager /compose/logs path

**Privacy (protection from operator):** Stage 0
- Operator holds BEARER_TOKEN for compose-manager
- Operator can access .decrypted-env
- Operator controls MODEL_DISCOVERY_SERVER_URL
- Operator can switch deployed models
- Datadog sends logs to operator's endpoint

**Model Identity:** Stage 0
- Inner compose not in RTMR3
- Model weights not checksummed
- HuggingFace endpoint not pinned
- Runtime model switching possible

---

## Recommendations

### Close the inner compose gap (highest impact)
compose-manager should call `emit_event("inner-compose-hash", sha256_of_yaml)` after each `/compose/up`. dstack's `emit_runtime_event` API is unrestricted, verifiers already replay post-boot events. This is a small code change.

### Expose compose-manager attestation
cloud-api should forward compose-manager's `/v1/attestation/report` (which includes the deployment action history with file SHA256) to users, so they can verify what was deployed.

### Pin HuggingFace endpoint and model revision
Set `HF_ENDPOINT=https://huggingface.co` explicitly in compose files. Pin model revisions by git commit hash instead of just model name.

### Restrict Datadog collection
Set `DD_LOGS_CONFIG_CONTAINER_COLLECT_ALL=false` and explicitly allowlist only known-safe log sources.

### Protect compose-manager API
Add mTLS or stronger auth beyond BEARER_TOKEN. Rate-limit /compose/logs. Audit log all access.

---

## Source Code

| Component | Repository | Key Files |
|-----------|-----------|-----------|
| cloud-api | [nearai/cloud-api](https://github.com/nearai/cloud-api) | `crates/services/src/inference_provider_pool/mod.rs`, `crates/services/src/attestation/mod.rs` |
| inference-proxy | [nearai/inference-proxy](https://github.com/nearai/inference-proxy) | `src/attestation.rs`, `src/signing.rs`, `src/proxy.rs` |
| compose-manager | [nearai/compose-manager](https://github.com/nearai/compose-manager) | `src/main.rs` |
| cvm-compose-files | [nearai/cvm-compose-files](https://github.com/nearai/cvm-compose-files) | `DeepSeek-V3.1.yaml`, `small-models.yaml` |
| private-ml-sdk | [nearai/private-ml-sdk](https://github.com/nearai/private-ml-sdk) | `vllm-proxy/` (Python, superseded by inference-proxy) |
| dstack | [Dstack-TEE/dstack](https://github.com/Dstack-TEE/dstack) | `dstack-attest/src/attestation.rs`, `guest-agent/src/rpc_service.rs` |
| verification example | [near-examples/nearai-cloud-verification-example](https://github.com/near-examples/nearai-cloud-verification-example) | `app.js`, `utils/` |

## Prior Art

- NEAR Private Chat audit: `case-studies/near-private-chat/DEVPROOF-REPORT.md` (2026-01-09)
- Model weight gap first raised: https://x.com/socrates1024/status/1953135192769724843 (2025-08-06)
- Phala co-founder acknowledged the gap in the same thread
