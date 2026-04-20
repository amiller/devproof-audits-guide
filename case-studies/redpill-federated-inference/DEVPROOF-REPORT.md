# Redpill Federated TEE Inference — Audit Analysis

**Server-side audit:** 2026-04-20
**Domain:** `api.red-pill.ai`
**Core Question:** Redpill presents a single `phala/*` model namespace, but
routes to four distinct TEE backends under the hood. Can a client verify
each one, and does the shape-dispatch produce a coherent privacy story?

---

## Executive Summary

Redpill's `/v1/attestation/report` endpoint returns **four distinct response
shapes**, one per backend type. A client that only knows one shape will
silently fall through to "unverifiable" on three quarters of the catalog.

| Backend shape           | Attestation class | What the verifier must do                          | Probe time (p50) |
|-------------------------|-------------------|----------------------------------------------------|-----------------:|
| `phala-simple`          | Phala TDX + GPU   | Top-level `intel_quote` + NRAS GPU                 | ~3s              |
| `nearai-via-redpill`    | NEAR AI gateway   | `gateway_attestation` + `model_attestations[]` (re-uses NEAR AI verifier) | 3–80s   |
| `chutes`                | Chutes TDX        | `all_attestations[]` × 5 instances, anti-tamper binding, debug-mode check | 35–94s  |
| `tinfoil` (unobserved)  | Tinfoil hw-policy | Sigstore golden values, hw policy attestation     | —                |

**The shape is not in the OpenAPI spec.** The only way to know which
verifier to run is to inspect the response JSON:

```python
if report.get("attestation_type") == "chutes":
    return verify_chutes(report, ...)
if "gateway_attestation" in report:
    return verify_nearai_gateway(report, ...)
if "intel_quote" in report:
    return verify_phala_simple(report, ...)
return fail("Unrecognized attestation response format")
```

This is a documentation gap, not a soundness bug — but it's load-bearing
for anyone building strict client-side verification.

---

## Per-model probe results — 2026-04-20

Probed `api.red-pill.ai/v1` with the hermes-cli strict verifier. Four-shape
dispatch, no fallbacks. `max_workers=6`, full probe ~94s (bounded by the
slowest Chutes response).

| Model                                       | Backend              | Verdict | Probe time | Error |
|---------------------------------------------|----------------------|:-------:|-----------:|-------|
| `phala/gpt-oss-20b`                         | phala-simple         | ✅ pass | 2.9s       |       |
| `phala/glm-4.7-flash`                       | phala-simple         | ✅ pass | 2.9s       |       |
| `phala/qwen-2.5-7b-instruct`                | phala-simple         | ✅ pass | 3.2s       |       |
| `phala/qwen2.5-vl-72b-instruct`             | phala-simple         | ✅ pass | 2.6s       |       |
| `phala/qwen3-vl-30b-a3b-instruct`           | phala-simple         | ✅ pass | 2.9s       |       |
| `phala/qwen3.5-27b`                         | phala-simple         | ✅ pass | 2.4s       |       |
| `phala/gemma-3-27b-it`                      | phala-simple         | ✅ pass | 3.4s       |       |
| `phala/uncensored-24b`                      | phala-simple         | ✅ pass | 2.7s       |       |
| `phala/glm-4.7`                             | nearai-via-redpill   | ✅ pass | 5.0s       |       |
| `phala/deepseek-chat-v3.1`                  | nearai-via-redpill   | ✅ pass | 79.1s      |       |
| `phala/deepseek-v3.2`                       | chutes               | ✅ pass | 35.7s      |       |
| `phala/kimi-k2.5`                           | chutes               | ✅ pass | 93.5s      |       |
| `phala/gpt-oss-120b`                        | nearai-via-redpill   | ❌ fail | 3.2s       | TDX quote verification failed: `ppid=ca98bce2d0f6c53afd2a37537fcc3c3a` `tcb_svn=0b010200000000000000000000000000` |
| `phala/glm-5`                               | nearai-via-redpill   | ❌ fail | 3.1s       | Same PPID as `gpt-oss-120b` — co-located on unpatched host |
| `phala/qwen3-30b-a3b-instruct-2507`         | nearai-via-redpill   | ❌ fail | 3.0s       | NVIDIA GPU attestation failed (NRAS `False`) |

**Shape distribution:** 8 Phala-simple, 5 NearAI-via-redpill, 2 Chutes, 0
Tinfoil.

---

## Architecture

```
                                   CLIENT
                                      │
                       ┌──────────────┴────────────────┐
                       │   api.red-pill.ai/v1          │
                       │   unified OpenAI-ish API      │
                       │   /v1/attestation/report      │
                       │   /v1/chat/completions        │
                       └──────────────┬────────────────┘
                                      │
            ┌─────────────────────────┼───────────────────────────┐
            │                         │                           │
            ▼                         ▼                           ▼
     Phala backend            NEAR AI fleet              Chutes backend
     (TDX + NRAS)             (cloud-api.near.ai)        (multi-instance TDX)
     Shape:                   Shape:                     Shape:
       intel_quote              gateway_attestation +     attestation_type=chutes
       nvidia_payload           model_attestations[]      all_attestations[] (×5)
                                                          e2e_pubkey anti-tamper
```

The "NEAR AI via Redpill" path is notable: Redpill's
`/v1/attestation/report?model=phala/X` for these models returns a
`gateway_attestation + model_attestations[]` bundle identical in shape to
`cloud-api.near.ai/v1/attestation/report?model=X`. The content likewise
matches — which is how we know those models are physically backed by NEAR
AI fleet CVMs. A failure on NEAR AI directly reproduces on Redpill. See:

- `phala/qwen3-30b-a3b-instruct-2507` (Redpill) and
  `Qwen/Qwen3-30B-A3B-Instruct-2507` (NEAR AI) — same NRAS `False` verdict.
- `phala/gpt-oss-120b` (Redpill) and `openai/gpt-oss-120b` (NEAR AI) —
  related failures.

Cross-reference: [near-ai-private-inference/DEVPROOF-REPORT.md](../near-ai-private-inference/DEVPROOF-REPORT.md).

---

## Chutes shape — anti-tamper binding

Unique to the Chutes backend: `all_attestations[]` contains N (observed 5)
instances, each with its own TDX quote, `e2e_pubkey`, and `nonce`. The
anti-tamper check binds the E2EE key into the TDX `report_data`:

```
SHA256(nonce || e2e_pubkey)  ==  report_data[0:32]
```

If this binding fails, the E2EE public key isn't hardware-bound and a MitM
could substitute keys. Our verifier rejects on mismatch.

**Debug-mode check:** the TDX `td_attributes & 1` bit indicates debug
enabled. In debug mode, the TEE offers no confidentiality guarantee and
must be rejected. Our verifier does so.

---

## Findings

1. **Four-shape dispatch is undocumented.** Client writers building strict
   verifiers today have to read Redpill's open-source verifier JavaScript
   implementation (`redpill-verifier/js/src/verifiers/{phala,nearai,chutes,tinfoil}.ts`)
   to know what shapes exist. Worth adding to the OpenAPI spec or a
   `backend_type` enum field.

2. **Two Phala-routed models share a broken host.** `phala/gpt-oss-120b`
   and `phala/glm-5` both TDX-fail with the same PPID
   `ca98bce2d0f6c53afd2a37537fcc3c3a` and same `tee_tcb_svn`
   `0b010200000000000000000000000000`. They are evidently co-located on a
   single CVM whose firmware hasn't been patched. Remediation is a fleet
   operation, not a per-model fix.

3. **Chutes attestation bundles are slow.** 35–94s per probe because the
   bundle packs 5 per-instance TDX quotes, each cross-verified via Phala's
   online verifier. Cacheable by the backend but currently isn't. For
   interactive flows (every `/model` selection would not tolerate this),
   strict attestation is an offline check only.

4. **Federated failure transparency.** When a Redpill `phala/*` model is
   actually backed by NEAR AI fleet and fails there, the Redpill error
   surfaces the NEAR AI TDX/GPU failure directly. This is good — the
   failure isn't laundered through an abstraction layer — but users who
   believe "I'm on Phala" may be confused why they see NEAR AI PPIDs in
   error messages.

---

## Recommendations

**Redpill: document the four shapes.** Add a `backend_type` field or a
separate `/v1/attestation/shape?model=...` endpoint so clients can pick
the verifier without response-shape sniffing.

**Redpill: cache Chutes attestation bundles server-side.** 5× per-instance
TDX re-verification on every client call is wasteful; a short-TTL cache
(60s) with nonce freshness proof would drop p99 probe latency by an order
of magnitude.

**Redpill + NEAR AI: shared fleet health dashboard.** Since some Redpill
models are NEAR AI CVMs, an unpatched firmware node on the NEAR side
surfaces as a broken Redpill model. A shared health/advisory dashboard
would help both teams coordinate remediation.

---

## Stage Assessment

**Verifiability: partial.** Three of four documented shapes have working
reference verifiers. Strict-mode client-side verification is possible
today for 12 of 15 curated `phala/*` models; the 3 failing are upstream
fleet-health issues, not verifier gaps.

**Privacy posture: competitive with NEAR AI and Phala direct.**
Inherits the same TEE guarantees as whichever backend routes the request.
The federation layer doesn't add privacy risk but also doesn't add
privacy beyond the underlying TEE.

**Biggest gap:** shape-dispatch isn't part of the public API contract.
A caller writing a production verifier has to reverse-engineer Redpill's
open-source JS verifier.

---

## Source Code

- **Verifier reference:** [Phala-Network/redpill-verifier](https://github.com/Phala-Network/redpill-verifier)
  — `js/src/verifiers/{phala,nearai,chutes,tinfoil}.ts`.
- **Probe harness:** `hermes-agent-tee-probe/hermes_cli/attestation.py`
  — `_verify_redpill_attestation`, `_verify_redpill_chutes`,
  `probe_models_for_provider`.
- **Probe notes (raw data):** `hermes-agent-tee-probe/notes/attestation-probe-results.md`.

---

## Prior Art

- [near-ai-private-inference](../near-ai-private-inference/DEVPROOF-REPORT.md)
  — covers the NEAR AI fleet that Redpill partially federates to.
- [confer](../confer/) — another TEE-routing architecture.
