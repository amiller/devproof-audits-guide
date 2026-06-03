# Confidential AI (Lunal / PrivateClaw) — DevProof Report

**Audit date:** 2026-05-25
**Target:** Confidential AI (https://confidential.ai), GitHub org `lunal-dev` (brand formerly "Lunal"). Product: **PrivateClaw** (privateclaw.dev), rebranding to "Confidential CVM" (`ccvm`); confidential **OpenClaw** agent + private-inference API.
**Method:** Source audit of the public repos (HEAD pinned below) + live probe of the production inference endpoint and browser demo. No account access used.
**Repos (HEAD):** `attestation-rs` `c1aebc2` · `kettle` `6a78002` · `privateclaw-cli` `403408f` (v1.5.8) · `confidential-cvm-cli` `f77595c` (v1.5.9) · `attestation-go` `ae2c7e4` · `home` `d4f6498`

---

## TL;DR

The cryptographic core is competent — AMD ARK→ASK→VCEK chain verification, Intel DCAP collateral, constant-time comparisons, RSA used only for PSS verification. **The gap is that nothing in the shipped stack enforces *which code* is running or *binds* the attestation to the session.** The verification library reports facts and explicitly punts the pass/fail decision to the caller; every first-party caller (CLI, WASM browser verifier, REST API, the `privateclaw`/`ccvm` product scripts, and the live demo) then gates on "a genuine TEE signed something" — never on a measurement allow-list, and (in the automated paths) never on a verified report-data binding.

The **C8s whitepaper** describes the correct design (a CDS that checks "launch measurement matches a reference value in the allow-list," a signed image-policy manifest, encrypted-artifact release gated on attestation). **None of that enforcement exists in any shipped, code-available artifact examined here** — the CDS is not in any public repo, and the deployed verifier (`ccvm verify`) does not allow-list measurements.

| Component | Status | Notes |
|---|---|---|
| HW signature / cert-chain crypto | ✅ | ARK→ASK→VCEK + report sig; Intel DCAP collateral. Sound. |
| Code-identity (measurement) enforcement | ❌ | No `expected_measurement` field exists in the API; measurement only ever *printed*. **F1** |
| Key / nonce binding | ❌ | `report_data_match` optional; CLI exits 0 on mismatch; product binds nothing to the quote. **F2** |
| Browser (WASM) verifier | ⚠️ | Bypasses lib `verify_evidence`: no debug-policy / TCB / measurement gate. **F3** |
| Attestation token service | ⚠️ | REST API signs a JWT of the result unconditionally. **F4** |
| Product CLI (`privateclaw`/`ccvm`) | ❌ | `signature_valid`-only gating; soft-passes on missing tooling; README claims overstate. **F5** |
| Build↔runtime measurement link (`kettle`) | ⚠️ | `kettle` records launch measurements; nothing pins them at runtime. **F6** |
| Live demo / inference attestation | ❌ | Stale (Aug-2025, expired) HMAC GPU token; GPU never verified client-side; static, non-fresh SNP report. **L1–L3** |
| Architecture (C8s) vs shipped | ❌ | Whitepaper specifies allow-list/CDS enforcement that is absent from the shipped code. |

**Verdict: Stage 0.** The advertised guarantee ("Customer prompts… never visible"; "you can be sure what ran") is not delivered by the shipped verification path. A genuine SEV-SNP/TDX enclave is proven, but not *which* code runs in it, and not that the attestation belongs to *this* session.

---

## Architecture & trust topology

```
user ──SSH / HTTPS(Caddy, private-CA cert)──┐
                                            │
                          PrivateClaw CVM  (Azure, AMD SEV-SNP)
                          ├─ OpenClaw agent
                          ├─ Caddy TLS reverse-proxy → loopback:18789
                          └─ `privateclaw`/`ccvm verify`  (user-facing 5-check verifier)
                                            │   baseUrl from Azure IMDS userData (orchestrator-set)
                          ┌─────────────────┴────────────────────┐
              "Confidential AI" gateway                  Redpill (failover)
              api.confidential.ai (via Caddy, tee-proxy)  api.redpill.ai  (Intel TDX + NVIDIA H100 CC)
              SEV-SNP; Attestation-Report header
```

- **Hardware:** AMD **SEV-SNP** on **Azure Confidential VMs** (`az-snp`, via the vTPM HCL report). First SEV-SNP-centric case in this guide. `attestation-rs` additionally supports bare TDX/SNP, GCP TDX/SNP, Azure TDX, and a dstack backend, but the deployed product is `az-snp`.
- **Federation:** the deployed inference path proxies to a "Confidential AI" SEV-SNP gateway, with **Redpill (Intel TDX + NVIDIA H100 CC) as a failover** — ties to [redpill-federated-inference](../redpill-federated-inference/DEVPROOF-REPORT.md).
- **Operator boundary:** per-CVM config (SSH key, inference `baseUrl`, model) is injected at boot from **Azure IMDS userData** (`ccvm:781-799`). Whoever writes userData (the orchestrator) is the operator-controlled slot.

## What's claimed vs. what's verified

| Claim (source) | Reality |
|---|---|
| "Customer prompts, responses, and model interactions are never visible." (home/README) | TEE confidentiality holds against the cloud, but the verifier never establishes that the *attested code* is the unmodified inference server — no measurement allow-list (**F1**). |
| "confirms the live SSH host key matches the key baked into the attestation evidence (so MITM is impossible)." (privateclaw README, Check 3) | Check 3 compares the live host-key hash to a `host_key_hash` field that `cmd_attest` wrote on the same machine; it never checks the quote's `report_data` (**F2**). The real binding is a manual README-only `--expected-report-data` step. |
| "validates the vTPM quote and AK cert chain." (privateclaw README, Check 2) | The `tpm2_nvread` path passes if the HCL blob is `>100 hex chars` — no signature/AK validation (**F5**). |
| "NVIDIA GPU attestation with hardware-verified integrity." (demo UI) | The demo never reads the `Gpu-Attestation` header; the live token is HS256 (client-unverifiable) and expired since Aug 2025 (**L2**). |
| C8s: CDS checks "launch measurement matches a reference value in the allow-list." (c8s-whitepaper) | No CDS or allow-list enforcement in any shipped repo; `attestation-rs` has no measurement parameter (**F1**). |

---

## Findings

### F1 — No code-identity (measurement) enforcement anywhere; no API to express one
**Severity: HIGH** (defeats the core confidential-inference guarantee)
**Where:** `attestation-rs/crates/attestation/src/types.rs:67` (`VerifyParams`); product `ccvm:238-240`.

`VerifyParams` exposes `expected_report_data`, `expected_init_data_hash`, `allow_debug`, `min_tcb` — **and no `expected_measurement` / MRTD / launch-digest field.** The SNP measurement / TDX MRTD is surfaced as `Claims.launch_digest` and, across the entire workspace, is **only ever printed** — the sole `launch_digest`-comparison sites are tests (prefix asserts) and CLI/example print statements. The one `expected_mrsigner` check (`tdx/dcap.rs:1087`) is the Intel Quoting-Enclave identity, not the workload.

The product makes this concrete: `ccvm` Check 1 extracts `MEASUREMENT` and `SNP_POLICY` and **prints them truncated to 32 chars + "…"** (`ccvm:238`), gating PASS purely on `signature_valid` (`ccvm:250`). A genuine SEV-SNP guest running *any* image — including a prompt-logging fork — passes.

**Fix:** add an `expected_measurements: Vec<Vec<u8>>` (or policy) field to `VerifyParams`, fail closed when the launch digest is not on the list, and ship the allow-list the C8s whitepaper already describes. Wire `ccvm` Check 1 to compare the full measurement against a pinned reference.

### F2 — Verification gates on `signature_valid`; key/nonce binding is optional and unenforced
**Severity: HIGH** (admits relay/MITM of a genuine but unrelated quote)
**Where:** `attestation-cli/src/main.rs:310-312`; lib doc `lib.rs:20-22`; product `ccvm:215,345-357,181-191`.

`attestation-cli verify` exits non-zero **only** on `!signature_valid`. A supplied `--expected-report-data` whose result is `report_data_match: Some(false)` is printed to stderr and **still exits 0**. The library's own Quick Start models the mistake: `assert!(result.signature_valid)` and nothing else.

In the product, `privateclaw verify` Check 1 calls `attestation-cli verify` **without** `--expected-report-data` (`ccvm:215`). The README says the host-key→TEE binding happens "independently in Check 3," but Check 3 compares the live SSH host-key hash to a `host_key_hash` field `cmd_attest` wrote on the same machine (`ccvm:345-357`) — it never touches the quote. A fallback even re-runs `attest` **without** `--report-data-hex` when the bound quote fails (`ccvm:181-191`). So the quote-`report_data`→key binding that would stop MITM is enforced **nowhere** in the automated path.

**Fix:** make `signature_valid && report_data_match && collateral_verified` (and measurement match) the *only* success in CLI/product; fail closed when an expected value is supplied but does not match.

### F3 — The WASM browser verifier is strictly weaker than the library
**Severity: MEDIUM**
**Where:** `attestation-rs/crates/attestation-wasm/src/lib.rs`.

`verify_snp` calls the low-level primitives (`parse_report`, `verify_cert_chain`, `verify_report_signature`) directly and bypasses the library's `verify_evidence`, so it skips the **debug-policy gate**, the **TCB/`min_tcb` gate**, and (like everything) the **measurement check**. `report_data` is optional. A debug-enabled or out-of-date-TCB SNP guest passes `verify_snp`. This is the live demo's client-side path (`/pkg/lunal_attestation_bg.wasm`, confirmed loaded).

**Fix:** route the WASM harness through `verify_evidence`/`VerifyParams` so it enforces the same gates as native.

### F4 — The verification REST API issues an attestation JWT that gates on nothing
**Severity: MEDIUM**
**Where:** `attestation-api/src/api/verify.rs:91-99`, `token/issuer.rs:78-114`.

`POST /verify` with `issue_token:true` calls `TokenIssuer::issue(&result)`, which stamps `signature_valid`, `report_data_match`, `collateral_verified` into ES256-signed JWT claims and signs **unconditionally** — it never refuses on a failed match or unverified collateral. A relying party that treats "validly-signed token from the issuer" as "attestation passed" inherits F1/F2 plus a new trusted third party (the issuer key).

**Fix:** refuse to issue (or set an explicit `verdict:false`) unless the caller-requested checks all pass; document that consumers must inspect every claim.

### F5 — Product soft-passes (auto-PASS when tooling is absent / failover is shallow)
**Severity: MEDIUM**
**Where:** `ccvm:564,616,292,455-470` (identical in `privateclaw`).

- `UPSTREAM_OK=true  # don't fail if CLI is missing` (`ccvm:564`) and `GATEWAY_OK=true # don't fail if CLI is missing` (`ccvm:616`): if `attestation-cli` is not installed, the upstream/gateway attestation is marked verified **with no check**.
- Check 2 `tpm2_nvread` path PASSES on an HCL blob being `>100 hex chars` (`ccvm:292`) — no signature/AK validation, contradicting the README.
- Redpill failover marks `UPSTREAM_OK=true` on mere presence of non-empty `signing_address`+`intel_quote` JSON fields (`ccvm:455`); no Intel TDX quote verification ("out of scope for this CLI"), and a **nonce mismatch is only printed in verbose, never fails** (`ccvm:464-470`).

**Fix:** absence of the verifier must be FAIL, not PASS; verify the HCL/TPM signature in the fallback; enforce the Redpill nonce echo.

### F6 — Build attestation (`kettle`) and runtime attestation are disconnected
**Severity: LOW (latent)**
**Where:** `kettle` (build) vs `ccvm verify` (runtime).

`kettle attest` records confidential-VM launch measurements alongside SLSA provenance and binds source→binary. But nothing in the deployed CVM consumes a kettle-attested measurement to confirm the *running* image; the user never compares the live SNP measurement against a kettle-published reference. The two halves of the "you can be sure what ran" story never meet. (Resolving F1 with a kettle-published allow-list would close this.)

---

## Live demo / inference findings (probe 2026-05-25)

Endpoint `https://llama-3b.lunal.dev` (open, no auth; `server: uvicorn`; LiteLLM/`hosted-vllm-server`, model `together_ai/meta-llama/Meta-Llama-3-8B-Instruct-Lite`). The product gateway `api.confidential.ai/v1/*` is behind Caddy with bearer auth. Full transcript: `verify/live-probe-2026-05-25.md`.

### L1 — Attestation served is static and not session-fresh
**Severity: HIGH (for the demo's stated guarantee).** Both `Attestation-Report` (Azure HCLA SNP blob, 9185 B) and `Gpu-Attestation` headers are **byte-identical across `/v1/models`, `/health`, and a 404**. They are served from a fixed header, not generated per request, and carry no per-request client nonce — so there is no freshness or channel binding; a recorded response is indistinguishable from a live one.

### L2 — GPU attestation is client-unverifiable and stale, and the client never checks it
**Severity: HIGH.** `Gpu-Attestation` is an **HS256** (symmetric/HMAC) JWT, `iss: LOCAL_GPU_VERIFIER`, `hwmodel: GH100`, fixed `eat_nonce`, **iat = 2025-08-06 22:52Z / exp = 2025-08-06 23:52Z — expired ~9 months before the probe.** HS256 means no client can verify it without the issuer's secret; it is a self-asserted result. The demo bundle never reads the `Gpu-Attestation` header at all (no reference to it, its `exp`, or its nonce anywhere in the JS), yet the UI advertises "NVIDIA GPU attestation with hardware-verified integrity." The GPU/CC half of the confidential-inference claim is displayed, not verified.

### L3 — `report_data` is used as a static code-repo label, not a binding
**Severity: MEDIUM.** The demo's "verified" gate (`verificationStatus === "verified"`; send button/input `disabled` otherwise) requires WASM `verify_snp` to pass **and** the SNP `report_data` to equal a bundled constant `b9bba338…f4915a85` that `maps_to "https://github.com/AmeanAsad/hosted-vllm-server"`. So a match proves only that a constant repo-pointer is present in the report — it does **not** bind the attestation to this TLS session or a fresh nonce. Combined with L1, the report is static and the binding is a label, so replay is not prevented. (The endpoint *is* hardcoded in the bundle — a point in its favor: not operator-env-injected.)

---

## Prompt-path analysis (operator-controllable slots)

| Slot | Verdict | Reason |
|---|---|---|
| `baseUrl` / inference endpoint (from IMDS userData → `openclaw.json`) | **on prompt path** | The orchestrator sets the upstream the agent talks to; `ccvm verify` only checks the endpoint returns *a* valid SNP cert chain, never a pinned measurement, so a redirected/forked upstream still PASSES. |
| `LUNAL_MODEL` (from userData) | on prompt path | Selects the served model; nothing binds the model identity to an attested measurement. |
| Gateway TLS (Caddy, private-CA cert installed at boot) | weak | TLS trust is via an operator-provisioned CA, not pinned to an attested key; the attestation header is the only binding and is not tied to the TLS key. |
| SSH `authorized_keys` (from userData) | off prompt path | Replaced clean-slate at assign; audited by Check 5. |

---

## Recommendations

**Immediate (close the core gap):**
1. Add a measurement allow-list to `VerifyParams` and **fail closed** on mismatch (F1). Publish the allow-list (ideally via `kettle`, closing F6).
2. Make CLI/product success require `signature_valid && report_data_match && measurement_match && collateral_verified`; remove the "exit 0 on mismatch" behavior (F2).
3. Bind the served attestation to a **fresh client nonce** and regenerate per request; stop serving a static header (L1). Verify the GPU attestation client-side against NVIDIA NRAS (not a local HMAC token) and check `exp` (L2).

**High priority:**
4. Route the WASM verifier through `verify_evidence` so it enforces debug-policy/TCB/measurement (F3).
5. Absence of `attestation-cli` must be FAIL, not PASS; verify the HCL/TPM signature in the `tpm2_nvread` fallback; enforce the Redpill nonce echo (F5).
6. Either ship the C8s CDS/allow-list machinery the whitepaper describes, or stop citing it as the product's guarantee until it ships.

**Medium:**
7. Don't issue the attestation JWT unless the requested checks pass, or carry an explicit verdict (F4).
8. Reconcile the README claims ("MITM is impossible", "validates the vTPM quote and AK cert chain") with what the code enforces.

---

## Appendix — reproduce

```bash
# Live headers (note: identical across endpoints)
curl -sS -D - -o /dev/null https://llama-3b.lunal.dev/v1/models | grep -iE 'attestation-report|gpu-attestation'
# Decode the (expired) GPU token
curl -sS -D - -o /dev/null https://llama-3b.lunal.dev/health \
  | awk -F': ' 'tolower($1)=="gpu-attestation"{print $2}' | cut -d. -f2 | tr '_-' '/+' | base64 -d | python3 -m json.tool
# Source: re-fetch repos per ../lunal-confidential-ai/.gitignore
```
