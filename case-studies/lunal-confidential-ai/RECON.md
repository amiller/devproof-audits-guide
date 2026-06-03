# Confidential AI (Lunal / PrivateClaw) — Initial Recon

**Recon date:** 2026-05-25
**Site:** https://confidential.ai · **Org:** https://github.com/lunal-dev (brand "Lunal" → "Confidential AI") · **Product:** PrivateClaw (privateclaw.dev), rebranding to "Confidential CVM"
**Repos (HEAD at clone):**
- `lunal-dev/attestation-rs` (verification library + CLI + REST API + WASM) — `c1aebc2`
- `lunal-dev/kettle` (attested builds / SLSA provenance) — `6a78002`
- `lunal-dev/privateclaw-cli` (product CLI, single bash script) — `403408f`, `VERSION=v1.5.8`
- `lunal-dev/confidential-cvm-cli` (same script, rebranded) — `f77595c`, `VERSION=v1.5.9`
- `lunal-dev/attestation-go` (Go port of the verifier) — `ae2c7e4`
- `lunal-dev/home` (marketing) — `d4f6498`

## Why this case is interesting

- **A verification *toolkit*, not a verification *policy*.** Unlike the dstack cohort (which ships a verifier that enforces a measurement allow-list) or Chutes (golden MRTD/RTMR registry), Confidential AI ships `attestation-rs` — a clean, multi-platform library that *reports facts* (`signature_valid`, `report_data_match`, `collateral_verified`) and **explicitly punts the pass/fail decision to the caller** (`types.rs:79` "the caller decides pass/fail based on this"). The interesting question is whether the first-party consumers (CLI, WASM, REST API, the `privateclaw`/`ccvm` product scripts) actually make that decision. **They mostly don't** — they gate on `signature_valid` alone.
- **AMD SEV-SNP-first, on Azure Confidential VMs** (`az-snp` via vTPM/HCL report). This is the first SEV-SNP-centric case study (the dstack/Chutes/Redpill cohort is Intel TDX + NVIDIA CC). `attestation-rs` also covers bare TDX/SNP, GCP TDX/SNP, Azure TDX, and has a `dstack` backend, but the deployed product is Azure `az-snp`.
- **A confidential *agent* product, not just inference.** PrivateClaw runs the **OpenClaw** agent inside an SEV-SNP CVM; inference is proxied to an upstream "Confidential AI" SEV-SNP gateway (`tee-proxy`), with **Redpill (Intel TDX + NVIDIA H100 CC) as a failover** upstream. So this provider *federates to Redpill* — ties into [redpill-federated-inference](../redpill-federated-inference/DEVPROOF-REPORT.md).
- **Build attestation (`kettle`) and runtime attestation (`privateclaw verify`) are disconnected.** `kettle` records confidential-VM launch measurements alongside SLSA provenance, but nothing in the deployed CVM consumes a kettle-attested measurement to confirm the running image. The user never compares the live SNP measurement against a known-good build.

## Trust topology (PrivateClaw)

```
user ──SSH / HTTPS(Caddy, private-CA cert)──┐
                                            │
                          PrivateClaw CVM  (Azure, AMD SEV-SNP)
                          ├─ OpenClaw agent (the thing the user trusts)
                          ├─ Caddy TLS reverse-proxy → loopback:18789
                          └─ `privateclaw verify` (5-check user-facing verifier)
                                            │  baseUrl from Azure IMDS userData (operator/orchestrator-set)
                          ┌─────────────────┴───────────────────┐
              "Confidential AI" gateway                 Redpill (failover)
              tee-proxy, AMD SEV-SNP                     Intel TDX + NVIDIA H100 CC
              Attestation-Report header                 GET api.redpill.ai/v1/attestation/report
```

Config is applied at boot from **Azure IMDS userData** (`cmd_assign`, `ccvm:781-799`): SSH key, inference `baseUrl`, model. The orchestrator that writes userData is the operator trust boundary.

## What's claimed

- **home/README.md:** "Customer prompts, responses, and model interactions are never visible." "Agents run inside TEEs with hardware-enforced credential isolation."
- **privateclaw-cli/README.md, Check 3:** "confirms the live SSH host key matches the key baked into the attestation evidence (**so MITM is impossible**)."
- **privateclaw-cli/README.md, Check 2:** "validates the vTPM quote and AK cert chain."
- **kettle/README.md:** "verify the exact inputs that produced any binary output"; "you can be sure what ran."

## Findings (code-traced this session)

### F1 — No code-identity (measurement) enforcement, anywhere; no API to express one
- `VerifyParams` (`attestation-rs/crates/attestation/src/types.rs:67`) has fields for `expected_report_data`, `expected_init_data_hash`, `allow_debug`, `min_tcb` — **but no `expected_measurement` / MRTD / launch-digest field.**
- `launch_digest` (SNP measurement / TDX MRTD) is surfaced in `Claims` and is **only ever printed**, never compared, in all first-party code. Grep across the workspace: the sole `launch_digest ==`-style comparisons are in **tests** (prefix asserts) and **CLI/example print statements**. The one `expected_mrsigner` check (`tdx/dcap.rs:1087`) is the Intel Quoting-Enclave identity, not the workload measurement.
- Product impact: `privateclaw`/`ccvm` Check 1 extracts `MEASUREMENT` and `SNP_POLICY` and **prints them truncated to 32 chars + "…"** (`ccvm:238-240`), gating PASS purely on `signature_valid` (`ccvm:250`). A genuine SEV-SNP guest running *any* code (including a logging fork) passes. This is the load-bearing check for "is this the model/agent I audited," and it is structurally absent.

### F2 — Verification gates on `signature_valid`; key/nonce binding is optional and unenforced
- `attestation-cli verify` exits non-zero **only** on `!signature_valid` (`attestation-cli/src/main.rs:310-312`). A supplied `--expected-report-data` that returns `report_data_match: Some(false)` is printed to stderr and **still exits 0**.
- The `lib.rs` Quick Start models exactly this mistake: `assert!(result.signature_valid)` and nothing else (`lib.rs:20-22`).
- Product impact: `privateclaw verify` Check 1 calls `attestation-cli verify` **without** `--expected-report-data` (`ccvm:215`). The README claims the host-key→TEE binding is done "independently in Check 3," but **Check 3 never touches the quote** — it compares the live SSH host-key hash to a `host_key_hash` field that `cmd_attest` wrote into `evidence.json` on the same machine (`ccvm:345-357`). The actual quote-`report_data`→key binding (the thing that stops MITM) is enforced **nowhere in the automated path**; it appears only as a manual `--expected-report-data` step in the README's "Independent verification" section. The "so MITM is impossible" claim overstates Check 3.
- An explicit fallback re-runs `attest` **without** `--report-data-hex` when the bound quote fails (`ccvm:181-191`), silently dropping even the (unverified) binding.

### F3 — The WASM browser verifier is strictly weaker than the library
- `attestation-wasm::verify_snp` (`attestation-wasm/src/lib.rs`) calls the low-level primitives directly (`parse_report`, `verify_cert_chain`, `verify_report_signature`) and bypasses the library's `verify_evidence`. It therefore skips the **debug-policy gate**, the **TCB/`min_tcb` gate**, and (like everything) the **measurement check**. `report_data` is optional here too. A debug-enabled or out-of-date-TCB SNP guest passes `verify_snp`. This is the likely client-side path for `private-inference-demo.confidential.ai` (unconfirmed live — see TODO).

### F4 — The verification REST API issues an attestation JWT that gates on nothing
- `POST /verify` with `issue_token:true` calls `TokenIssuer::issue(&result)` (`attestation-api/src/api/verify.rs:91-99`). `issue()` stamps `signature_valid`, `report_data_match`, `collateral_verified` into ES256-signed JWT claims and signs **unconditionally** (`token/issuer.rs:78-114`) — it never refuses to issue on a failed match or unverified collateral. A relying party that treats "validly-signed token from the issuer" as "attestation passed" inherits F1/F2 plus a new trusted third party (the issuer key).

### F5 — Product soft-pass branches (auto-PASS when the verifier is absent / failover is shallow)
- `UPSTREAM_OK=true  # don't fail if CLI is missing` (`ccvm:564`) and `GATEWAY_OK=true # don't fail if CLI is missing` (`ccvm:616`): if `attestation-cli` is not installed, the upstream/gateway attestation is marked verified **without any check**.
- Check 2 `tpm2_nvread` path: PASSES if the HCL blob is merely `>100 hex chars` (`ccvm:292`) — **no signature/AK-cert validation**, contradicting the README's "validates the vTPM quote and AK cert chain."
- Redpill failover path: `UPSTREAM_OK=true` on mere **presence of non-empty `signing_address` + `intel_quote` JSON fields** (`ccvm:455`); no Intel TDX quote verification ("out of scope for this CLI"), and a **nonce mismatch is only printed in verbose, never fails** (`ccvm:464-470`).

### Build/runtime gap (F6, to firm up)
- `kettle attest` produces `evidence.json` binding source→binary→CVM launch measurement. But the deployed CVM's `privateclaw verify` does not load any kettle measurement / golden value to confirm the running image corresponds to a kettle-attested build. Build-time and runtime attestation are not joined.

## Crypto core (looks sound — not the gap)
The underlying primitives appear competently implemented: AMD ARK→ASK→VCEK chain + report-signature verification, Intel DCAP collateral (TCB/QE-identity/CRL) in `tdx/dcap.rs`, `constant_time_eq` for comparisons, RSA used only for PSS verification (documented RUSTSEC acceptance). The gap is **policy/binding/enforcement at the consumer layer**, not broken cryptography — same shape as Chutes F1/F2 (`model-not-measured` + golden-value-not-enforced).

## Not yet done (see TODO)
- Live probe of `private-inference-demo.confidential.ai` and `simulator.confidential.ai` (confirm WASM path, model served, whether report_data is bound).
- Read the C8s ("Confidential Kubernetes") whitepaper + Confidential Agents API docs at confidential.ai/docs.
- `attestation-go` parity check (does the Go verifier repeat the same optional-binding posture?).
- `kettle` deep-dive: does the published `attestation-api` image's build actually run through kettle, and is the resulting measurement anywhere a user can pin?
