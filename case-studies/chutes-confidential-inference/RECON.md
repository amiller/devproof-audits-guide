# Chutes Confidential Inference — Initial Recon

**Recon date:** 2026-05-25
**Repos (HEAD at clone):**
- `rayonlabs/chutes` (SDK) — `08d79872`
- `rayonlabs/chutes-api` (validator/control-plane) — `77b6f355`
- `rayonlabs/chutes-miner` (operator) — `7afea4b1`

**Live at probe time:** `https://api.chutes.ai`, `https://llm.chutes.ai/v1`. 13 models listed, **12 with `confidential_compute: true`** (the `-TEE` suffixed ones).

## Why this case is interesting

- First case study of a **Bittensor-subnet** inference provider (SN64). Trust is split three ways: the **validator/control-plane** (Chutes/Rayon Labs), the permissionless **miners** running the GPUs, and the **TEE hardware**.
- **Not dstack.** Zero `dstack` references in any of the three repos. Chutes rolls its own confidential-VM stack: a custom attestation-service sidecar, LUKS-encrypted rootfs released after boot attestation, k8s orchestration, Bittensor hotkey-signed requests, and its own measurement registry. This is structurally distinct from the dstack cohort (Phala/Redpill/NEAR-AI) and from Tinfoil.
- Two verification regimes coexist: **GraVal** (GPU proof-of-work / proof-of-GPU-possession, no confidentiality) for normal chutes, and the **TDX flow** (Intel TDX + NVIDIA CC mode) for `-TEE` chutes. Only the latter is in scope here.
- The "chutes shape" in our [redpill case study](../redpill-federated-inference/DEVPROOF-REPORT.md) is *this* service's attestation, copied into `redpill-verifier/chutes.ts`. Redpill federates to Chutes-TEE backends.

## Trust topology (TEE path)

```
client ──TLS+ML-KEM-768 E2E──┐
                             │  (ciphertext only; relay can't read content)
                    chutes-api control plane  ── selects instance, hands out e2e_pubkey + nonces, relays, bills
                             │
                    miner host (permissionless)
                             │  k8s; LUKS rootfs key released post-boot-attestation
                    ┌────────┴─────────┐
              Intel TDX CVM        NVIDIA H100/H200 (CC mode)
              (chute container:    8× GPU, attested via NRAS
               vLLM/SGLang +        evidence
               model weights)
```

## What's claimed (chutes.ai blog + code)

- Every GPU instance runs in an **Intel TDX** confidential VM; NVIDIA H100/H200 in **confidential-compute (CC) mode**.
- **E2E encryption** with **ML-KEM-768** (post-quantum); "not even we can see your data."
- Hardware-rooted attestation: TDX quote whose `report_data` contains `SHA256(your_nonce ‖ instance_e2e_pubkey)`, verifiable against Intel DCAP.

## Live snapshot (probe 2026-05-25)

**Confidential models (12):** Qwen3-32B, gemma-4-31B-turbo, GLM-5 / GLM-5.1, Qwen3.5-397B-A17B, Kimi-K2.5 / K2.6, DeepSeek-V3.2, MiniMax-M2.5, Qwen3.6-27B, Mistral-Nemo-Instruct-2407, Qwen2.5-Coder-32B — all `-TEE`.

**Attestation flow (third-party path), all confirmed live:**
1. `GET /e2e/instances/{chute_id}` → `{instances:[{instance_id, e2e_pubkey, nonces[]}], …}`. The `nonces[]` are fresh single-use **relay tokens** for `/e2e/invoke` — *not* the attestation binding. `e2e_pubkey` is a ~1184-byte ML-KEM-768 key.
2. `GET /instances/{instance_id}/evidence?nonce=<64 hex>` → `{quote, gpu_evidence[], certificate}`. The **client supplies the nonce**; the API proxies it to `chute-service-{deployment_id}/evidence?nonce=…`, and the instance regenerates a TDX quote bound to it.
3. Verify: debug bit off, `report_data[:32] == SHA256(nonce ‖ e2e_pubkey)`, GPU evidence, golden MRTD/RTMR match.
4. `POST /e2e/invoke` (headers `X-Chute-Id`, `X-Instance-Id`, `X-E2E-Nonce`) relays the ML-KEM-encrypted blob; control plane sees ciphertext only (+ token-count usage for billing).

**Reference values:** `GET /servers/tee/measurements` publishes per-hardware golden configs (`8xh200`, `8xRTX_PRO_6000`, …) with full MRTD + RTMR0/1/2 (boot & runtime), `expected_gpus`, `gpu_count`.

## Verified this session (`verify/verify_chutes.py`)

Against `Qwen/Qwen3-32B-TEE`, two requests with different client nonces:

| Check | Result |
|---|---|
| `report_data[:32] == SHA256(nonce‖e2e_pubkey)` | ✅ both nonces |
| Debug mode (`td_attributes` bit 0) | ✅ disabled |
| GPU evidence count | 8 |
| `report_data` differs across nonces | ✅ (genuine per-request freshness) |
| MRTD stable across requests | ✅ |
| Live MRTD `DDC6EFCD…EC38C` == published `8xh200` golden | ✅ matches |

So freshness, the e2e_pubkey↔hardware binding, and MRTD↔published-golden are real. The authoritative server-side binding is `instance/util.py:1073` — `sha256((nonce + e2e_pubkey).encode())` — matching `redpill-verifier/chutes.ts`.

## Audit framing — what to probe (the five deep-dives)

1. **Model→attestation binding (substitution).** Measurements are keyed by *hardware*, not *model*. Does anything bind the served model/weights to the quote? If not: same model-substitution gap family as NEAR-AI / Redpill. *(Resolved → F1: no. RTMR3 is non-zero in image v1.3.0 but tracks the VM image/LUKS state, identical across models; the TEE path also disables the command check + weight-digest monitor. See DEVPROOF-REPORT.md.)*
2. **Golden-value provenance / reproducibility.** Values come from an operator-maintained `/etc/config/tee_measurements.yaml`. Can a third party reproducibly rebuild the VM image to re-derive MRTD `DDC6…`, or is it TOFU on Chutes' assertion? (`audit_exporter.py` hints at on-chain commitments — worth checking.)
3. **GPU evidence depth.** Server-side `verify_gpu_evidence` + `nv-attest`. Are NRAS tokens + cert chains verified and CC-mode enforced? What does a third-party client get (raw certs vs pre-verified tokens — `chutes.ts` punts here)?
4. **cert_hash binding + E2EE termination.** `report_data` is 64 bytes; `[:32]` is the nonce-binding. Is `[32:64]` a TLS-cert pubkey hash that proves the E2EE channel terminates *inside* the attested TEE (no MITM relay)?
5. **Control-plane trust + boot/LUKS provisioning.** What the relay sees; whether trusting the discovery list (without independently verifying the quote) is exploitable; the boot→LUKS key-release flow; Bittensor hotkey auth + on-chain commitments.

## Key code paths

| Path | What |
|---|---|
| `chutes-api/api/e2e/router.py` | `/e2e/instances/{chute_id}`, `/e2e/invoke` (relay + billing) |
| `chutes-api/api/instance/router.py:2897` | `/instances/{id}/evidence?nonce=` (third-party evidence) |
| `chutes-api/api/instance/util.py:1066-1080` | binding `sha256(nonce+e2e_pubkey)`; `verify_quote` + `verify_gpu_evidence` |
| `chutes-api/api/server/quote.py` | TDX quote parse (MRTD `[136:184]`, RTMRs, `report_data [520:584]`, td_attributes) |
| `chutes-api/api/server/util.py` | `verify_quote_signature` (DCAP), `verify_measurements`, `get_matching_measurement_config` |
| `chutes-api/api/server/router.py` | `/servers/tee/measurements`, `/boot/attestation`, `/{vm}/luks*` |
| `chutes-api/api/config/__init__.py:334-345` | `tee_measurements.yaml` loader |
| `chutes-api/nv-attest/chutes_nvattest/verifier.py` | NVIDIA NRAS GPU attestation |
| `chutes/chutes/entrypoint/verify.py` | instance-side evidence **producer** (not a client verifier) |
| `chutes-miner/src/chutes-miner/audit_exporter.py` | signed export + on-chain hash commitment |
