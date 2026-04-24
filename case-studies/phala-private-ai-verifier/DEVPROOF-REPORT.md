# Phala private-ai-verifier — Audit Analysis

**Audit date:** 2026-04-24
**Repo:** [Phala-Network/private-ai-verifier](https://github.com/Phala-Network/private-ai-verifier) @ `2d2f5cf` (master, 2026-03-27)
**Package:** `confidential-verifier` v0.1.0
**Core question:** If a developer drops this SDK into a client and it returns `model_verified: true`, what has actually been verified — and what has the user been led to believe?

---

## Executive Summary

| Component | Verifiable? | Notes |
|-----------|-------------|-------|
| TDX quote signature (NEAR/Redpill path) | ✅ Yes | Delegated to opaque `dstacktee/dstack-verifier` Docker sidecar |
| TDX quote signature (Tinfoil path) | ✅ Yes | Local `dcap-qvl` + Sigstore golden values |
| NVIDIA GPU attestation (NRAS) | ✅ Yes | Per-model, nonce-bound |
| Gateway `report_data` binding (NEAR AI) | ✅ Yes | Supports both `signing_address‖padding` and `SHA256(signing_address‖tls_fingerprint)` layouts |
| Live TLS fingerprint cross-check | ❌ No | Uses server-supplied fingerprint; never opens a live TLS connection to verify |
| Compose-hash from quote `mr_config` | ❌ No | NEAR AI path compares `info.compose_hash` against `sha256(app_compose)` — **both server-supplied** |
| Signing-public-key → signing-address binding | ❌ No | `signing_public_key` is never read anywhere in the repo |
| E2EE transport (encrypt a prompt) | ❌ Missing | Zero `encrypt`/`decrypt`/ECIES/HPKE/AES-GCM code. No path from "verified" to "send a private prompt." |
| Debug-mode check (`td_attributes` bit 0) | ⚠️ Partial | Implemented for Tinfoil + Chutes; absent on NEAR AI / Redpill-Phala paths |
| Tinfoil SEV-SNP + Sigstore pinning | ✅ Yes | `mr_seam` allow-list, `rtmr1/rtmr2/mrtd/rtmr0` against golden measurements |
| Venice support | ❌ Not implemented | — |

**Verdict:** This is an **attestation verifier**, not a **private-inference verifier**. It confirms TEE hardware is on the other end and that certain measurements are self-consistent. It does not establish a confidential channel, does not validate the key a client would need to do so, and has no code to encrypt a prompt.

---

## Architecture

```
                          Caller (SDK user)
                                │
                       verifier.verify_model(...)
                                │
                                ▼
             ┌──────────────────────────────────────┐
             │  TeeVerifier (confidential_verifier) │
             │  — dispatch by provider              │
             └──────────────────────────────────────┘
                  │         │         │         │
          NEAR AI │  Redpill│  Tinfoil│   Chutes│
                  │         │         │         │
                  ▼         ▼         ▼         ▼
          ┌──────────────────────┐  ┌──────────┐  ┌──────────┐
          │   dstack-verifier    │  │ dcap-qvl │  │ offline  │
          │   Docker sidecar     │  │  (local) │  │ e2e_pubkey│
          │   :8080 (opaque)     │  │          │  │ binding  │
          └──────────────────────┘  └──────────┘  └──────────┘
                  │
                  ▼
        ┌──────────────────────┐
        │   NVIDIA NRAS         │
        │   /v3/attest/gpu      │
        │   (JWT, x-nvidia-*)   │
        └──────────────────────┘

                   Where E2EE should be:
          ┌────────────────────────────────────┐
          │   [ NOT IMPLEMENTED IN THIS SDK ]  │
          │   No ECIES/HPKE/Noise code         │
          │   No signing_public_key read       │
          │   No VerificationResult.pubkey     │
          └────────────────────────────────────┘
```

**Operational shape:** the primary NEAR AI / Redpill / Phala paths depend on a `dstacktee/dstack-verifier` Docker image running on port 8080 ([`docker-compose.yml:1-6`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/docker-compose.yml), [`README.md:15-21`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/README.md)). The SDK does not verify TDX quotes locally on these paths — it forwards to the sidecar. So the TDX trust root for the most-used provider is "a Docker image Phala publishes," not the Python source in this repo.

---

## Verification Coverage by Provider

### NEAR AI (`confidential_verifier/verifiers/nearai.py`)

| Check | Implemented? | Where |
|-------|:---:|---|
| TDX quote signature | ✅ | Delegated to sidecar: [`verifiers/dstack.py:91-105`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/confidential_verifier/verifiers/dstack.py#L91-L105) |
| Live TLS fingerprint | ⚠️ Partial | Fingerprint is read from the attestation body if present (`include_tls_fingerprint=true`); no live TLS connection is opened to cross-check. A gateway can lie about its own fingerprint. Compare [`hermes_cli/attestation.py:126-138`](https://github.com/amiller/hermes-agent/blob/feat/near-ai-attestation/hermes_cli/attestation.py#L126-L138). |
| Gateway attestation | ✅ | [`verifiers/nearai.py:185-187`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/confidential_verifier/verifiers/nearai.py#L185-L187) |
| Model attestation(s) | ✅ | All must pass ([`verifiers/nearai.py:190-194, 231`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/confidential_verifier/verifiers/nearai.py#L190-L231)) |
| GPU NRAS per model | ✅ | [`verifiers/nvidia.py:15-43`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/confidential_verifier/verifiers/nvidia.py#L15-L43), nonce-bound at `verifiers/nearai.py:132-136` |
| GPU verdict semantics | ⚠️ | Checks `x-nvidia-overall-att-result is True` only; does not surface the `"FAIL"` string shape NRAS returns in practice |
| RTMR / MRTD pinning | ❌ | Not done on the NEAR AI path |
| Compose hash from quote | ❌ | Only `info.compose_hash == sha256(app_compose)` ([`verifiers/nearai.py:20-26, 76-87`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/confidential_verifier/verifiers/nearai.py#L20-L87)) — **self-consistency check between two server-supplied values, not a binding to the hardware-signed `mr_config`** |
| Signing-public-key → address | ❌ | `grep -rn signing_public_key` returns zero hits in the repo |
| Intel Trust Authority (optional) | ✅ | [`verifiers/intel.py:113-141`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/confidential_verifier/verifiers/intel.py#L113-L141); unauthenticated JWT decode (`verify_signature: False`) — trust is TLS + API-key only |

### Tinfoil (`verifiers/tinfoil.py`)

Substantially stronger than the NEAR AI path:
- `mr_seam` pinned to a 4-element allow-list ([`tinfoil.py:18-27`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/confidential_verifier/verifiers/tinfoil.py#L18-L27))
- `rtmr1/rtmr2/mrtd/rtmr0` matched against Sigstore-published golden values ([`tinfoil.py:388-432`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/confidential_verifier/verifiers/tinfoil.py#L388-L432))
- Debug-mode flag checked
- SEV-SNP path included

### Redpill (`verifiers/redpill.py`)

Dispatches by provider metadata to `phala`, `tinfoil`, or the NEAR AI verifier ([`redpill.py:113-194`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/confidential_verifier/verifiers/redpill.py#L113-L194)). Inherits whatever coverage the target verifier provides — so Redpill-over-NEAR-AI inherits the above gaps.

### Chutes (`verifiers/chutes.py`)

Offline verifier, semantically different: checks `SHA256(nonce‖e2e_pubkey) == report_data[0:32]` ([`chutes.py:127-146`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/confidential_verifier/verifiers/chutes.py#L127-L146)). Verifies the attestation pre-fetched NRAS JWT rather than calling NRAS live. Pub-key binding is present (the `e2e_pubkey` is hash-bound to the quote) — but, critically, [`docs/chutes_verification.md:189-197`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/docs/chutes_verification.md) punts the actual encryption step back to the caller: *"you can trust that the E2E public key belongs to the TEE and use it for encrypted communication."*

---

## E2EE Coverage

Zero. Definitively absent. Grep results over `**/*.py` and `**/*.md`:

- `encrypt`, `decrypt`, `ECIES`, `HPKE`, `AES-GCM`, `AESGCM`, `Cipher`, `ephemeral` — 0 hits
- `X-Signing-Algo`, `X-Client-Pub-Key`, `X-Model-Pub-Key` — 0 hits
- `signing_public_key` — 0 hits

`signing_address` flows into `report_data` checks but the actual EC public key that a client would encrypt to is never read, returned, or validated. `VerificationResult` in [`types.py:20-30`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/confidential_verifier/types.py#L20-L30) has no `signing_public_key` field — the data that would let a caller close the loop is not even exposed.

Compare `hermes_cli/attestation.py`:
- Returns `AttestationReport.signing_public_key` to the caller (line 80)
- Derives the address from the key and cross-checks: `eth_keys.PublicKey(...).to_canonical_address()` (lines 331-340 for NEAR AI, 660-668 for Venice)
- Ships a separate `hermes_cli/e2ee_transport.py` that actually uses the verified key to encrypt prompts

The Phala verifier stops one step before useful.

---

## User-Facing Story

The README example ([`README.md:86-113`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/README.md#L86-L113)):

```python
verifier = TeeVerifier()
result = await verifier.verify_model("redpill", "meta-llama/llama-3.3-70b-instruct")
print(f"Model Verified: {result.model_verified}")
print(f"Hardware: {result.hardware_type}")
```

The return type is `VerificationResult(model_verified, hardware_type, claims, error, ...)` — pass/fail plus a claims dict. There is no follow-on API. No `encrypt_prompt`, no `wrap_request`, no "now send this prompt through the verified channel." The FastAPI server ([`server/main.py`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/server/main.py)) exposes `/verify-model` and returns the same struct as JSON.

**End of the documented flow: user knows the TEE is real. How they send a prompt to it — and whether the prompt is actually readable only by the model — is out of scope.** `README.md` and `docs/nearai_verification.md` do not discuss encryption. `docs/chutes_verification.md` mentions it only as something the caller must implement.

This is the backdoor-by-incompleteness pattern. A developer who reads the example, sees `model_verified: true`, and sends a prompt over plain HTTPS to `cloud-api.near.ai` has the same prompt-confidentiality posture as any non-TEE HTTPS endpoint: TLS terminates at the gateway, and the gateway does whatever it does. The NEAR AI ECIES machinery (`signing_public_key` + envelope) is never touched by this SDK.

---

## Compose Hash: Why the NEAR AI Check Is Doubly Weak

The NEAR AI path checks `info.compose_hash == sha256(app_compose)` (both server-supplied) rather than against the quote's hardware-signed `mr_config`. Even if it used `mr_config`, the documented NEAR AI gap is that the *inner* compose (inference-proxy + vLLM) is never extended into RTMR3 — see the [near-ai-private-inference](../near-ai-private-inference/DEVPROOF-REPORT.md) case study.

So on the NEAR AI path, the verifier confirms that the *reported* compose hash hashes to what the server says it hashes to. The hardware-signed measurement of the boot compose exists in the quote but is not consulted. Hermes's reference impl does consult it: `mrconfig.startswith("01"+compose_hash)` ([`hermes_cli/attestation.py:321-325`](https://github.com/amiller/hermes-agent/blob/feat/near-ai-attestation/hermes_cli/attestation.py#L321-L325)).

---

## Comparison with `hermes_cli/attestation.py`

| Check | `private-ai-verifier` | `hermes_cli/attestation.py` |
|-------|:---:|:---:|
| TDX quote signature | sidecar (Docker) | public Phala endpoint **or** local `dcap_qvl` |
| Live TLS fingerprint cross-check | ❌ | ✅ `_live_tls_fingerprint()` at `:126-138`, used as cache-invalidator at `:160-164` |
| Gateway + model `report_data` binding | ✅ | ✅ |
| GPU NRAS | ✅ | ✅ (three variants: NEAR inline / Phala NRAS for Redpill+Venice / Chutes `e2e_pubkey` binding) |
| Compose hash from quote's `mr_config` | ❌ | ✅ `mrconfig.startswith("01"+compose_hash)` at `:321-325` |
| Debug-mode flag (NEAR AI / Redpill-Phala) | ❌ | ❌ for NEAR AI; ✅ for Redpill-Chutes at `:438-444` |
| `signing_public_key → signing_address` derivation | ❌ | ✅ NEAR (`:331-340`), Venice (`:660-668`) |
| Return encryption key to caller | ❌ | ✅ `AttestationReport.signing_public_key` / `.signing_algo` |
| Actually use the key to encrypt a prompt | ❌ | ✅ separate module `e2ee_transport.py` + `e2ee_proxy.py` |
| Providers | NEAR AI, Redpill, Tinfoil, Chutes | NEAR AI, Redpill (4 shapes), Venice |
| Venice | ❌ | ✅ (`attestation.py:601-709`) |
| Intel Trust Authority | ✅ opt-in | ❌ |
| Tinfoil Sigstore + SEV-SNP | ✅ | ❌ |

**What `private-ai-verifier` does that hermes does not:** Intel Trust Authority appraisal; Tinfoil Sigstore manifest pinning; SEV-SNP parsing; offline Chutes verification with pre-fetched NRAS tokens.

**What hermes does that `private-ai-verifier` does not:** Live TLS fingerprint probe; signing-public-key recovery and binding; return the verified key to the caller; actually encrypt prompts with it; RTMR3 compose-hash re-derivation from the quote for NEAR AI.

---

## Versioning / Activity

- No git tags, no GitHub releases
- Package version `0.1.0`
- 31 commits total; last commit `2d2f5cf` on 2026-03-27
- One merged PR (#1, Chutes + multi-platform Tinfoil, merged 2026-03-27)
- **Zero issues, open or closed.** No discussion of E2EE or `signing_public_key` binding.

---

## Stage Assessment

**As a user-facing verifier product:** Stage 0.
- Attestation is verifiable but the client cannot act on it — there is no E2EE path.
- Reproducibility of measurement is partial: Tinfoil uses Sigstore golden values (good); NEAR AI compares server-supplied values (not reproducible in the ERC-733 sense).
- Trust root for TDX verification on primary paths is an opaque `dstacktee/dstack-verifier` Docker image, not the SDK source.

**As a tool for moving downstream systems toward Stage 1:** covers the "enclaves are attested off-chain" checkbox for NEAR/Redpill/Tinfoil/Chutes and will flag catastrophic regressions (quote invalid, GPU NRAS failing). Does not establish:
- *"Developer has no access to application secrets"* — the SDK doesn't know what the application's encryption key is, so it cannot verify end-to-end privacy.
- *"No backdoor or debug paths"* — only checked on Tinfoil + Chutes. A NEAR AI CVM running in TDX debug mode would pass this verifier.

---

## Recommendations

**Read and expose `signing_public_key`.** Add it to `VerificationResult`. Derive the Ethereum address from it and check against the `report_data`-bound `signing_address`. This is ~5 lines with `eth_keys` and closes the TOFU gap at the SDK boundary.

**Ship an E2EE transport, or explicitly redirect callers to one.** Either add an `encrypt_prompt(result, payload)` helper that uses the ECIES envelope NEAR AI publishes, or put a large-font warning in the README that this SDK does not provide prompt confidentiality and link to a client that does. Leaving it implicit is the current gap.

**Switch the NEAR AI compose check to use `mr_config` from the quote.** `sha256(app_compose) == info.compose_hash` is self-consistency. `mr_config` is what's hardware-signed.

**Open a live TLS connection and cross-check the fingerprint.** Trusting the fingerprint the server reports to you is not a binding — it's a transitive restatement.

**Check `td_attributes` bit 0 (debug) on the NEAR AI and Redpill-Phala paths.** You already do this for Tinfoil and Chutes.

**Ship releases.** v0.1.0 with no tags, no changelog, no issues, and verification trust on an unreleased Docker image is a weak provenance story for a trust-model library.

---

## Source Code

| Component | File |
|-----------|------|
| SDK facade | [`confidential_verifier/sdk.py`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/confidential_verifier/sdk.py) |
| NEAR AI verifier | [`confidential_verifier/verifiers/nearai.py`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/confidential_verifier/verifiers/nearai.py) |
| dstack-verifier sidecar client | [`confidential_verifier/verifiers/dstack.py`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/confidential_verifier/verifiers/dstack.py) |
| Intel TDX (local dcap-qvl + ITA) | [`confidential_verifier/verifiers/intel.py`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/confidential_verifier/verifiers/intel.py) |
| NVIDIA NRAS | [`confidential_verifier/verifiers/nvidia.py`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/confidential_verifier/verifiers/nvidia.py) |
| Tinfoil (golden values) | [`confidential_verifier/verifiers/tinfoil.py`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/confidential_verifier/verifiers/tinfoil.py) |
| Chutes (offline, e2e_pubkey) | [`confidential_verifier/verifiers/chutes.py`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/confidential_verifier/verifiers/chutes.py) |
| Redpill dispatcher | [`confidential_verifier/verifiers/redpill.py`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/confidential_verifier/verifiers/redpill.py) |
| Phala Cloud app verifier | [`confidential_verifier/verifiers/phala.py`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/confidential_verifier/verifiers/phala.py) |
| HTTP server | [`server/main.py`](https://github.com/Phala-Network/private-ai-verifier/blob/2d2f5cf/server/main.py) |
| Reference for comparison | `hermes-agent` `feat/near-ai-attestation` branch: `hermes_cli/attestation.py`, `hermes_cli/e2ee_transport.py` |

## See Also

- [near-ai-private-inference](../near-ai-private-inference/DEVPROOF-REPORT.md) — what this SDK is verifying against
- [venice-private-inference](../venice-private-inference/DEVPROOF-REPORT.md) — Venice, which resells NEAR and would benefit from (but isn't covered by) this verifier
