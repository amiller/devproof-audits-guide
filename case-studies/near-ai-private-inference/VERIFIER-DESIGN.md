# NEAR AI Private Inference — Verifier Design Document

**Status:** working draft (2026-05-02). Companion to
`DEVPROOF-REPORT-revisit-2026-05-02.md`. Goal is to specify what a
"closed-chain" verifying client needs to check, against what reference
values, anchored to which trust roots — and to compare against what's
implemented today in `nearai/nearai-cloud-verifier` and
`Phala-Network/private-ai-verifier`.

---

## 1. Threat model and goals

Adversary: the cloud host operator (and anyone with the operator's
deploy-time secrets — `BEARER_TOKEN` for compose-manager, admin tokens for
cloud-api, push to `nearai/cvm-compose-files`).

Security goals, in priority order:

1. **No exfiltration of user queries.** A query encrypted to the model's
   public key cannot be read by the operator.
2. **No exfiltration of inference output.** Same, for the response stream.
3. *(Optional)* **No injection of wrong model weights.** A request for
   model X is served by an actual instance of X.

The verifying client's job is to mechanically check that the X25519 public
key it's about to encrypt to belongs to a TDX TD whose code provably cannot
break (1) or (2), and whose declared model name corresponds to (3).

---

## 2. Data flow architecture

Three call paths exist; each has a different "what's load-bearing" profile.

```
                          ┌─────── Path A — gateway, plain TLS ───────┐
                          │                                            │
client ──https──▶ dstack-ingress CVM ──VPC──▶ chat-api ──▶ cloud-api ──▶ inference-proxy
              (TLS terminates)                         │
                                                        ▼
                                                  per-model backend


                          ┌── Path B — direct per-model subdomain ──┐
                          │                                          │
client ──https──▶ glm-5-1.completions.near.ai ──SNI passthrough──▶ inference-proxy
                                                                   (nginx in same TD as GPU
                                                                    terminates TLS)


                          ┌── Path C — E2EE headers (over A or B) ──┐
                          │                                          │
client (encrypts to X25519(signing_pubkey)) ──https──▶ any TLS hop sees ciphertext
                                              ──▶ inference-proxy decrypts inside its TD
```

Inside a single model CVM (one TDX TD):

```
TDX TD = "model CVM"
    OS image:        dstack-nvidia-0.5.5  (os_image_hash da9a3d5c…)
    OUTER compose:   measured into RTMR3, hashed → compose_hash → on-chain
        - nearaidev/compose-manager@sha256:a3c6e223…
        - datadog/agent@sha256:5556fb80…   (DD_API_KEY in allowed_envs)
        - certbot/dns-cloudflare         (Let's Encrypt for *.completions.near.ai)
    INNER compose:   deployed by compose-manager from nearai/cvm-compose-files
        - nearaidev/vllm-proxy-rs@sha256:6f3cb72d…   ← holds the E2EE key
        - lmsysorg/sglang:dev@sha256:e1eee3f7…       ← inference engine
        - nginx                                        ← TLS terminator for path B
        - model-downloader                             ← pulls weights from HF
        - dcgm-exporter                                ← GPU metrics
    KMS:             dstack-managed (Phala) → app key derived per app_id
                     KMS root pubkey on-chain in DstackKms.kmsInfo.k256Pubkey
```

The OUTER compose is anchored on-chain (`DstackApp.allowedComposeHashes`).
The INNER compose is anchored only by compose-manager's TDX-attested
`actions[]` log + the public Git history of `nearai/cvm-compose-files`.

---

## 3. Components and what they attest

| Component | Attestation it produces | What it binds |
|---|---|---|
| Intel TDX (per CVM) | Intel-signed TDX quote | MRTD, RTMR0..3, `report_data` (64 bytes) |
| dstack runtime | `info` block in attestation response | extracts `app_id`, `compose_hash`, `os_image_hash`, `key_provider_info` from RTMR3 event log |
| dstack KMS | KMS-root signature over the booting CVM's app pubkey (`signature_chain[1]` from `get_key`) | (KMS root, app_id) → app k256 pubkey |
| dstack-guest-agent (in CVM) | app-key signature over `"signing:" \|\| derived_pubkey` (`signature_chain[0]`) | (app pubkey, path string, derived pubkey) |
| inference-proxy `vllm-proxy-rs` | TDX `report_data[0:32] = SHA256(signing_address \|\| tls_cert_fp)`, `report_data[32:64] = nonce` | (signing_pubkey, optional tls cert, nonce) ↔ this TDX TD |
| compose-manager | second TDX quote with `report_data[0:32] = SHA256(actions_json)` | actions log ↔ this TDX TD |
| inference-proxy OHTTP gateway | Ed25519 signature over the OHTTP HPKE key config (`ohttp_attestation`) | OHTTP HPKE pubkey ↔ Ed25519 signing key (which is itself bound by report_data) |
| NVIDIA NRAS | NRAS-signed JWT over GPU evidence | GPU identity, VBIOS, nonce |

These are independent attestations linked by:
- **shared nonce** between TDX quote, GPU evidence, and compose-manager's quote (request-time freshness),
- **`report_data` binding** between the TDX TD and its keys/cert,
- **shared MRTD/RTMR3** between the inference-proxy TDX quote and the
  compose-manager TDX quote (they run in the same TD).

---

## 4. Reference values, where they live, what anchors them

For "the X25519 public key this client encrypts to belongs to genuine NEAR
inference for model M":

| Reference value | Lives in attestation as | Anchor (today) | Anchor (closed) |
|---|---|---|---|
| Intel TDX root cert chain | implicit in `intel_quote` signature | well-known Intel CA | well-known Intel CA |
| `os_image_hash` | RTMR3 event log | `DstackKms.allowedOsImages(hash)` on Base | same |
| `compose_hash` (outer) | RTMR3 event log | `DstackApp(app_id).allowedComposeHashes(hash)` on Base | same |
| `app_id` | RTMR3 event log | `DstackKms.registeredApps(app_id)` on Base | same |
| KMS root pubkey | `info.key_provider_info.id` (P-256 SPKI) | `DstackKms.kmsInfo.k256Pubkey` on Base | same |
| `model_name → app_id` map | implicit; client must trust the request/response pair | **nothing** | NEAR-published manifest (signed release / on-chain pointer) |
| `model_name → kms_contract_addr` | not in attestation | **nothing** | same manifest |
| Inner compose `(commit, file_sha256)` | `compose_manager_attestation.actions[i]` | only by `nearai/cvm-compose-files` Git history (mutable; 2h `min_tag_age`) | NEAR-pinned `(model → expected commit window)` allowlist |
| Inner image digests (`vllm-proxy-rs@sha256:…`, `sglang:…`) | content of the YAML at `commit` | only by reading the YAML from public GitHub | NEAR-pinned `expected_inner_images.json` per release |
| TLS cert SPKI fingerprint (path B) | `tls_cert_fingerprint` field; bound via `report_data[0:32]` | `report_data` itself | same |
| `signing_public_key` (the E2EE keystone) | top-level field; bound via `report_data[0:32]` | `report_data` itself | same |
| GPU identity | `nvidia_payload` JWT signed by NRAS | NVIDIA's PKI | same |

Trust roots, with this design: **{Intel TDX cert chain, Base mainnet (chain
8453), NEAR-published manifest, NVIDIA NRAS PKI}**. The "NEAR-published
manifest" is the missing piece. Phala has an analogue at
`https://cloud-api.phala.network/api/v1/apps/{app_id}/attestations`
(centralized API). NEAR does not have an equivalent; no
`cloud-api.near.ai/v1/apps/...` route exists (`404`).

---

## 5. Verifier algorithm (closed chain)

```
INPUT  (pinned at verifier release time):
  - intel_root_certs                     [well-known]
  - base_rpc_url           OR base_light_client_config
  - canonical_kms_addr     [from NEAR manifest]
  - per_model_anchor       [from NEAR manifest:
                              { "zai-org/GLM-5.1-FP8":
                                  {"app_id": "0x2c0a…", "kms_addr": "0x…"},
                                ... }]
  - expected_inner_images  [from NEAR manifest:
                              { "GLM-5.1.yaml":
                                  {"vllm-proxy-rs": "sha256:6f3cb72d…",
                                   "sglang":         "sha256:e1eee3f7…"},
                                ... }]
  - allowed_yaml_repo:     "https://github.com/nearai/cvm-compose-files"

PER REQUEST:
  N    ← random 32-byte nonce
  resp ← GET /v1/attestation/report?model=M&nonce=N
                                  &include_tls_fingerprint=true
                                  &signing_algo=ed25519

  # ───── A. Intel-anchored cryptography (already in NEAR's verifier) ─────
  A1.  Verify intel_quote signature against intel_root_certs.
       (Use dcap-qvl or Intel Trust Authority.)
  A2.  Replay event_log; recompute RTMR3; assert == quote.rt_mr3.
       Extract: compose_hash, app_id, os_image_hash, key_provider_info.
  A3.  Assert resp.report_data[0:32]
                  == SHA256(resp.signing_address || resp.tls_cert_fingerprint).
       Assert resp.report_data[32:64] == N.
  A4.  Verify nvidia_payload via NRAS; assert nonce == N; verdict == PASS.

  # ───── B. Base-anchored reference values (NOT YET in NEAR's verifier) ──
  B1.  light_client.read(canonical_kms_addr).kmsInfo().k256Pubkey
                  must equal info.key_provider_info.id
       (this confirms the booting KMS is the canonical one).
  B2.  light_client.read(canonical_kms_addr).allowedOsImages(os_image_hash)
                  must be true.
  B3.  light_client.read(canonical_kms_addr).registeredApps(app_id)
                  must be true.
  B4.  app_id must equal per_model_anchor[M].app_id  (catches model→app substitution).
  B5.  light_client.read(app_id).allowedComposeHashes(compose_hash) must be true.

  # ───── C. Inner-compose chain (NOT YET in any verifier) ────────────────
  C1.  parse resp.compose_manager_attestation:
         verify its inner intel_quote (same MRTD as resp.intel_quote);
         verify report_data[0:32] == SHA256(actions_json);
         verify report_data[32:64] == N (compose-manager echoes the request nonce).
  C2.  let last_up = actions where action="compose_up", model M's file last;
       fetch from allowed_yaml_repo at commit=last_up.commit, path=last_up.file;
       assert sha256(yaml) == last_up.file_sha256.
  C3.  parse the YAML; assert image digests match
         expected_inner_images[last_up.file].
       Assert MODEL_NAME env equals M.
       Assert no DEV / GPU_NO_HW_MODE / debug envs.

  # ───── D. E2EE handshake ──────────────────────────────────────────────
  D1.  x25519_recipient = ed25519_to_x25519(resp.signing_public_key)
  D2.  encrypt body to x25519_recipient with X25519+HKDF+XChaCha20-Poly1305.
  D3.  POST /v1/chat/completions
         X-Signing-Algo: ed25519
         X-Client-Pub-Key: <ephemeral X25519 pub>
         X-Model-Pub-Key:  <hex(resp.signing_public_key)>
```

Block A — what the published `nearai-cloud-verifier` does today.
Block B — what's missing; this is the critical "anchor to Base" leg.
Block C — what's missing; this is the inner-compose closure.
Block D — already implemented as `encrypted_chat_verifier.py`.

Without B, the verifier's "verified: True" output means "the cryptography
is internally consistent" — not "the keypair is one I should trust." Without
C, the inner deployment (vllm-proxy-rs, sglang, MODEL_NAME) is unattested
even with B. With both B and C the only remaining trust assumption is the
`per_model_anchor` and `expected_inner_images` files in the verifier
release, which is reducible to "you trust this tagged version of the
verifier at this commit."

---

## 6. Comparison: today's verifiers

### `nearai/nearai-cloud-verifier @ ec30401`

| Step | Implemented? | Where |
|---|---|---|
| A1 | yes | `py/model_verifier.py::check_tdx_quote` (uses `dcap-qvl`) |
| A2 | yes | event log replay inside `check_tdx_quote` |
| A3 | yes | `check_report_data` |
| A4 | yes | `check_gpu` (via NRAS) |
| B1–B5 | **no** | `show_compose` prints `compose_hash` and stops |
| C1–C3 | **no** | `compose_manager_attestation` is unread |
| D1–D3 | yes | `py/encrypted_chat_verifier.py` |

PRs already open (mine, 2026-04-21):
- [#22](https://github.com/nearai/nearai-cloud-verifier/pull/22) — pytest scaffolding for offline helpers
- [#23](https://github.com/nearai/nearai-cloud-verifier/pull/23) — `verify_attestation` returns a `VerificationResult` with `.valid`; enforce `model_attestations` non-empty and `model_name == requested_model`

PR #23 closes a separate "silent failure" hole (the verifier returned
`None` no matter what), but does not add B or C.

### `Phala-Network/private-ai-verifier @ 2d2f5cf`

| Step | Implemented? | Where |
|---|---|---|
| A1 | yes (delegated) | `confidential_verifier/verifiers/intel.py`; for full reproduction, calls a local `dstack-verifier` Docker service that re-runs QEMU |
| A2 | yes | inside the `dstack-verifier` service |
| A3 | yes | `verifiers/dstack.py::verify_report_data` |
| A4 | yes | `verifiers/nvidia.py` |
| **B1–B5 (Phala apps)** | **partial** | `PhalaCloudVerifier.get_system_info` calls `https://cloud-api.phala.network/api/v1/apps/{app_id}/attestations` for reference values — a **centralized Phala registry**, not on-chain |
| **B1–B5 (NEAR apps)** | **no** | `providers/nearai.py` only fetches; Phala's API does not know NEAR's app IDs (returns `dstack app not found`) |
| C1–C3 | no | not consumed |
| D1–D3 | no | this is a *verification* SDK; no E2EE encrypt/decrypt code |

So Phala has chosen "centralized API publishes reference values" as their
anchor strategy. NEAR has not chosen any anchor strategy — neither a
centralized API nor an on-chain manifest beyond the raw DstackKms /
DstackApp contracts.

---

## 7. Concrete PRs to close the chain

Stack on top of #22 and #23:

**`PR-A` — on-chain anchoring (block B above)**

- Add `py/on_chain.py` with thin `viem`-style or `eth_call`-based readers
  for `DstackKms` and `DstackApp` ABIs.
- Read `canonical_kms_addr` and `per_model_anchor` from a JSON file shipped
  with the verifier (`py/anchors/nearai_mainnet.json`).
- Wire into `verify_attestation` such that block-B failures set
  `VerificationResult.valid = False`.
- Use a simple HTTP RPC by default; document how to point at a Helios light
  client for users who don't want to trust an RPC provider.

**`PR-B` — NEAR publishes the anchor file**

- This is documentation + a JSON commit. NEAR-side action.
- Bare minimum:
  ```json
  {
    "kms_contract_addr": "0x…",
    "models": {
      "zai-org/GLM-5.1-FP8":     {"app_id": "0x2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b"},
      "deepseek-ai/DeepSeek-V3.1": {"app_id": "0x2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b"},
      "openai/gpt-oss-120b":      {"app_id": "0x…?"}
    }
  }
  ```
- Optionally, a NEAR-org-controlled signing key signs each release of
  this file.

**`PR-C` — inner-compose closure (block C above)**

- Add reader for `compose_manager_attestation` in `model_verifier.py`.
- Verify the inner TDX quote shares MRTD with the outer quote.
- Verify `actions_hash == sha256(json(actions))`.
- Find the most recent `compose_up` matching the requested model's YAML;
  fetch from `https://raw.githubusercontent.com/nearai/cvm-compose-files/<commit>/<file>`;
  recompute `sha256` and assert match.
- Parse the YAML and check image digests against
  `py/anchors/nearai_inner_images.json` (also NEAR-published).

**`PR-D` — light-client integration (optional follow-up)**

- Replace HTTP RPC with `helios` or similar so the Base-side reads are
  trustless beyond Ethereum consensus.

With A+B+C the chain is closed against a verifier release whose anchor
files are reviewed at release time. With D the only trust roots remaining
are Intel + NVIDIA + the Base validator set + the verifier release's GPG
signature.

---

## 8. What this audit's "deliverable" looks like, in this framing

The audit's actual deliverable is the gap between section 5 ("what a closed
verifier needs to do") and section 6 ("what today's verifiers actually do").
That gap is concretely: blocks B and C, which is concretely PRs A, B, and
C above.

The DEVPROOF revisit report should reference this design doc for the
verifier-side concerns and treat the deployed-side concerns
(`MODEL_DISCOVERY_*` removal, image-digest pinning, EOA owner, etc.) as
input to the design rather than findings in their own right.
