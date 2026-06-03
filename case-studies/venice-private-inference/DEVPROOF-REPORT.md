# Venice AI Private Inference — Audit Analysis

**Audit date:** 2026-04-24
**Domains:** `api.venice.ai`, `docs.venice.ai`, `github.com/veniceai/skills`
**Core question:** Venice advertises E2EE-capable models. What does the wire actually run, what do the agent skills teach, and does an agent following those skills end up with real confidentiality?

---

## Executive Summary

| Component | Verifiable? | Notes |
|-----------|-------------|-------|
| E2EE-capable model list | ✅ Yes | 11 of 75 models flagged `supportsE2EE` + `supportsTeeAttestation` |
| `/tee/attestation` endpoint | ⚠️ Flaky | Works for most models; `e2ee-glm-5` and `e2ee-qwen3-5-122b-a10b` repeatedly timed out |
| Wire protocol (chat path) | ✅ Confirmed ECIES | SECP256K1 + ECDH + HKDF-SHA256 + AES-GCM, `X-Venice-TEE-*` headers — identical crypto to NEAR AI |
| Venice gateway re-encryption | ✅ Not present | Ciphertext flows through to the model CVM; Venice does not see plaintext on ECIES path |
| `signing_public_key` binding to TDX quote | ⚠️ Done by our client | Docs list as "best practice"; skills never mention it — client-dependent |
| TDX quote verification | ✅ Possible | `intel_quote` field returned; Venice docs link to Phala's verifier |
| GPU attestation (NRAS) | ✅ Possible | `nvidia_payload` returned |
| Multi-backend transparency | ❌ Partial | `tee_provider` field varies per model (`near-ai` vs `phala`) — same E2EE facade, different CVM operators |
| `supportsE2EE` flag → actual E2EE shape | ❌ Inconsistent | `e2ee-gpt-oss-20b-p` attests OK but returns no `signing_public_key` — flag doesn't imply a usable ECIES path |
| `veniceai/skills` — attestation-verification guidance | ❌ Absent | Zero of 6 standard verification steps taught in any SKILL.md |
| `veniceai/skills` — protocol name | ❌ Wrong | Skills say "HPKE / Noise handshake"; real protocol is ECIES. Cited doc URL `docs.venice.ai/e2ee` returns 404. |
| OHTTP / HPKE endpoint | ❌ Not reachable | `ohttp_key_config` (HPKE, X25519) published in attestation body, but no `/ohttp*` endpoint responds — stub or documentation-only |

**Verdict:** The protocol itself is ECIES and is cryptographically sound when the client does the work. The gateway is transparent — Venice does **not** see plaintext on the E2EE path, so this is not a re-encryption backdoor. The backdoor is in the **agent skills** Venice publishes: `veniceai/skills` misnames the protocol, points at a 404 URL, and teaches zero of the six standard TDX-verification steps. An agent that follows the skill as written will either fail to connect or connect with TOFU-trusted keys and no enclave binding.

---

## Architecture

```
                              INTERNET
                                 │
                       HTTPS via Cloudflare
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Venice gateway  (api.venice.ai)                                     │
│  Multiplexes across multiple TEE backends:                           │
│  ├── NEAR AI (cloud-api.near.ai)    tee_provider: "near-ai"          │
│  └── Phala                          tee_provider: "phala"            │
│                                                                      │
│  Does NOT re-encrypt on the ECIES path — pass-through on ciphertext. │
│  Confirmed by live probe: client ephemeral pubkey goes out in        │
│  x-venice-tee-client-pub-key, model pubkey comes back, ciphertext    │
│  decrypts inside the enclave.                                        │
└──────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Backend CVM  (Intel TDX + NVIDIA GPU TEE — NEAR AI or Phala)        │
│                                                                      │
│  - Holds SECP256K1 signing keypair; pubkey bound into TDX report_data│
│  - Returns intel_quote + nvidia_payload + signing_public_key via     │
│    GET /api/v1/tee/attestation?model=…&nonce=…                       │
│  - Also publishes an ohttp_key_config (HPKE / X25519) — no working   │
│    OHTTP endpoint observed; appears unused                           │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Venice Skills — the Agent-Facing Surface

The skills repo [veniceai/skills](https://github.com/veniceai/skills) published 2026-04-21 is a 19-skill catalog. The E2EE-relevant evidence:

**`skills/venice-chat/SKILL.md:238-246`** — the only procedural block an agent sees:

```
## E2EE (end-to-end encryption)

For models advertising `supportsE2EE`:

1. Perform an HPKE / Noise handshake with Venice (see docs.venice.ai/e2ee).
2. Send encrypted payload with the required E2EE request headers.
3. Leave `venice_parameters.enable_e2ee` at default `true`, or set `false` to fall back to TEE-only.
```

Every sentence of this block is wrong or empty:

1. **Wrong protocol name.** The real wire protocol is ECIES (ECDSA SECP256K1 + ECDH + HKDF-SHA256 + AES-GCM). HPKE and Noise are distinct, incompatible constructions. An agent that reaches for `@hpke/core` or `noise-protocol` npm packages will not produce a valid Venice request.
2. **Broken URL.** `docs.venice.ai/e2ee` returns **404**. The real documentation lives at `docs.venice.ai/overview/guides/tee-e2ee-models`.
3. **Undefined headers.** "The required E2EE request headers" is not followed by a list. The actual required headers are `X-Venice-TEE-Signing-Algo: ecdsa`, `X-Venice-TEE-Client-Pub-Key` (uncompressed SECP256K1, 04-prefix, 130-hex), `X-Venice-TEE-Model-Pub-Key`.
4. **No attestation step.** `/tee/attestation` — the endpoint that returns `intel_quote` and `signing_public_key` — is never named in any SKILL.md (zero grep hits for `tee/attestation`, `intel_quote`, `tdx` across the repo).
5. **No verification step.** Zero mentions of `report_data`, MRTD, RTMR, debug-flag, TLS fingerprint, signing-address derivation, or any of the six standard verification steps that turn a TEE attestation into a confidentiality guarantee.

Capability flags in `skills/venice-models/SKILL.md:77-78`:

```
| `supportsTeeAttestation` | Runs inside a TEE with hardware attestation. |
| `supportsE2EE`           | End-to-end encrypted inference available (requires TEE). |
```

These are flags in a table. An agent that reads `supportsE2EE: true` and treats it as "I have E2EE now" has **trusted a metadata assertion**, not a cryptographic binding.

**Verification-gap matrix** (six checks a real E2EE client must perform):

| Step | Taught in any SKILL.md? |
|------|:---:|
| Fetch a TDX quote (`/tee/attestation`) | ❌ |
| Verify quote signature (Intel TDX structure + DCAP/dcap-qvl) | ❌ |
| Check `report_data` binds `signing_address` | ❌ |
| Derive address from `signing_public_key`, compare to bound address | ❌ |
| Pin TLS cert / check live TLS fingerprint | ❌ |
| Check MRTD / RTMR / `td_attributes` debug flag | ❌ |

Six of six absent. The public docs at `docs.venice.ai/overview/guides/tee-e2ee-models` list several of these as "best practices," but the skill — the thing an LLM agent actually loads into its context — does not.

---

## Live Wire Probe — 2026-04-24

Ran against `api.venice.ai/api/v1` with the reference ECIES client at [`hermes_cli/e2ee_transport.py`](https://github.com/amiller/hermes-agent/blob/feat/near-ai-attestation/hermes_cli/e2ee_transport.py) (branch `venice-only`).

**Model inventory.** 11 of 75 models carry both `supportsE2EE: true` and `supportsTeeAttestation: true`:

```
e2ee-venice-uncensored-24b-p   e2ee-qwen3-30b-a3b-p
e2ee-gemma-3-27b-p             e2ee-qwen3-vl-30b-a3b-p
e2ee-glm-4-7-p                 e2ee-glm-5
e2ee-glm-4-7-flash-p           e2ee-qwen3-5-122b-a10b
e2ee-gpt-oss-20b-p             e2ee-qwen-2-5-7b-p
e2ee-gpt-oss-120b-p
```

**Attestation response shape** (from `e2ee-glm-5`):

```
model_name, signing_address, signing_algo, signing_public_key, request_nonce,
intel_quote, nvidia_payload, event_log, info, ohttp_key_config,
compose_manager_attestation, signing_key, verified, model, nonce, nonce_source,
tee_provider, tee_hardware, upstream_model, server_verification,
candidates_evaluated, candidates_available
```

Crypto-relevant fields:
- `signing_algo: "ecdsa"`
- `signing_public_key`: 130-hex, 65 bytes, leading `04` (uncompressed SECP256K1)
- `tee_provider`: varies per model — observed `"near-ai"` (e2ee-glm-5) and `"phala"` (e2ee-venice-uncensored-24b-p). **Same Venice facade, different CVM operators.**
- `nonce_source: "client"` (caller's nonce is bound into TDX `report_data`)

**Probe A — ECIES chat roundtrip: PASS.**

- Model: `e2ee-venice-uncensored-24b-p`
- Outgoing request headers: `x-venice-tee-signing-algo: ecdsa`, `x-venice-tee-client-pub-key: 04…`, `x-venice-tee-model-pub-key: 04…`
- Outgoing body `messages[0].content` replaced with hex envelope (`04 || eph_pub(64) || nonce(12) || ciphertext || tag`)
- HTTP 200; response body decrypted with the ephemeral key to plaintext (`"Ping!"`)
- Response headers include `x-venice-tee: true`, `x-venice-tee-provider: phala`

Result: Venice **does not** re-encrypt on the ECIES path. The ciphertext the client emits is what the model CVM decrypts. Gateway is transparent for confidentiality on the E2EE path.

**Probe B — HPKE / Noise / OHTTP advertisement: PARTIAL.**

- Strings `hpke`, `noise` appear zero times in the attestation response or response headers.
- `ohttp_key_config` IS present: a 45-byte RFC 9458 blob advertising HPKE.
  - `key_id = 1`
  - `kem_id = 0x0020` → DHKEM(X25519, HKDF-SHA256)
  - X25519 pubkey (32 bytes): `7ab01e13754cc4f0ebcbe78f1e23ae9a9509fb2483642ce2d9c9fa19cc4dea21`
  - Suites offered: `(HKDF-SHA256, AES-128-GCM)` and `(HKDF-SHA256, ChaCha20Poly1305)`
- No `/ohttp*`, `/tee/ohttp*`, `/ohttp-keys`, `/ohttp-gateway`, `/hpke`, `/tee/hpke` endpoint responds (all 404)
- The chat path (`/v1/chat/completions`) is not OHTTP-wrapped — it takes JSON, not `message/ohttp-req`

Conclusion: Venice publishes an HPKE key in the attestation bundle but **has no observable HPKE/OHTTP transport**. Either it's a stub for a future OHTTP gateway or leftover infrastructure. The skill's "HPKE/Noise handshake" guidance does not describe anything an agent can actually reach.

**Shape inconsistency.** `e2ee-gpt-oss-20b-p` returned `verified: true` on its attestation but no `signing_public_key` field. The `supportsE2EE` flag does not imply a consistent ECIES surface across all flagged models.

**Flakiness.** `/tee/attestation` timed out repeatedly on `e2ee-glm-5` and `e2ee-qwen3-5-122b-a10b`. Worked quickly on `e2ee-venice-uncensored-24b-p` and `e2ee-gpt-oss-20b-p`. Not transient — consistent across retries.

---

## Venice as Multi-Backend Front

Per-request the attestation body reports `tee_provider` and `tee_hardware`. Observed values:
- `e2ee-glm-5` → `tee_provider: "near-ai"` (confirms Venice resells NEAR AI)
- `e2ee-venice-uncensored-24b-p` → `tee_provider: "phala"` (confirms Venice also runs on Phala-operated CVMs)

Venice's own privacy page names both as TEE partners. This is consistent with wire evidence.

Implications:
- The `supportsE2EE: true` flag tells an agent **nothing** about which operator runs the model it's about to encrypt to. Operator-level trust assumptions (logging policy, upgrade process, debug flag) differ between NEAR AI and Phala.
- A case study of Venice E2EE inherits at minimum whatever trust posture the underlying backend has. For `near-ai` models, that means all the gaps documented in [near-ai-private-inference](../near-ai-private-inference/DEVPROOF-REPORT.md) (inner compose not in RTMR3, NRAS failing on some models, OutOfDate TCB on ~80% of the fleet).
- A client that does not read `tee_provider` from the attestation and adjust its verification path is treating two very different deployment shapes as interchangeable.

---

## Where the Trust Actually Breaks

Venice's E2EE is a layered stack. Failure is possible at any layer:

| Layer | Status |
|-------|--------|
| 1. TLS to `api.venice.ai` | ✅ Normal Cloudflare-fronted HTTPS |
| 2. ECIES ciphertext flows through gateway | ✅ Gateway does not decrypt |
| 3. Model CVM decrypts with `signing_public_key` holder | ✅ (assuming the key belongs to the CVM) |
| 4. **`signing_public_key` actually belongs to a verified TDX enclave** | ⚠️ Client-dependent — not enforced by the API itself |
| 5. **Client parses `intel_quote`, verifies signature, checks `report_data` binds signing_address** | ⚠️ Client-dependent |
| 6. **Client derives address from `signing_public_key` and compares** | ⚠️ Client-dependent |
| 7. Inner compose (inference-proxy + vLLM) measured in RTMR3 (NEAR backend) | ❌ Not extended — same gap as the NEAR case study |
| 8. Debug-flag check on TDX attributes | ⚠️ Client-dependent |
| 9. GPU NRAS attestation | ⚠️ Client-dependent; known-failing for parts of NEAR fleet |

Layers 4–8 are where `veniceai/skills` drops the ball. A skill-following agent jumps from layer 1 straight to layer 9 by assumption — skipping precisely the steps that make the TEE meaningful. This is the "TOFU signing key" backdoor: any gateway that returns a plausible `signing_public_key` is trusted, and the enclave binding is never checked.

---

## Privacy Analysis

**Protected from Venice gateway ✅.** ECIES path is pass-through. Venice cannot read plaintext on E2EE-enabled models *if* the client encrypted to an enclave-bound key.

**Protected from underlying operator (NEAR AI or Phala) ❌ — inherited.** Whichever operator runs the model CVM inherits the posture documented in `near-ai-private-inference` or Phala's per-app gaps. For NEAR-backed models: inner compose not in RTMR3, operator holds `BEARER_TOKEN`, `/compose/logs` exfil path available.

**Protected via E2EE when client follows the skill ❌.** Skill teaches no verification. Signing-key substitution is not blocked. The crypto is correct; the anchor isn't.

---

## Documentation Hierarchy — Where the Truth Lives

| Source | Accuracy |
|--------|:---:|
| `docs.venice.ai/overview/guides/tee-e2ee-models` | ✅ Correct protocol, correct headers, best-practice checklist |
| Venice API (`/models` + `/tee/attestation`) | ✅ Returns all fields a client needs to do full verification |
| `veniceai/skills` (the thing agents load) | ❌ Misnames protocol; 404 URL; omits every verification step |

The gap is squarely in the agent-facing layer. This is the pattern we're cataloging: **TEE infrastructure is present and usable, but the surface developers and agents interact with — the SKILL.md, the SDK examples, the README snippet — silently skips the verification that makes the TEE real.** Venice's skill is a textbook instance.

---

## Stage Assessment

**Venice E2EE infrastructure (what the backend provides):** Stage 0–1.
- Hardware isolation + attested signing key exist.
- Multi-operator backends (NEAR + Phala) means the ERC-733 "no centralized infrastructure" checkbox is per-model, not per-Venice.
- Weakened by flaky `/tee/attestation` (some models not reachably verifiable).

**Venice E2EE client story (what `veniceai/skills` gives users):** Stage 0.
- Skill teaches none of the verification steps.
- Skill misnames the protocol; cited doc URL is a 404.
- An agent that follows the skill as written builds a TOFU connection.

**Overall catalog classification:** this is a **"backdoor by inattention"** case — not a deliberate exfiltration path, not malicious protocol design, but a wide-open gap between the claimed privacy property and what an agent following the public guidance will actually achieve. Fixes are skill-text changes, not infrastructure changes.

---

## Recommendations

**Venice: rewrite `skills/venice-chat` E2EE section.** Name the protocol correctly (ECIES: SECP256K1 + ECDH + HKDF-SHA256 + AES-GCM). Link to `docs.venice.ai/overview/guides/tee-e2ee-models`, not `docs.venice.ai/e2ee`. List the three required `X-Venice-TEE-*` headers and the `04`-prefix uncompressed-pubkey format. Add a pre-flight "fetch `/tee/attestation`, verify it, derive address from `signing_public_key` and compare" step. This is a 20-line edit to one SKILL.md.

**Venice: expose or remove `ohttp_key_config`.** If there's a planned OHTTP/HPKE gateway, ship the endpoint and document it. If not, stop advertising an HPKE pubkey that doesn't go anywhere — it encourages wrong implementations.

**Venice: fix `/tee/attestation` reliability.** Two of 11 E2EE models repeatedly time out. An attestation endpoint that doesn't respond is the same as no attestation.

**Venice: surface `tee_provider` in `/models`.** A client reading `/models` should be able to see whether a given model runs on NEAR AI or on Phala CVMs before sending a prompt. Hiding that behind an attestation fetch means most callers won't know which trust posture they're adopting.

**Client implementers: don't trust `supportsE2EE: true` as a confidentiality claim.** Treat it as "there's an attestation fetchable at `/tee/attestation`." Do the verification. If you can't, send prompts to a `tee-*` (TEE-only) model or don't use Venice for sensitive content.

**Third-party auditors: the protocol compatibility with NEAR AI means the `hermes_cli` transport works against Venice with a header-name change.** Venice-specific verification gaps (debug flag, inner compose measurement) transfer directly from the NEAR AI case study.

---

## Source Evidence

| Thing | Location |
|-------|----------|
| Skills repo | [github.com/veniceai/skills](https://github.com/veniceai/skills) @ initial commit `ae3db1f` (2026-04-21), unchanged through `de089fa` |
| Wrong "HPKE/Noise" block | `skills/venice-chat/SKILL.md:238-246` |
| Capability-flag rows | `skills/venice-models/SKILL.md:77-78` |
| Correct protocol doc | `https://docs.venice.ai/overview/guides/tee-e2ee-models` |
| Broken URL cited by skill | `https://docs.venice.ai/e2ee` (404) |
| Venice names NEAR AI + Phala as TEE partners | `https://venice.ai/privacy` |
| Reference ECIES client | [`hermes_cli/e2ee_transport.py`](https://github.com/amiller/hermes-agent/blob/feat/near-ai-attestation/hermes_cli/e2ee_transport.py) (`VeniceE2EETransport`) |
| Reference attestation client | [`hermes_cli/attestation.py`](https://github.com/amiller/hermes-agent/blob/feat/near-ai-attestation/hermes_cli/attestation.py) (`AttestationVerifier._verify_venice`, lines 601-709) |
| Live probe harness | `/tmp/venice_probe4.py` (local, not committed) |
| Existing Venice integration tests | `tests/hermes_cli/test_nearai_e2ee.py::TestVeniceLiveAttestation` |

## See Also

- [near-ai-private-inference](../near-ai-private-inference/DEVPROOF-REPORT.md) — upstream for Venice's `tee_provider: near-ai` models; inherits all documented gaps
- [phala-private-ai-verifier](../phala-private-ai-verifier/DEVPROOF-REPORT.md) — the attestation SDK that *should* cover Venice but doesn't (no Venice provider implemented)
- [redpill-federated-inference](../redpill-federated-inference/DEVPROOF-REPORT.md) — sibling multi-backend router pattern
