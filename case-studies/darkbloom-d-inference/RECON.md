# Darkbloom (d-inference) — Initial Recon

**Recon Date:** 2026-05-10
**Subject:** [Layr-Labs/d-inference](https://github.com/Layr-Labs/d-inference) — product brand "Darkbloom" by Eigen Labs (the EigenLayer org). Repo HEAD `cf4c0ef` ("ci: remove racing deploy-dev-coordinator workflow").
**Live API:** `https://api.darkbloom.dev` (66 providers / 65 attested at probe time).
**License:** Proprietary, all rights reserved. Repo carries a "🚧 not audited, not for production" disclaimer.
**Paper:** Naik, *Private Decentralized Inference on Consumer Hardware*, Eigen Labs, April 2026. `repo/papers/dginf-private-inference.pdf`. Provisional patent draft also in repo.

## Why this case is interesting

Every prior case study in this guide audits an Intel-TDX or AMD-SEV-SNP server-class CVM (oauth3-burnt, tinfoil, near-ai-private-inference, redpill, venice). Darkbloom is the first **edge-TEE** subject we've looked at and it deliberately uses *no* application-level memory encryption on the inference node. Apple Silicon offers no TEE that third-party code can sit inside, so the project's design philosophy is "eliminate every software path through which the machine owner could observe inference data and prove the eliminations remain in force." Apple's own Private Cloud Compute is the explicit prior art (paper §2). What is novel here is doing it on **adversarial-owned** hardware.

The system is also two-tier — the inference node is software-only-TEE-equivalent, but the **coordinator** is a normal CVM. This doubles the attestation chain we have to evaluate.

## Trust topology

```
Consumer SDK / web UI / curl
   │
   │ ① HTTPS  (optional sealed envelope to coordinator's long-lived X25519 — opt-in)
   ▼
Coordinator (Go)  ─── runs inside EigenCloud TEE in prod
   │                  (GCP SEV-SNP CVM in dev — see docs/dev-environment.md)
   │ ② NaCl Box (X25519 + XSalsa20-Poly1305) to provider's encryptionPublicKey
   │   The coordinator decrypts ① first to route by model, then encrypts ② per provider.
   ▼
Provider (Rust + embedded Python via PyO3) ─── runs on a third-party Mac
   │ ▸ PT_DENY_ATTACH at startup
   │ ▸ Hardened Runtime (no get-task-allow ⇒ task_for_pid denied)
   │ ▸ SIP + SecureBoot enforced and re-checked every 5 min
   │ ▸ Optional Hypervisor.framework guest with Stage 2 page tables (DMA defense)
   │ ▸ X25519 keypair bound to a Secure Enclave P-256 attestation
   ▼
mlx-lm / vllm-mlx (in-process via PyO3) → Metal → Apple Silicon GPU
```

Two encryption hops, two TEE substrates, two operators with distinct privileges:

| Operator | Controls | Constrained by |
|---|---|---|
| **Eigen Labs (coordinator)** | Coordinator image, blessed-binary registry, model catalog, MDA verification logic, long-lived X25519 key | Whatever attestation EigenCloud TEE publishes for the `d-inference` app |
| **Provider (Mac owner)** | macOS root, physical custody, network ingress/egress, hardware itself | Apple SE-bound key + SIP + Hardened Runtime + MDA cert chain (when enrolled) + binary-hash gate at coordinator |

## What's claimed (paper + README + ARCHITECTURE.md)

1. **Software path elimination, not memory encryption.** No subprocess, no IPC, no localhost server, no Unix socket — MLX runs in the same hardened process. Memory is wiped (volatile zero + fence) after each request.
2. **Theorem 1 (paper §?):** SIP is "immutable for the process lifetime" because disabling it requires a reboot, which terminates the process. Need to read the proof to find its assumptions (kernel exploit excluded? recovery-to-recovery transitions?).
3. **Multi-layer attestation:**
   - L1 — Secure Enclave P-256 ECDSA signature over an attestation blob (chip, model, SIP, SecureBoot, ARV, system-volume hash, X25519 encryption pubkey, **provider binary SHA-256**, timestamp).
   - L2 — Apple MDM `SecurityInfo` cross-check (independent confirmation of SIP/SecureBoot/SSV/FileVault).
   - L3 — Apple Managed Device Attestation (MDA) cert chain, leaf signed by Apple Enterprise Attestation Sub CA 1, anchored at Apple Enterprise Attestation Root CA. Carries OIDs for serial, UDID, OS version, SepOS version, Secure Boot level, and a freshness nonce.
   - L4 — 5-min challenge-response over WebSocket; immediate untrust if SIP or SecureBoot is reported false.
4. **Coordinator binary-hash gate.** The coordinator only routes traffic to providers whose attested `binaryHash` matches a release that was registered via `POST /v1/releases` from GitHub Actions. CI signs/notarizes the bundle and computes SHA-256 *after* code-signing.
5. **Coordinator re-encryption.** The coordinator (inside its CVM) takes the routing decision, then NaCl-Box-seals the request to the chosen provider's X25519 key. The provider's X25519 is bound to its SE-attested identity (`encryptionPublicKey` field is part of the attested blob).
6. **Optional hypervisor isolation.** The provider can run inside an Apple `Hypervisor.framework` guest with Stage 2 page tables. Closes the DMA attack vector at "zero performance cost" (claimed).
7. **`MIN_TRUST=hardware` enforced in prod and dev.** Trust levels `none` and `self_signed` are visible in the public attestation feed but not eligible for routing in production.
8. **User-verifiable attestation feed.** `GET /v1/providers/attestation` is public-no-auth, returns SE pubkey + Apple MDA cert chain (base64 DER) per provider. Clients can verify chain → Apple Root CA themselves with any standard x509 library.
9. **Sender→coordinator encryption is OPT-IN.** A client can `GET /v1/encryption-key` (today: `kid=833aec78e1c7c828`, `algorithm=x25519-nacl-box`) and `Content-Type: application/eigeninference-sealed+json` to seal the request body. Default path is plaintext-over-HTTPS into the coordinator TEE.

## Live network snapshot (probe `2026-05-10`)

```
GET /health            → {"providers":66,"status":"ok"}
GET /v1/encryption-key → kid=833aec78e1c7c828, x25519-nacl-box
GET /v1/providers/attestation → 65 providers, 103 KB
```

By chip family (live, sorted): M4 Max ×11, M3 Ultra ×11, M4 ×8, M4 Pro ×7, M1 Max ×7, M3 Max ×5, M2 Max ×3, M3 Pro ×3, M2 Ultra ×3, **M5 Max ×2**, **M5 Pro ×1**, **M5 ×1**, M1 Ultra ×1, M1 ×1, M1 Pro ×1.

By trust:
- `hardware`: 38
- `self_signed`: 24
- `none`: 3
- `mda_verified=true`: 35  (← 3 fewer than `hardware` claims; worth tracing)
- `sip_enabled`: 65 / 65
- `status`: 63 online + 2 serving

Apple M5 silicon is freshly available and already enrolled, so the live network is current.

## Three docs disagree about who sees plaintext

| Source | Says |
|---|---|
| `README.md` §How It Works | "The coordinator encrypts each request with the provider's X25519 public key before forwarding it." (⇒ coordinator sees plaintext) |
| `docs/ARCHITECTURE.md` §Coordinator | "Consumers send plain text over HTTPS; the Confidential VM is the trust boundary." (⇒ coordinator sees plaintext) |
| `CLAUDE.md` §Key Design Decisions | "Coordinator never sees plaintext prompts. Decryption only inside the hardened provider process." (⇒ coordinator does NOT see plaintext) |
| Code (`coordinator/internal/api/sender_encryption.go`, `consumer.go:12`) | Sender encryption is optional; when used, "the middleware transparently decrypts the body so downstream handlers see plaintext, and re-seals the response." Coordinator decrypts to route by model. |

**The code is authoritative: the coordinator's CVM is the trust boundary.** This matters for two reasons:

1. The marketing line "they cannot see your data" applies to the *provider operator*, not to Eigen Labs. Eigen Labs sees plaintext inside the coordinator TEE and the user must trust EigenCloud's TEE attestation transitively.
2. Several public-facing docs overstate the guarantee. The CLAUDE.md sentence in particular is wrong as written and should be flagged.

## Audit framing per AUDIT-GUIDE — Prompt-Path Test, applied twice

The framework's Prompt-Path Test asks: for each operator-controllable slot, can the operator intercept/redirect/log/sign/decrypt user content? Darkbloom has two operators, so we run it twice.

### Coordinator side (Eigen Labs as operator)

The coordinator handler sees plaintext for every request that did not opt into sealed mode (≈ all traffic in practice). Slots an Eigen-internal change can affect:

- **Coordinator image** → controls everything. Whatever attestation EigenCloud publishes for this image is the only thing constraining the operator. **TODO:** find the EigenCloud TEE attestation surface and check whether it pins the coordinator image hash to a Git commit / Docker digest, and whether there's a transparency log. This is the moral equivalent of dstack's `compose_hash` for this case.
- **Long-lived X25519 key** (`/v1/encryption-key`, kid `833aec78e1c7c828`) → derived from a BIP39 mnemonic via SLIP-0010 with domain separation (`coordinator/internal/e2e/coordinator_key.go`). If Eigen Labs holds the mnemonic outside the TEE, sealed-mode privacy collapses for that key generation.
- **Blessed binary-hash registry** → coordinator verifies provider attestations against a list of "known blessed versions" registered via `POST /v1/releases` (handler in `release_handlers.go`). Who can call this endpoint? Is the list public? Append-only? Need to read the handler.
- **MDA root CA pin** → the coordinator embeds Apple Enterprise Attestation Root CA. If the embedded root is replaced in a coordinator release, MDA verification can be silently weakened.
- **Model catalog + scoring** → routing decisions select the provider. Routing isn't on the prompt path for confidentiality (any selected provider is attested) but **is** on the integrity path: a malicious coordinator can route to an attacker-favored provider for any reason.

Verdict pending: **likely Stage 0** until we trace the EigenCloud attestation story for the coordinator. The provider-side hardening is wasted if the coordinator image is unpinned or its TEE attestation isn't externally verifiable.

### Provider side (Mac owner as operator)

The provider operator's prompt-path slots are blocked by a stack of OS-level mechanisms; the paper enumerates them in a single table (ARCHITECTURE.md §Why Providers Can't Read Prompts):

| Surface | Defense |
|---|---|
| Debugger attach (`lldb`) | `PT_DENY_ATTACH` + Hardened Runtime denies `task_for_pid` |
| Memory read of inference process | Hardened Runtime (kernel-enforced) |
| IPC sniff | No IPC; MLX is in the same Rust process via PyO3 |
| Modified binary | Code signing + SIP refuses to launch; binary SHA-256 in attestation; coordinator gates by hash |
| Malicious Python pkg | Python import path locked to the bundled, signed packages |
| Kext load | SIP blocks unsigned kexts |
| Kernel patch at runtime | KIP (hardware-enforced) |
| Disable SIP at runtime | Requires reboot ⇒ kills process ⇒ wipes data |
| `/dev/mem` | Doesn't exist on Apple Silicon |
| DMA attack | IOMMU default-deny + optional Hypervisor.framework Stage 2 page tables |
| Physical memory probe | LPDDR5x soldered into SoC die — lab-grade attack |

If Theorem 1 holds, the provider operator's prompt-path is closed up to a residual physical-attack threat that Apple PCC also accepts. **The audit work here is verifying each cell, not finding gaps in the architecture.**

Verdict pending: depends on Theorem 1 plus implementation soundness. Same-day skim of `provider/src/security.rs`, `enclave/Sources/EigenInferenceEnclave/`, and the SIP-check call sites is the next step.

## Source provenance & build pipeline (positive notes vs prior case studies)

In contrast to oauth3 / Phala-KMS apps that fail Source Provenance and Image Pinning, darkbloom's pipeline is unusually traceable on the provider side:

```
GitHub master branch
  → .github/workflows/release.yml
    → cargo build (no-default-features, distribution mode)
    → codesign with Developer ID Application cert
    → Apple notarytool notarization
    → SHA-256 over the SIGNED binary  ← order matters; CLAUDE.md flags this
    → upload to R2 (s3://d-inf-app/releases/v{VERSION}/)
    → POST /v1/releases registers (version, sha256) with coordinator
  → install.sh (served by coordinator) verifies SHA-256 + codesign before launch
  → provider attestation includes binaryHash; coordinator gates routing by hash
```

This is a complete chain: source commit → notarized artifact → registered hash → attested-and-gated execution. The remaining gap is whether the released binary is **bit-for-bit reproducible** without Apple's signing service — almost certainly not, since the codesign step injects per-build signatures. So a third-party auditor cannot independently rebuild and match. They can verify (a) the GitHub release is what GitHub Actions produced, and (b) the SHA in the coordinator matches a public release. That's still better than "trust me."

## Open audit questions

1. **EigenCloud TEE attestation surface.** What hardware does EigenCloud use for the `d-inference` app? Where is the coordinator image hash published? Is there a transparency log for upgrades? *(This is the most load-bearing unknown — if EigenCloud is opaque, the whole system reduces to "trust Eigen Labs.")*
2. **Discrepancy between `trust_level=hardware` and `mda_verified=true` in the live feed.** 38 vs 35 — three providers claim hardware trust without an MDA flag. Trace through `coordinator/internal/registry/` and `attestation/mda.go` to find the rule.
3. **`POST /v1/releases` access control.** Who can register a blessed binary hash? Is the registry append-only and publicly readable?
4. **Theorem 1 assumptions.** Read paper §? carefully. The "SIP is immutable for the process lifetime" claim presumably depends on no-kernel-exploit and no-DMA-from-PCIe assumptions. Both are reasonable but worth stating explicitly.
5. **`self_signed` providers in the live feed.** README claims only `self_signed` and `hardware`; ARCHITECTURE.md adds `none`. Live feed shows 24 self_signed + 3 none. CLAUDE.md says `MIN_TRUST=hardware` in prod. So either the public feed includes ineligible providers (transparency feature, fine) or the routing gate is weaker than CLAUDE.md says. Need to verify by reading routing code.
6. **Sealed-mode adoption.** Does the official Python SDK (`from eigeninference import EigenInference`) default to sealed mode, or to plaintext? If sealed mode is opt-in, the realistic threat model for most users is "trust Eigen's coordinator TEE."
7. **Coordinator long-lived X25519 mnemonic custody.** `coordinator/internal/e2e/coordinator_key.go` derives the key from a BIP39 mnemonic. Where is the mnemonic stored at rest? If it lives in EigenCloud KMS (per the deploy runbook reference) and is sealed to the TEE, sealed-mode actually provides forward secrecy under coordinator compromise. If it's a plain env var, it doesn't.
8. **Hypervisor.framework requirement vs. opt-in.** Is the Stage-2-page-table guest mandatory or opt-in? `provider/src/hypervisor.rs` exists; entitlement `com.apple.security.hypervisor` is in `scripts/entitlements.plist`. Need to verify production providers actually enable it.
9. **Apple's MDA freshness window.** MDA cert chains include a freshness OID. How frequently does the coordinator re-request `DevicePropertiesAttestation`, and what's the staleness tolerance?
10. **Patent draft scope.** `papers/provisional-patent-draft.md` is the inventor's own description of what is novel; reading it will isolate the core security mechanisms vs. the workaday plumbing.

## What an audit report against the framework would look like

The dstack-shaped checklist (compose_hash, allowed_envs, KMS-key-provider, transparency log, source provenance, image pinning, secret isolation) doesn't translate one-to-one. A darkbloom-shaped checklist would have **two columns**:

| Check | Coordinator side (CVM) | Provider side (edge) |
|---|---|---|
| Hardware integrity attestation | EigenCloud TEE quote | SE-signed blob + Apple MDA cert chain |
| Image / binary pinning | Coordinator image registered to TEE attestation? | binaryHash gate via `POST /v1/releases` ✓ |
| Source provenance | EigenCloud build pipeline | GitHub Actions → notarized → SHA registered ✓ (modulo non-reproducibility of codesign) |
| Transparency log | Unknown — biggest open question | Coordinator's blessed-hash registry; need to confirm public/append-only |
| Secret isolation | Coordinator long-lived X25519 mnemonic custody | Provider X25519 bound to SE attestation ✓ |
| Operator can read prompts? | **Yes by design** in default plaintext mode | No, modulo Theorem 1 |
| Operator can swap prompt path? | Yes (chooses model & provider) | No (binary-hash gated) |
| Sealed mode available? | Opt-in via `Content-Type` ✓ | n/a |
| Verifier surface for end users | Hidden until EigenCloud story is documented | `GET /v1/providers/attestation` is real, parseable, publicly accessible ✓ |

This case study should also expand the framework's `AUDIT-GUIDE.md` taxonomy with an "Edge-TEE substitution" section that documents how to evaluate "no-memory-encryption-but-software-path-elimination" trust models, with darkbloom and Apple PCC as the canonical examples.

## Key code paths to read next

- `coordinator/internal/api/sender_encryption.go` — opt-in seal/unseal middleware (already partially read).
- `coordinator/internal/api/consumer.go` lines around 720 ("E2E encryption — must be done per provider").
- `coordinator/internal/api/provider.go:1211–1230` — bind WebSocket X25519 key to attested encryption pubkey.
- `coordinator/internal/api/release_handlers.go` — who can register blessed binary hashes.
- `coordinator/internal/attestation/mda.go` — MDA cert chain verification + serial cross-check.
- `coordinator/internal/registry/` — provider routing, scoring, MIN_TRUST gate.
- `coordinator/internal/e2e/coordinator_key.go` — long-lived X25519 from BIP39 mnemonic.
- `provider/src/security.rs` — SIP / SecureBoot / PT_DENY_ATTACH / binary self-hash.
- `provider/src/hypervisor.rs` — Hypervisor.framework Stage 2 page tables.
- `enclave/Sources/EigenInferenceEnclave/` — SE P-256 keygen + attestation blob signing + FFI bridge to Rust.
- `papers/dginf-private-inference.pdf` §Theorem 1 + §Software Attack Surface enumeration.
- `papers/provisional-patent-draft.md` — what Eigen considers novel/defensible.

## Quick references

- Live API: `https://api.darkbloom.dev/v1`
- Public attestation feed: `https://api.darkbloom.dev/v1/providers/attestation` (no auth)
- Coordinator encryption pubkey: `https://api.darkbloom.dev/v1/encryption-key`
- Web console: `https://console.darkbloom.dev`
- Repo HEAD on recon: `cf4c0ef`
- Vendor support: `security@eigenlabs.org`
