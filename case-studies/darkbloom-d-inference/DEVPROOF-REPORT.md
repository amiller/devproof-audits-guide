# Darkbloom (d-inference) DevProof Audit

**Audit date:** 2026-05-10
**Subject:** [Layr-Labs/d-inference](https://github.com/Layr-Labs/d-inference) — product brand "Darkbloom" by Eigen Labs
**Repo HEAD on audit:** `cf4c0ef` ("ci: remove racing deploy-dev-coordinator workflow")
**Provider release audited:** v0.4.7 (registered 2026-04-26, `binary_hash 88848229…`, `bundle_hash f3eb0c1c…`)
**Live API:** `https://api.darkbloom.dev` (66 providers / 65 attested at probe time)
**Reference paper:** Naik, *Private Decentralized Inference on Consumer Hardware*, Eigen Labs, April 2026 — `repo/papers/dginf-private-inference.pdf`
**Re-verifier:** `case-studies/darkbloom-d-inference/verify/` — openssl + Python `cryptography`. Reproducible from a single terminal session, no payment, no account.
**Repo disclaimer:** "🚧 Darkbloom is under active development and has not been audited… should be used only for testing purposes and not in production. 🚧"

**Note on repo identity.** A second GitHub repo at `darkbloomdev/darkbloom` carries the same code but is a stale snapshot — single "Initial commit from Layr-Labs/d-inference" dated 2026-04-20, never updated, 1 star vs 138 on Layr-Labs. Active development happens at `Layr-Labs/d-inference`; the audit targets that tree. The `darkbloomdev` org appears to be a placeholder for the brand rename ("EigenInference / d-inference" → "Darkbloom"); not a parallel codebase or release source.

**Recent hardening (positive credit).** Two PRs landed on `Layr-Labs/d-inference` between 2026-04-30 and the audit date, and *substantially* tightened the binary-hash gate: PR #99 ("Harden release registration and binary hash policy", `b5dd048`) made Open Mode untrust when a hash policy is configured, added a registration→challenge binary-hash consistency check, required valid attestation before any binary-hash claim, and added constant-time release-key comparison. PR #103 ("Harden release workflow protections", `e515244`) restricted release-workflow token permissions, validated prod-release source against `origin/master`, and pinned `uv` + `vllm-mlx` archives against supply-chain drift. Findings F1–F5 below stand because they target different gaps (binding gate, public feed completeness, coordinator attestation, transparency log, client-side verifiers), but the team is clearly attending to the integrity-in side of the release flow.

---

## Quick Status

| Check | Provider tier | Coordinator tier | Overall |
|---|:---:|:---:|:---:|
| TEE / hardware-rooted attestation | PASS (Apple SE + MDA) | **FAIL** (no public quote) | PARTIAL |
| Hardware integrity claim | PASS (cert chain to Apple's root verifies) | **FAIL** (claim only) | PARTIAL |
| Transparency log | n/a | **FAIL** (no public release history) | **FAIL** |
| Reproducible build | PARTIAL (source pinned; codesign/notarization breaks bytewise reproducibility — structural ceiling for any notarized macOS app) | n/a | PARTIAL |
| Source provenance | PASS (bundle/binary hashes match manifest; binary's panic paths, symbols, entitlements all consistent with repo) | unknown | PARTIAL |
| Image / binary pinning | PASS (binary hash gated at routing) | **FAIL** (no published image hash) | PARTIAL |
| Secret isolation | PASS (X25519 bound to SE attestation) | PARTIAL (long-lived X25519 mnemonic custody in EigenCloud KMS, externally invisible) | PARTIAL |
| Operator-controllable prompt-path slots | None on attested-binary path | Default plaintext-into-CVM; sealed mode opt-in | **see findings** |

**Overall: Stage 0 today, despite a much stronger provider-side build than the dstack/Phala cohort.** The provider side has unusually clean source provenance (Apple-notarized → SHA registered → coordinator-gated), but the coordinator-as-trust-kingpin sits behind no externally fetchable attestation. Until a coordinator quote (or build-pipeline predicate) is published, every protection on the provider side rests on an opaque middle.

---

## Bottom Line

> Apple's vouching is real. Every MDA cert chain in the live feed verifies against Apple's Enterprise Attestation Root CA. Provider source provenance is unusually clean. **But** three concrete gaps mean a TEE-style "the device that decrypts my prompt is genuine Apple hardware running an attested binary" verification is not achievable from outside the coordinator today: (1) the MDA→SE-key binding silently fails for **13/30 (43%)** hardware-trust providers in the live network, (2) the SE-signed AttestationBlob is not in the public feed so security-state fields are coordinator-asserted, (3) the coordinator runs in a TEE per self-claim but exposes no externally fetchable attestation surface.

The repo agrees this is research-preview-not-production maturity. The audit findings are scoped to *what would need to change for the project to graduate to "verifiable inference at the level of the dstack/Tinfoil cohort"* — they are devproofness gaps, not exploits.

---

## Architecture

### System overview

```
Consumer SDK / web UI / curl
   │
   │ ① HTTPS  (sender→coordinator sealed envelope is OPT-IN per Content-Type;
   │           default = plain HTTPS into the coordinator CVM)
   ▼
Coordinator (Go) ─── Intel TDX TEE on EigenCompute in prod (per paper Fig 1)
   │                  GCP SEV-SNP CVM in dev
   │                  ✗ no externally fetchable attestation surface today
   │ ② NaCl Box (X25519 + XSalsa20-Poly1305) to provider's encryptionPublicKey
   │   Coordinator decrypts ① first to route by model, then encrypts ② per provider.
   ▼
Provider (Rust + embedded Python via PyO3) ─── third-party Mac
   │ ▸ PT_DENY_ATTACH at startup
   │ ▸ Hardened Runtime (no get-task-allow ⇒ task_for_pid denied)
   │ ▸ SIP + SecureBoot enforced and re-checked every 5 min
   │ ▸ Optional Hypervisor.framework guest with Stage 2 page tables (DMA defense)
   │ ▸ X25519 keypair bound to a Secure Enclave P-256 attestation
   │ ▸ Binary SHA-256 in attestation; coordinator gates on registered hash
   ▼
mlx-lm / vllm-mlx (in-process) → Metal → Apple Silicon GPU
```

### Four-layer attestation (per paper §7 Table 2)

```
   ┌───────────────────────────────────────────────────────────────────┐
   │ Layer 1 — Secure Enclave P-256 ECDSA                              │
   │    Hardware-bound identity; signs AttestationBlob (chip, model,   │
   │    SIP, SecureBoot, ARV, system_volume_hash, encryptionPublicKey, │
   │    binaryHash, timestamp). Replay-prevention by registration nonce │
   ├───────────────────────────────────────────────────────────────────┤
   │ Layer 2 — MDM SecurityInfo                                         │
   │    OS-side MDM client reports SIP / SecureBoot / ARV / FileVault. │
   │    Independent of provider software; spoofing requires SIP off,   │
   │    which itself requires SIP off (circular per Proposition 1).    │
   ├───────────────────────────────────────────────────────────────────┤
   │ Layer 3 — ACME device-attest-01 / Apple MDA                        │
   │    Apple-signed P-384 leaf cert chain. Carries serial, UDID,      │
   │    OS, SepOS, LLB, SIP, SecureBoot level, and a 32-byte freshness │
   │    code = sha256(SE pubkey b64). Anchors trust at Apple Root CA.  │
   ├───────────────────────────────────────────────────────────────────┤
   │ Layer 4 — Continuous Challenge-Response (every 5 min)             │
   │    σ = Sign_SE(n ‖ t ‖ pk).  ⚠ Per paper §7.4 the signature       │
   │    scope is exactly (n,t,pk). Status fields (sip_enabled, etc.)   │
   │    are reported but NOT in σ. v0.3.11+ adds opt-in `status_signature` │
   │    that covers the canonical status payload — see F-discussion.   │
   └───────────────────────────────────────────────────────────────────┘
```

### What's externally verifiable vs coordinator-asserted

```
Apple Enterprise Attestation Root CA (P-384, embedded in coordinator src)
    │   ✓ chain verifies — we did this on 5/5 sampled providers
    ▼
Apple Enterprise Attestation Sub CA 1 (P-384)
    │   ✓ chain verifies
    ▼
Per-device leaf cert (P-384, ~3-month validity)
    │   ✓ OIDs (serial/UDID/OS/SepOS) cross-check the public feed (30/30)
    │
    │  ⚠ THE BINDING JUMP: freshness OID = sha256(SE pubkey b64)
    │  ✓ verifiable from public feed alone
    │  ✗ FAILS for 13/30 hardware-trust providers in production today (F1)
    │
    ▼
Provider Secure Enclave key (P-256)
    │   ✗ AttestationBlob and signature NOT in public feed (F2)
    │     so binary_hash, encryption_public_key, sip_enabled,
    │     system_volume_hash all coordinator-asserted to outsiders
    ▼
AttestationBlob.encryptionPublicKey (X25519)
    │   ✗ not externally verifiable
    ▼
Provider in-process MLX engine

Coordinator (Intel TDX per paper, EigenCompute per diagram-test.pdf)
    ✗ no public quote endpoint (F3)
    ✗ no published image hash
    ✗ no transparency log for blessed binaries (F4)
```

**Two operators with different privileges.** This is the framework's first **two-tier hybrid TEE** case:

| Operator | Controls | Constrained by |
|---|---|---|
| **Eigen Labs** (coordinator) | Coordinator image, blessed-binary registry, model catalog, MDA verification logic, long-lived X25519 key | Whatever attestation EigenCloud TEE publishes for the `d-inference` app — externally invisible today |
| **Provider** (Mac owner) | macOS root, physical custody, network, hardware itself | Apple SE-bound key + SIP + Hardened Runtime + MDA cert chain (when enrolled) + binary-hash gate at coordinator |

**Two encryption hops.** Sender→coordinator (optional, sealed mode) → coordinator decrypts to route → coordinator→provider (always, NaCl Box). The coordinator's CVM is the trust boundary by construction. The marketing line "the operator cannot see your data" applies to the *provider operator* (the Mac owner), not to Eigen Labs in the coordinator CVM.

**Default-plaintext to coordinator.** Sealed mode requires the client to fetch `GET /v1/encryption-key` (returns `kid=833aec78e1c7c828`, `algorithm=x25519-nacl-box`) and POST as `Content-Type: application/eigeninference-sealed+json`. We confirmed the sealed-mode endpoint exists; we did not exercise a sealed POST. The official Python SDK path is not in this repo and was not audited; the README's example uses plaintext.

---

## Trust chain we re-verified

```
Apple Enterprise Attestation Root CA  (P-384, 2022-02-16 → 2047-02-20)
    │  Serial 42:c0:c2:bb:2c:72:7c:5c:5e:ab:f6:f1:a6:6f:1f:ac:5d:79:87:37
    │  DER SHA-256 ccf59ef8fcb3017d97f8b5fa6fa90e7a3f9283f76b55ac6cf6eda8b8b949f05b
    │  NOT published on apple.com/certificateauthority — embedded in
    │  coordinator/internal/attestation/mda.go:45-58.
    │  ECDSA-SHA384
    ▼
Apple Enterprise Attestation Sub CA 1  (P-384, 2022-02-16 → 2032-02-18)
    │  ECDSA-SHA384
    ▼
Per-device leaf cert  (P-384, ~3-month validity)
    │  Apple-vouched OIDs: serial, UDID, OS version, SepOS version, LLB version,
    │  SIP, SecureBoot ("Full Security"), Kext, freshness code (32B), EKU
    │  1.2.840.113635.100.4.24 (Apple Device Attestation)
    │
    │  THE BINDING JUMP: freshness OID 1.2.840.113635.100.8.11.1
    │  = sha256(base64-string of SE pubkey). The only cryptographic linkage
    │  between Apple's chain (P-384) and the SE pubkey (P-256).
    ▼
Provider Secure Enclave key  (P-256, in SE silicon, non-extractable)
    │  Signs: AttestationBlob (chip, model, SIP, SE, ARV, system volume hash,
    │  encryptionPublicKey, binaryHash, timestamp) + 5-min challenge response
    │  + (v0.3.11+) status_signature covering the canonical status payload
    │  ECDSA-P256-SHA256
    ▼
AttestationBlob.encryptionPublicKey  (X25519 / NaCl Box)
    │  Coordinator routes encrypted prompts to this key.
    ▼
Provider in-process MLX engine  (PyO3-embedded, no IPC, hardened, SIP-locked)
```

### What we re-ran

```bash
# 1. Pull live feed (no auth, no payment).
curl -sS https://api.darkbloom.dev/v1/providers/attestation > feed.json

# 2. Verify cert chain → Apple root (5/5 sampled providers).
for f in chain-*.pem; do openssl verify -CAfile apple-root.pem -untrusted "$f" "$f"; done
# All 5: OK

# 3. Cross-check feed serial/UDID/OSversion/SepOSversion against leaf-cert OIDs.
# 30/30 leaf OIDs match what the coordinator publishes.

# 4. MDA→SE binding check — sha256(se_public_key_b64) == OID 1.2.840.113635.100.8.11.1
# Across all mda_verified=true providers in the live feed:
#   30 with cert chain in feed
#   17 binding HOLDS  (57%)
#   13 binding FAILS  (43%)  ← cryptographic linkage broken

# 5. Pull v0.4.7 release bundle from R2.
curl -fsSL https://pub-3d1cb668259340eeb2276e1d375c846d.r2.dev/releases/v0.4.7/eigeninference-bundle-macos-arm64.tar.gz \
  | sha256sum
# f3eb0c1c1575b16ede6923a2c0801ca942b8fb274a1597b08c829daa177208e9  ← matches manifest

tar -xzf bundle.tar.gz; sha256sum bundle/bin/darkbloom
# 88848229e9e4a420e7ecbf0f3244810601d043e38f18d1f559ca68baf5a82b46  ← matches manifest

# 6. Confirm coordinator attestation is not exposed.
curl -sS -o /dev/null -w '%{http_code}\n' https://api.darkbloom.dev/v1/coordinator/attestation
# 404
curl -sS -o /dev/null -w '%{http_code}\n' https://api.darkbloom.dev/v1/releases
# 405  (POST-only registration; no public history)
```

### What it adds up to

- **MDA cert chain → Apple root:** verifiable from outside, holds for the entire live network.
- **Leaf-cert OIDs → feed claims:** verifiable from outside, 30/30 match.
- **MDA → SE pubkey binding:** verifiable from outside, holds for 17/30, **fails for 13/30**.
- **SE pubkey → AttestationBlob:** **not externally verifiable** — blob and signature not in the public feed.
- **5-min status reports → SE pubkey:** **not externally verifiable** — challenge-response sample not exposed; signature scope gap (`attestation.go:459-478`) is being closed in v0.3.11+ via opt-in `status_signature`.
- **Coordinator binary → source:** **not externally verifiable** — no quote, no published image hash.
- **Provider binary → source:** soft-verified — Mach-O arm64 signed by Team `SLDQ2GJ6TL` ("Eigen Labs, Inc."); panic paths reference `src/{coordinator,security,hypervisor,wallet,models}.rs` files that exist in this repo; mangled symbols include `darkbloom::coordinator::handle_attestation_challenge` and `darkbloom::security::check_sip_enabled`; embedded entitlements match `scripts/entitlements.plist`; canonical-status field list matches `attestation.BuildStatusCanonical`. Exact bytewise reproducibility blocked by Apple notarization.

---

## Stage Assessment

### Provider tier

By the framework's standard checklist, the provider tier earns **conditional Stage 1**:

| Check | Verdict | Evidence |
|---|---|---|
| TEE-equivalent attestation | PASS for `SEKeyBound=true` providers | Apple cert chain + freshness-OID binding + SE-signed blob |
| Hardware integrity | PASS | Apple's MDA leaf cert encodes serial, UDID, OS version, Secure Boot level, etc.; we extracted and cross-checked OIDs |
| Source provenance | PASS (soft) | GitHub Actions → notarized bundle → SHA registered → in-attestation `binaryHash` → routing gate. We re-hashed the v0.4.7 release artifact and matched the manifest |
| Image pinning | PASS at the routing layer | `binary_hash` in `AttestationBlob` is checked against the registered release set (`coordinator/internal/api/release_handlers.go`) |
| Reproducible build | PARTIAL | Source pinned (`Cargo.lock`, vllm-mlx fork, python-build-standalone version). Output is codesigned and Apple-notarized — bytewise reproduction requires Eigen's signing key. Structural ceiling for notarized macOS apps, not a darkbloom-specific gap |
| Secret isolation | PASS | X25519 encryption key is bound to the SE-attested identity (`AttestationBlob.encryptionPublicKey` is signed by the SE P-256 key); no operator-supplied secrets are on the prompt path |
| No operator-controllable prompt-path env | PASS | The provider is launched from a notarized binary by a launchd plist / Swift app; no external-config disk equivalent to dstack's `tinfoil-ext-config` |

The conditional in "conditional Stage 1": the binding gap (13/30 = 43%) means a fraction of today's live network does not actually meet the chain's strongest property. **Promotion to unconditional Stage 1 is one policy change away** — refuse `trust_level=hardware` when `SEKeyBound=false` (`coordinator/internal/api/provider.go:1487-1497`).

### Coordinator tier

**Stage 0.** The coordinator is the silent kingpin and the `apple.com/certificateauthority` page is the only public anchor.

| Check | Verdict | Evidence |
|---|---|---|
| TEE attestation surface | **FAIL** | `/v1/coordinator/attestation` returns 404. EigenCloud's TEE substrate is undocumented externally. `docs.eigencloud.xyz` returns 403 to anonymous fetch; `eigencloud.xyz` marketing page does not specify the substrate. |
| Image pinning | **FAIL (publicly)** | The coordinator is built from `coordinator/Dockerfile` and deployed via `ecloud compute app deploy d-inference`, but no image hash is published. Compare to Tinfoil's Sigstore-signed in-toto predicate at `atc.tinfoil.sh/attestation`. |
| Transparency log | **FAIL** | `GET /v1/releases` returns 405; only `/v1/releases/latest` is public. `GET /v1/admin/releases` returns the full set but is admin-only. `DELETE /v1/admin/releases` flips the routing gate without any external trace. The release registry lives only in PostgreSQL; no Sigstore log, no on-chain anchor. Old artifacts persist on R2 but only if you guess the version. |
| Source provenance | unknown | Build pipeline for the coordinator image is not exposed externally. The repo's `release.yml` covers the *provider* bundle; the coordinator deploy is `ecloud compute app deploy` with no public link to a GitHub commit hash. |
| Secret isolation | PARTIAL | Coordinator long-lived X25519 key derived from a BIP39 mnemonic via SLIP-0010 (`coordinator/internal/e2e/coordinator_key.go`). Mnemonic is in EigenCloud KMS per the deploy runbook. Whether the key is sealed to the TEE attestation is not externally verifiable. |
| Default plaintext path | n/a | Sealed mode is opt-in; default = plain HTTPS into the CVM. This is fine when the CVM is attested. **It is currently not attested from outside.** |

The combination of (a) coordinator default-decrypts plaintext, (b) coordinator chooses which provider receives the prompt, (c) coordinator chooses which binary hashes are blessed, (d) no external attestation of any of these → the coordinator is unilaterally trusted on the default code path.

---

## Findings

Detailed reproductions and code citations are in `ISSUES-DRAFT.md` (file-able as separate GitHub issues). Summary:

### F1 — `trust_level=hardware` is set even when MDA→SE binding fails (high)

**43% of hardware-trust providers in today's network have `SEKeyBound=false`.** The coordinator computes the binding internally (`provider.go:1487-1497`) but does not gate routing on it (`scheduler.go:370,650` only checks `trust_level >= MinTrustLevel`). The flag is exposed in the authenticated `/me` endpoint (`me_handlers.go:64,576`) but not in the public `/v1/providers/attestation` feed, so external auditors cannot detect the gap. Most likely cause: SE key was rotated (re-install/refresh) without re-issuing MDA — the existing leaf binds an earlier SE key.

The 13 providers we identified (provider_id prefix · MDA serial · chip):

```
46a8fd75  HH0K6TJY0J   Apple M4 Max
53d12f24  FXXNF6YCRF   Apple M4 Pro
17ca90f7  WV0NCDC2TX   Apple M3 Ultra
5c9de56e  GVC24LQHPW   Apple M3 Max
b1ea9dfa  LQFHXK6WW6   Apple M2 Max
5fce353e  XQ9LHC6PHF   Apple M4 Max
06896220  D59QMM9VJ7   Apple M3 Ultra
4d25a72c  X733VV9WHW   Apple M1 Max
0350c51f  TXT4N7GHM2   Apple M4 Pro
899ddd70  LXP4L3Y106   Apple M4 Pro
18378ddd  DL6CWHWL5C   Apple M4 Pro
0962a7c2  TX14PFPRFQ   Apple M1 Max
fc1df89f  JK6RKWCW6C   Apple M4 Max
```

**Suggested fix:** require `SEKeyBound==true` for `trust_level=hardware`, OR re-issue MDA when the SE key changes, OR at minimum publish `se_key_bound` in the public feed.

### F2 — Public attestation feed omits the SE-signed AttestationBlob (medium)

`/v1/providers/attestation` returns the SE pubkey, the cert chain, and a flat list of security-state claims. It does not return the SE-signed blob or its signature. `binary_hash`, `encryption_public_key`, and the SIP/SecureBoot/ARV claims are coordinator-asserted to outside auditors; nothing about the security state can be re-checked from outside.

**Suggested fix:** add `signed_attestation_b64`, `attestation_signature_b64`, `binary_hash`, `encryption_public_key` to the response. Verification logic already exists in `attestation.Verify`.

### F3 — No public coordinator attestation endpoint (medium → high depending on how the project frames its claims)

`api.darkbloom.dev` runs in EigenCloud TEE per `CLAUDE.md`. There is no externally fetchable TEE quote, no published coordinator image hash, no Sigstore-signed predicate tying the running image to a Git commit. Compare to Tinfoil's `atc.tinfoil.sh/attestation`, Phala dstack apps' 8090 endpoint, NEAR Private AI Verifier's on-chain anchors.

**Suggested fix:** publish `GET /v1/coordinator/attestation` returning the EigenCloud-provided TEE quote + image digest + a build-pipeline link. Even the minimum version (just publish the EigenCloud quote + a coordinator commit hash) closes the largest single gap.

### F4 — Release registry has no public history; silent adds are a CT-analogous MITM vector (medium → high under realistic insider/CI-compromise threat models)

The integrity-in side is recently hardened (PR #99 added constant-time release-key comparison, payload validation, and R2 bundle re-download + re-hash at registration). The transparency-out side is the gap.

`GET /v1/releases/latest` is the only public endpoint (`release_handlers.go:443-468`). Listing all releases requires admin auth (`release_handlers.go:470-482`). `DELETE /v1/admin/releases` (`:484-522`) deactivates a registered release and re-syncs the routing gate immediately. **`POST /v1/releases` adds a registered hash with no public log**. Both writes are externally invisible.

Silent **adds** are strictly more damaging than silent deletes — they are a structural MITM vector for any user routed to the new binary. The threat model is the same one Certificate Transparency was designed for: a trusted issuer (CA / coordinator-with-release-key) vouches for an entity (cert / binary) that the relying party cannot independently enumerate. The attack today:

1. Attacker obtains the scoped release-key (`release_handlers.go:69-74`) — insider, leaked GH Actions secret, or compromised `macos-latest` runner.
2. `POST /v1/releases` with a metadata payload pointing at the canonical R2 URL pattern. `verifyReleaseArtifact` re-downloads and re-hashes (`release_handlers.go:321-426`); this is good integrity-in, but it only confirms the artifact at the URL hashes to the supplied value — it says nothing about the artifact's source.
3. Attacker stands up a provider running the new binary. Once the new hash is registered, the provider's `AttestationBlob.binaryHash` matches a blessed value, the routing gate (`scheduler.go:370`) accepts it.
4. Coordinator routes some traffic to the attacker. Routing scores are operator-defined and externally invisible; a malicious coordinator could selectively target users.
5. Neither the official Python SDK (no verifier) nor the web verifier (does not check `binary_hash` — it's not in the public feed per F2) nor any external monitor (no public registration log) detects it.

The cohort handles this in two ways. **Tinfoil:** every CVM image attestation is a Sigstore in-toto predicate signed via GitHub OIDC pinned to `^https://github.com/tinfoilsh/confidential-model-router/.github/workflows/.*@refs/tags/.*`; attestations land in Rekor; an attacker without that GH OIDC identity can't sign predicates that pass policy. **NEAR:** on-chain dstack image-hash registry at `0x8fa1593f…` on Base; anyone watches the contract.

**Suggested fix (smallest):** route `GET /v1/releases` (read-only, no admin) so external monitors can poll and diff. Closes silent-delete detection; partially closes silent-add detection (you still need someone to be polling).
**Suggested fix (CT-equivalent):** Sigstore-sign each `POST /v1/releases` using GitHub OIDC from `release.yml`. Pin identity to `^https://github.com/Layr-Labs/d-inference/.github/workflows/release.yml@refs/tags/.*`. Publish the Rekor log entry alongside the registered hash. Cost-of-attack now requires forging a Sigstore predicate from outside the GH OIDC identity — same property CT gives the X.509 system.

### F5 — Both client-side paths are incomplete; the realistic Python path runs no verifier at all (medium → high)

There are two ways an end user reaches Darkbloom: the web console (browser) and the Python OpenAI-compatible API. Both client paths have devproofness gaps.

**(a) Web verifier — incomplete in the same shape as NEAR Private Chat.**
`console.darkbloom.dev` ships a real cryptographic verifier at `console-ui/src/lib/cert-verify.ts` (332 lines, pkijs + WebCrypto). The comment at line 5 is candid: *"This replaces the fake 'verify' button that just checked JSON fields."* It does five steps and returns "Genuine Apple device — certificate chain valid."

What it checks: parse chain → extract leaf OIDs (serial, UDID, OS, SepOS) → verify intermediate→leaf → verify root fingerprint → confirm.

What it does NOT check:
- **MDA→SE-key binding** (freshness OID `1.2.840.113635.100.8.11.1` vs `sha256(se_public_key_b64)`). For the 13/30 providers where the binding fails (F1), the verifier shows ✓✓✓✓✓ and the same green "Genuine Apple device" message.
- **SE-signed AttestationBlob.** Can't — the public feed doesn't ship the blob (F2). `binary_hash`, `encryption_public_key`, and the live security flags are displayed from coordinator-asserted JSON, not cryptographically re-checked.
- **Coordinator attestation.** Provider-tier only.

Structurally identical to NEAR Private Chat's "easy path is incomplete" pattern in `case-studies/near-private-chat/`: a published, real verifier that stops one step short of the load-bearing property and leaves the user with a green check that doesn't mean what it appears to mean.

Suggested fix: ~60 lines in `cert-verify.ts` — extract `OID_FRESHNESS = "1.2.840.113635.100.8.11.1"`, compute `sha256(se_public_key)` from the same response, compare. Fail step 5 with `"SE key not bound to this device — coordinator could be substituting another provider's key"` when it doesn't hold. Same fix shape as F1 (server-side gate); applying both makes the user-visible verdict honest.

**(b) Python SDK — referenced in docs, not actually shipped.**
`docs/ARCHITECTURE.md:81-82` has:

```python
from eigeninference import EigenInference
client = EigenInference(base_url="https://coordinator.darkbloom.io", api_key="eigeninference-...")
```

This package does not exist publicly. We checked:
- PyPI: `eigeninference`, `darkbloom`, `eigen-inference`, `d-inference`, `eigenlabs-inference` — all 404 on `/pypi/{name}/json` and `/simple/{name}/`.
- npm: `eigeninference`, `darkbloom`, `@eigenlabs/inference`, `@darkbloom/sdk`, `@darkbloom/client` — all 404.
- GitHub: `Layr-Labs` org has no Python SDK repo. Same project also lives at `darkbloomdev/darkbloom` (`fork=false`, identical structure — likely a brand-rename in progress); no SDK there either. No `sdk/`, `python/`, `clients/` directory in either tree.

The realistic Python path is what the `README.md` actually shows:

```python
from openai import OpenAI
client = OpenAI(base_url="https://api.darkbloom.dev/v1", api_key="eigeninference-...")
```

The bare OpenAI client has no concept of MDA, SE keys, or binary hashes. **Zero attestation enforcement on this code path.** A user paying for the TEE-equivalent privacy claim ends up with the same posture as any HTTPS API. This is the dominant practical risk that Tinfoil's report flags ("use the verifier or you've got nothing"); Darkbloom is structurally worse than Tinfoil here because Tinfoil ships `tinfoil-go` / `tinfoil-py` on PyPI and Darkbloom ships nothing.

Suggested fix: ship a thin `eigeninference` (or `darkbloom`) PyPI package that wraps the OpenAI client and runs the cert-chain + binding check (per F1) before each request — refusing to send if the chosen provider's binding fails. This is `cert-verify.ts` ported to Python, ~200 lines. Or remove the `from eigeninference` example from `docs/ARCHITECTURE.md` so users aren't pointed at a package that doesn't exist.

### F6 — Three project docs disagree about who sees plaintext (docs nit)

(plus, per F5b: `docs/ARCHITECTURE.md:81-82` references an `eigeninference` Python package that is not on PyPI, GitHub, or anywhere else we could find. Either ship the package or remove the example.)

| Source | Says |
|---|---|
| `README.md` §How It Works | "The coordinator encrypts each request with the provider's X25519 public key before forwarding it." (correct: coordinator sees plaintext) |
| `docs/ARCHITECTURE.md` §Coordinator | "Consumers send plain text over HTTPS; the Confidential VM is the trust boundary." (correct) |
| `CLAUDE.md` §Key Design Decisions | "Coordinator never sees plaintext prompts. Decryption only inside the hardened provider process." (**incorrect** — sender encryption is opt-in) |

Also: `docs/ARCHITECTURE.md` describes prod as "GCP Confidential VM (AMD SEV-SNP)" but `CLAUDE.md` and the deploy runbook now say prod runs on EigenCloud (TEE). `~15-line docs PR.

---

## Concordance with the research paper

`papers/dginf-private-inference.pdf` (Naik, Eigen Labs, April 2026) is unusually rigorous for a project at this stage — formal threat model (Definition 2), explicit assumptions (Definition 3), a security-property game (Definition 4), Theorem 1 (SIP runtime immutability) with a clean proof, and Table 1's complete software-attack-surface enumeration. The paper is also the architectural ground truth that should match the deployed system. We compared each finding against the paper's text. Three of the five gaps are findable from the paper alone (a careful reader would not need code access to spot them); the others require code or live-API access.

| Finding | In the paper as written? | What a careful reader would notice |
|---|---|---|
| **F1** — MDA→SE binding not enforced for `trust_level=hardware` | **Yes — as architectural inconsistency.** §17 conclusion (line 985-988) lists *"MDA nonce-based SE key binding"* as one of five layers that "provides defense-in-depth where each layer independently verifies properties that the others cannot." But Definition 5 *"Verified Provider"* (§5.4 line 358-374) item 5 only requires *"Apple MDA certificate chain is valid and serial number matches self-reported attestation"* — no binding requirement. So the paper's conclusion claims a property (binding) that its operational verification definition doesn't enforce. | Reader asks: *"the conclusion lists 'MDA nonce-based SE key binding' as a defense layer — where in §7 is the freshness-OID = sha256(SE pubkey) check formalized? Does Definition 5 include it?"* The answer is: §7.3.2 lists freshness code as an OID field but doesn't describe its role in binding to the SE key, and Definition 5 doesn't mention the binding at all. **Paper-findable.** |
| **F2** — SE-signed AttestationBlob not in public feed | **No — implementation question.** §7.3.3 (line 600) says *"the complete certificate chain is stored and exposed via a public API endpoint, enabling consumers to independently verify each provider against Apple's publicly available root CA certificate."* Paper claim is true for the *cert chain*, but doesn't enumerate which other fields are or aren't exposed. | Not visible from paper alone. Requires a `curl /v1/providers/attestation` to discover that the SE-signed blob and signature are not among the exposed fields. |
| **F3** — No external coordinator attestation surface | **Yes — by omission.** §4 architecture (Figure 1) shows the coordinator inside an Intel TDX TEE labeled *"Container Image Attested"* but no section describes how outside parties verify the coordinator's image. Compare to §7.3.3 explicitly describing the public-API endpoint for provider chains. | Reader asks: *"§7 covers provider attestation in detail. Where's the parallel section for the coordinator? What's the equivalent of `/v1/providers/attestation` for the TDX VM?"* No answer in the paper. **Paper-findable as an omission.** |
| **F4** — Release registry has no public history; CT-analogous silent-add vector | **Yes — by omission.** No paper section discusses how blessed binary hashes are recorded over time, audited, or anchored. Definition 5 item 2 says *"Binary hash matches a known blessed version"* but the paper doesn't describe how the "blessed" set is constructed, modified, or made auditable. §17 Future Work doesn't mention transparency. | Reader asks: *"the blessed-binary set determines which providers can serve. How does a consumer know the set hasn't grown to include a backdoored binary? Where's the audit log?"* No answer. **Paper-findable as an omission.** |
| **F5a** — Web verifier stops at "genuine Apple device" | **Mostly no — implementation question.** §7.3.3 says *"consumers can independently verify each provider"* but doesn't describe what the SDK or web UI actually checks. | Reader can't verify completeness from paper alone — would need to read `cert-verify.ts` or use the live web verifier and inspect what it does. |
| **F5b** — Python SDK referenced in docs but absent from PyPI / GitHub | **No — out of paper scope.** The paper doesn't claim a Python SDK ships; that's only in `docs/ARCHITECTURE.md`. | Not paper-findable. Requires PyPI / GitHub search. |
| **(plus)** Pre-#99 binary-swap gap (registration→challenge consistency) | **Yes — by omission.** §7.1.2 lists the registration-time check (*"Step 6: Verify binaryHash is in the set of blessed versions"*); §7.4 lists the challenge-response fields including binary_hash but does not state that the challenge-time hash must equal the registration-time hash. The chain isn't closed in the text. | Reader asks: *"a provider attests binary A at registration, then at 5-min challenge reports binary B. Both are blessed. What stops the swap?"* §7.4 doesn't answer. **Paper-findable as an omission.** |
| **(plus)** Pre-#99 challenge-response signature scope gap | **Yes — explicitly described.** §7.4 line 770ish: *"σ = SignSE(n∥t∥pk) where pk is the registered public key"* and then lists the response tuple including sip_enabled, etc. The paper documents the narrow signature scope without acknowledging that the OS-state fields are outside it. | Reader asks: *"σ covers (n,t,pk) only. The coordinator then trusts sip_enabled. What stops a compromised provider with a valid SE key from echoing a correct σ and lying about sip_enabled?"* The paper doesn't address this; the code (`attestation.go:459-478`) acknowledges it as a TODO. **Paper-findable as a security argument hole.** |

So out of seven distinct gaps, **five are paper-findable** (F1, F3, F4, and the two pre-#99 fixes) and two require code or live-API access (F2, F5b; F5a is partly paper-adjacent). The paper is candid in its assumption set and threat model but its operational definitions (Definition 5) and protocol specifications (§7.4) leave several gaps that careful reading would expose. A reviewer with the paper in hand and no access to the code could write half of this audit by asking "is the architectural claim X enforced by the operational requirement Y, and if so where?"

This is, on balance, **a well-written research paper with audit-discoverable gaps in its operational claims**. The kind of paper where peer review at a security venue would ask exactly the same questions our audit asked.

## What we did NOT verify

- **Theorem 1 (paper §?, SIP runtime immutability).** The paper's formal argument that SIP cannot be disabled without a reboot that terminates the inference process. The assumption set is the load-bearing part. Out of scope for this audit; flagged for follow-up.
- **End-to-end binary-hash gate exercise.** We confirmed both the registration path and the verification call site exist; we did not run a tampered binary against a live coordinator to confirm the gate fires.
- **Hypervisor.framework guest with Stage 2 page tables.** `provider/src/hypervisor.rs` exists; the entitlement is in `scripts/entitlements.plist`; the binary's panic paths reference it. We did not audit how many live providers run inside the guest vs. on bare metal.
- **EigenCloud TEE substrate.** No public surface; out of scope for a no-payment audit.
- **Sender→coordinator sealed mode.** We confirmed `GET /v1/encryption-key` works (`kid=833aec78e1c7c828`, `x25519-nacl-box`); we did not exercise a sealed POST end-to-end.
- **Official Python SDK behavior.** Determined that no public Python SDK exists (F5b) — this means the realistic Python path runs zero attestation verification. The `eigeninference` PyPI/GitHub/npm hunt across plausible names returned 404 everywhere; the README's actual install instructions point at the bare OpenAI client.

---

## Reproducing this audit

```bash
git clone https://github.com/Layr-Labs/d-inference.git /tmp/d-inference
cd path/to/case-studies/darkbloom-d-inference

# 1. Pull live feed (~100KB, no auth).
curl -sS https://api.darkbloom.dev/v1/providers/attestation > /tmp/feed.json

# 2. Extract the embedded Apple root from the coordinator source.
sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' \
  /tmp/d-inference/coordinator/internal/attestation/mda.go \
  | sed 's/^[[:space:]]*//' > verify/apple-root.pem

# 3. Run the binding check (verify/binding-check.py).
python3 verify/binding-check.py /tmp/feed.json
# Today: holds 17, fails 13

# 4. Pull and verify the v0.4.7 release.
curl -sS https://api.darkbloom.dev/v1/releases/latest | jq .
curl -fsSL <url-from-step-4> -o bundle.tar.gz
sha256sum bundle.tar.gz                 # should match bundle_hash
tar -xzf bundle.tar.gz -C /tmp/bundle
sha256sum /tmp/bundle/bin/darkbloom     # should match binary_hash

# 5. Confirm the coordinator publishes nothing about itself.
curl -sS -o /dev/null -w '%{http_code}\n' https://api.darkbloom.dev/v1/coordinator/attestation
curl -sS -o /dev/null -w '%{http_code}\n' https://api.darkbloom.dev/v1/releases
```

Round-trip cost: ~30 seconds of API calls + a Python script. No payment, no API key, no Mac required for steps 1–3 and 5; step 4 only needs a Mac if you want to verify the codesign chain.

---

## Comparison to the rest of this cohort

| Case study | Hardware substrate | Source provenance | Image / binary pinning | External coord attestation | Notable failure mode | Stage |
|---|---|---|---|:---:|---|:---:|
| dstack apps (general) | Intel TDX + dstack KMS | Variable | `compose_hash` ✓ | ✓ via 8090 endpoint | env-var prompt-path | varies |
| oauth3-burnt | Intel TDX (Phala prod5) | Nix flake (partial) | `${DOCKER_IMAGE}` operator-set | ✓ but Pha KMS opaque | DeriveKey imported, never called | 0 |
| tinfoil-confidential-inference | AMD SEV-SNP + dm-verity weights | Sigstore-signed in-toto, public | `@sha256:` digest pin | ✓ at `atc.tinfoil.sh/attestation` | router-only operator slots, off prompt path | 1 (conditional) |
| near-ai-private-inference | Intel TDX + on-chain anchors (Base) | Reproducible builds | DstackKms `0x8fa1593f…` registry | ✓ via dstack | unenforced compose_hash gate | 0→1 in progress |
| **darkbloom-d-inference** | **Apple SE + Hardened Runtime + SIP + EigenCloud TEE** | **GitHub Actions → notarized → SHA registered ✓ (provider only)** | **binaryHash via `POST /v1/releases` ✓ (registry not public-readable)** | **✗** | **MDA→SE binding gap (43% live) + opaque coordinator** | **0** |

Provider-side build is on par with `near-ai-private-inference`. Coordinator-side externalization is meaningfully behind the rest of the CVM-backed cohort — none of the others omit the coordinator's TEE quote.

---

## Recommendation

The route from Stage 0 to Stage 1 is short and concrete:

1. **Refuse `trust_level=hardware` when `SEKeyBound=false`** (5-line change in `provider.go`). Demotes 13 providers today; the fleet recovers as they re-attest.
2. **Publish `signed_attestation_b64` + `attestation_signature_b64` + `binary_hash` + `encryption_public_key` in the public feed** (4 fields added to the response struct in `provider.go:1540-1626`).
3. **Publish a coordinator TEE quote** at `GET /v1/coordinator/attestation` — even a minimum version (EigenCloud-provided quote + coordinator commit hash) closes the largest gap.
4. **Route `GET /v1/releases`** to return all active releases as JSON. Bigger lift: Sigstore-sign each `POST /v1/releases` using the GH OIDC identity from `release.yml`.

These four changes — none of them protocol-level, all of them small — would land darkbloom at the same external-verifiability posture as Tinfoil. The build pipeline and on-device hardening are already there; the missing piece is exposing the proofs.

The repo's "research preview" framing is honest about the current maturity. The findings above are exactly the kind of thing an audit produces and a small set of PRs would close.
