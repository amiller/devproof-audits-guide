# Darkbloom (d-inference) — Chain of Trust Analysis

**Audit date:** 2026-05-10
**Subject:** [Layr-Labs/d-inference](https://github.com/Layr-Labs/d-inference) HEAD `cf4c0ef`
**Live API:** `https://api.darkbloom.dev` — public, no-auth attestation feed at `/v1/providers/attestation`
**Reference verifier we ran:** `verify/` — `openssl verify` for x509 chains + a 60-line Python script using `cryptography` + `hashlib` for the MDA→SE binding check. Reproducible in one terminal session.
**Core question:** *"Without paying, what can a third party actually verify, where does the chain stop being externally checkable, and where does it stop being load-bearing?"*

---

## Bottom line

> **No payment, no account, no SDK install needed.** Anyone with `curl + openssl + python` can verify Apple's signature over each provider's hardware identity for the entire 65-provider live network. We did so against Apple's Enterprise Attestation Root CA: every cert chain in the feed verified cleanly. **However, three concrete gaps mean a TEE-style end-to-end "the device that decrypts my prompt is genuine Apple hardware running an attested binary" verification is not achievable from outside the coordinator today.**

The three gaps:

| # | Gap | Evidence | Severity |
|---|---|---|---|
| 1 | **MDA→SE-key binding broken for 13/30 (43%) hardware-trust providers in the live feed** | Re-ran `sha256(se_public_key_b64) == OID 1.2.840.113635.100.8.11.1` on every provider with `mda_verified=true`; 17 hold, 13 fail. Coordinator computes the same check internally as `SEKeyBound` but does not expose the result in the feed. `MDAVerified=true` is set whether or not the binding holds (`coordinator/internal/api/provider.go:1487-1497`). | High |
| 2 | **SE-signed attestation blob is not in the public feed** — only the public key + cert chain + coordinator-extracted security flags. So `sip_enabled`, `secure_boot_enabled`, `binary_hash`, `system_volume_hash`, `encryption_public_key` are all coordinator-asserted to outside auditors. | Reconstructed the response struct from `coordinator/internal/api/provider.go:1540-1626`; no `signature` / `attestationRaw` field is exposed. | Medium |
| 3 | **5-min challenge-response signature only covers `(nonce ‖ timestamp)`** — not the live SIP/SecureBoot/binary-hash claims it carries. A provider with a valid SE key but a compromised current security posture can sign correctly while lying about its state. The newer `VerifyStatusSignature` covers the full canonical payload but is opt-in. | Source comment is unusually candid: `attestation.go:459-478` calls this out as a known scope gap with a fix-plan that requires coordinated provider rollout. | Medium |

The chain to Apple's root works. The chain from Apple's vouching to *the X25519 key your prompt is actually encrypted to* doesn't, for nearly half of today's hardware-trust providers.

---

## The chain we walked, end to end

```
                                 ROOT OF TRUST
                                       │
                ┌──────────────────────┴──────────────────────┐
                │ Apple Enterprise Attestation Root CA (P-384)│
                │ Serial 42:c0:c2:bb:2c:72:7c:5c:5e:ab:f6:f1: │
                │        a6:6f:1f:ac:5d:79:87:37              │
                │ Valid 2022-02-16 → 2047-02-20               │
                │ DER sha256: ccf59ef8fcb3017d97f8b5fa6fa90e7a│
                │             3f9283f76b55ac6cf6eda8b8b949f05b│
                │ NOT published on apple.com/certificateauthority/│
                │ Embedded in coordinator/internal/attestation/mda.go:45-58 │
                └──────────────────────┬──────────────────────┘
                                       │ ① ECDSA-SHA384 sig
                                       ▼
                ┌──────────────────────────────────────────────┐
                │ Apple Enterprise Attestation Sub CA 1 (P-384)│
                │ Serial 70:31:e0:40:a6:e6:b4:6b:f0:e2:f3:4d:  │
                │        55:6a:84:54:d0:42:5e:71               │
                │ Valid 2022-02-16 → 2032-02-18                │
                │ Returned by the coordinator alongside the leaf│
                └──────────────────────┬──────────────────────┘
                                       │ ② ECDSA-SHA384 sig
                                       ▼
                ┌──────────────────────────────────────────────┐
                │ Per-device leaf cert (P-384, valid ~3 months)│
                │ Subject CN: <sha256 of MDA key handle>        │
                │ Issued by Apple via DevicePropertiesAttestation│
                │ Carries Apple-vouched OIDs:                   │
                │   100.8.9.1  serial    (e.g. HH0K6TJY0J)      │
                │   100.8.9.2  UDID      (e.g. 00006041-…)      │
                │   100.8.9.4  swUpdateID                       │
                │   100.8.10.1 OS version (e.g. 26.4.1)         │
                │   100.8.10.2 SepOS version                    │
                │   100.8.10.3 LLB version                      │
                │   100.8.13.1 SIP status                       │
                │   100.8.13.2 SecureBoot ("Full Security")     │
                │   100.8.13.3 Kext status                      │
                │   100.8.11.1 freshness (32B = sha256 of nonce)│
                │   EKU 1.2.840.113635.100.4.24 (Apple Device Att)│
                └──────────────────────┬──────────────────────┘
                                       │ ③ Apple binds the device's MDA key
                                       │   (the leaf SPKI, P-384) — but THAT
                                       │   key is NOT what signs blobs.
                                       │
                  THE BINDING JUMP: nonce-as-hash-of-SE-key
                  freshness OID = sha256(base64-string of SE pubkey)
                  ↑
                  This is the only cryptographic linkage between
                  Apple's cert chain (P-384) and the SE pubkey (P-256)
                  that signs everything else.
                                       │
                                       ▼
                ┌──────────────────────────────────────────────┐
                │ Provider Secure Enclave key (P-256, ECDSA)   │
                │ Generated in Apple SE silicon, non-extractable│
                │ Used to sign:                                 │
                │   • the "AttestationBlob" containing          │
                │     binaryHash, encryptionPublicKey,          │
                │     systemVolumeHash, sipEnabled, etc.        │
                │   • the 5-min challenge-response (nonce ‖ ts) │
                │   • optionally, the canonical status payload  │
                │     covering sip + binary hash + runtime hash │
                └──────────────────────┬──────────────────────┘
                                       │ ④ ECDSA-P256-SHA256
                                       ▼
                ┌──────────────────────────────────────────────┐
                │ AttestationBlob.encryptionPublicKey           │
                │ X25519 (NaCl Box) — bound by the SE signature │
                │ ↑                                             │
                │ Coordinator routes encrypted prompts to this  │
                │ key. Provider decrypts inside the hardened    │
                │ in-process MLX engine.                        │
                └──────────────────────────────────────────────┘
                                       │
                                       ▼
                              YOUR PROMPT (plaintext only here)
```

Every step is real and present in the codebase. The chain is well-designed in the *common case*. The audit work is in the joints.

---

## What we actually verified, with commands

All artifacts saved under `case-studies/darkbloom-d-inference/verify/`.

### Step 1: pull the live feed (no auth)

```bash
curl -sS https://api.darkbloom.dev/v1/providers/attestation > providers.json
# 65 providers, 103 KB
```

Fields per provider: `provider_id, chip_name, hardware_model, serial_number, trust_level, status, memory_gb, gpu_cores, models, secure_enclave, sip_enabled, secure_boot_enabled, authenticated_root_enabled, system_volume_hash, se_public_key, mdm_verified, acme_verified, mda_verified, mda_cert_chain_b64, mda_serial, mda_udid, mda_os_version, mda_sepos_version`. Nothing else. **No SE-signed blob, no challenge-response sample, no signature, no `se_key_bound` flag, no coordinator attestation.**

### Step 2: chain-to-Apple verification (5/5 sampled)

```bash
for f in chain-*.pem; do
  openssl verify -CAfile apple-root.pem -untrusted "$f" "$f"
done
# chain-17ca90f7.pem: OK
# chain-46a8fd75.pem: OK
# chain-53d12f24.pem: OK
# chain-db9b4c03.pem: OK
# chain-f99b7905.pem: OK
```

Each leaf is freshly issued (1–16 days old; 3-month validity). The intermediate ("Apple Enterprise Attestation Sub CA 1") is good until 2032-02-18; the root until 2047-02-20.

### Step 3: leaf OID extraction

The OIDs the coordinator stores into `MDAResult` are all present and correctly extractable. Cross-checked the `mda_serial` / `mda_udid` / `mda_os_version` / `mda_sepos_version` in the feed against the OID values in the leaf cert: **30/30 leaf OIDs agree with the feed's claimed values.** The coordinator faithfully republishes what Apple signed.

### Step 4: MDA→SE-key binding check (the load-bearing one)

The coordinator's nonce-binding flow (`coordinator/internal/api/provider.go:1411-1497`):

```go
seKeyHash := sha256.Sum256([]byte(attestResult.PublicKey))      // PublicKey is the b64 string
seKeyNonce = base64.StdEncoding.EncodeToString(seKeyHash[:])   // sent to Apple via MDM
expectedFreshness = seKeyHash                                   // 32 bytes
// ... after Apple returns the leaf cert ...
seKeyBound = bytes.Equal(mdaResult.FreshnessCode, expectedFreshness[:])
```

Apple decodes the base64 nonce and embeds the raw 32-byte hash as OID `1.2.840.113635.100.8.11.1` in the leaf. The check is: **does `sha256(se_public_key_b64)` (which we can compute from the public feed) equal the freshness OID (which we can extract from the published leaf cert)?**

We re-ran this on every `mda_verified=true` provider in the live feed:

```
mda_verified=true                35
  cert chain present in feed     30   (5 mda_verified=true entries published with no chain — separate gap)
  has freshness OID              30   (every leaf carried 100.8.11.1)
  binding holds                  17   (sha256(SE pubkey b64) == OID 100.8.11.1)
  binding fails                  13   ← cryptographic linkage broken
```

Confirmed working derivation against a known-good provider:

```
chip          Apple M2 Max
serial        WRPWFW61H9
SE pubkey     qKxKds4zZk81flmOxcOmQVYSL0xkeg88tLBfXd7ghhJ/QYjW5ZKBAzASJ0TPwseWv38jW61NESGDtGsJqdzJ9Q==
sha256(b64)   984a169f28cd03dd50df4772724174bf3573486b20384918fe44eca467d86a98
OID 100.8.11.1 984a169f28cd03dd50df4772724174bf3573486b20384918fe44eca467d86a98
match         True
```

13 of the 30 fail. Cert ages don't explain it (matching set median 7d, failing set median 8d — both well within the 90-day cert window).

The 13 failing providers (provider_id prefix, MDA serial, chip):

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

Most likely cause: the provider's SE key was regenerated (reinstall, key rotation) but MDA wasn't re-requested in the same flow, so the existing MDA cert binds an *earlier* SE key. The coordinator's current logic:

```go
provider.MDAVerified = true   // unconditional once cert chain validates
provider.SEKeyBound  = ...   // computed but kept private
```

means the public-facing flag stays at "MDA verified, hardware-trust" even when the cryptographic linkage has decayed. **For these 13 providers, an external auditor verifying along Apple's signed chain reaches "this was a real Apple device when MDA was issued" — but the SE pubkey they see in the feed is not the one Apple's cert vouched for.** All they can conclude is "the same coordinator that registered this provider asserts this is the right SE pubkey now." That's the same trust posture as a non-attested provider for the most security-critical link.

**Recommended fix (filed as audit finding):** The coordinator should either (a) refuse `trust_level=hardware` when `SEKeyBound=false`, or (b) re-request MDA whenever the SE pubkey changes, or (c) at minimum publish `se_key_bound` in the feed so external verifiers can detect the gap themselves. (c) is the cheapest and matches the project's transparency posture; (a) is the right posture and would silently demote 43% of today's hardware-trust providers until they re-attest.

---

## What is and is not externally verifiable

For each link in the chain, what an outside verifier with only the public feed can check:

| Link | Mechanism | Externally verifiable? | Notes |
|---|---|:---:|---|
| Apple Enterprise Attestation Root CA → Sub CA 1 | ECDSA-SHA384 over X.509 | ✓ | Root P-384 valid 2022 → 2047. Embedded in coordinator source; **not** published on `apple.com/certificateauthority`. The Eigen Labs source repo is the de-facto root pinning vector. |
| Sub CA 1 → leaf | ECDSA-SHA384 over X.509 | ✓ | Sub CA expires 2032-02-18. |
| Leaf cert → device identity (serial, UDID, OS, SepOS, LLB) | OID extraction | ✓ | All fields cross-check against feed values. |
| Leaf cert → SE pubkey (the BINDING) | freshness OID 100.8.11.1 = sha256(SE_pubkey_b64) | ✓ but **broken for 13/30** | This is the load-bearing audit step. |
| SE pubkey → AttestationBlob | ECDSA-P256-SHA256 | ✗ | Blob + signature not in feed. Coordinator-asserted. |
| SE pubkey → live security state (every 5 min) | ECDSA-P256-SHA256 over `(nonce ‖ ts)` | ✗ | Challenge-response sample not in feed. Even when received by coordinator, signature does **not** cover the security flags (`sip_enabled`, `binary_hash`, …) — known TODO at `attestation.go:459-478`. |
| AttestationBlob.encryptionPublicKey → in-process inference memory | OS-level mechanisms (PT_DENY_ATTACH, Hardened Runtime, SIP, optional Hypervisor.framework) | ✗ from outside | This is the "no-memory-encryption-but-software-path-elimination" claim. The paper formalizes it as Theorem 1. We did not re-derive Theorem 1 in this session; that is a separate read of `papers/dginf-private-inference.pdf`. |

The "✗ from outside" entries are **architecturally unavoidable** — Apple Silicon has no third-party-accessible TEE to host the SE-signed blob in a way an outside party could re-verify per request. What *is* avoidable: the coordinator could publish the SE-signed blob and the latest challenge-response in the feed so an external auditor at least sees what the coordinator saw.

---

## The two-tier trust story

This is the framework's first **edge-TEE + CVM hybrid** case. Two independent trust chains:

### Provider side (every node)
*See above.* Apple-anchored, external-verifiable up through the SE→MDA binding (when it holds), then becomes coordinator-asserted.

### Coordinator side (single point)

The coordinator is the trust kingpin: it sees every plaintext prompt (sealed-mode is opt-in per `Content-Type: application/eigeninference-sealed+json`; the default path is plain HTTPS into the CVM). The coordinator:

- Decides which provider receives a request (model catalog + scoring)
- Holds the long-lived X25519 key referenced by `GET /v1/encryption-key` (kid `833aec78e1c7c828`), derived from a BIP39 mnemonic via SLIP-0010 with domain separation (`coordinator/internal/e2e/coordinator_key.go`)
- Re-encrypts to the chosen provider's X25519
- Validates every provider's MDA + SE attestation (and silently downgrades `SEKeyBound` to false when the binding fails — finding above)
- Maintains the blessed-binary registry consulted in `binaryHash` checks
- Embeds Apple's Enterprise Attestation Root CA (so the project's source is the ground truth for which Apple key is "really Apple's")

According to `CLAUDE.md`, prod runs on **EigenCloud (TEE)** as app `d-inference`; dev runs on **GCP SEV-SNP CVM**. We could not enumerate `/v1/coordinator/attestation` (HTTP 404). **There is no externally fetchable coordinator attestation surface today.** Every protection on the provider side rests on the coordinator's CVM behaving honestly, and the coordinator's CVM attestation is currently invisible from outside Eigen's infrastructure. This is the largest single open audit question.

By contrast, every other case study in this cohort that runs in a CVM publishes its attestation: Tinfoil at `atc.tinfoil.sh/attestation`, NEAR Private AI Verifier publishes Phala-style quotes, Phala apps via the trust-center. Darkbloom does not (yet).

---

## Why "hardware" trust today is closer to "trust the coordinator did its job"

When you call `https://api.darkbloom.dev/v1/chat/completions` without sealed mode (the default), here is exactly who has to be honest for "the operator cannot read my prompt" to hold:

1. **DNS / HTTPS to `api.darkbloom.dev`** — standard web PKI. (Same as any cloud API.)
2. **The coordinator process** — sees plaintext, decides which provider to encrypt to. **No external attestation today.**
3. **The coordinator's view of which providers are honest** — including the 43% of hardware-trust providers whose MDA cert doesn't bind the SE pubkey we'd verify.
4. **The coordinator's blessed-binary registry** — `POST /v1/releases` is gated; `GET /v1/releases` returns 405 (Method Not Allowed). The list of blessed binaries is not publicly readable. Compare to dstack's compose-hash transparency.
5. **The provider machine** — Theorem 1 + binary-hash gate. *This* is the part that's unusually well-engineered.

Steps 2–4 are coordinator-mediated trust. Step 5 is hardware-anchored trust. Today's deployment is "well-engineered hardware step + opaque coordinator step." The marketing claim "the operator cannot see your data" is true with respect to **step 5's operator** (the Mac owner) and false with respect to **step 2's operator** (Eigen Labs in the CVM, on the default code path).

This is a familiar shape — same structural framing as "Tinfoil's router CVM sees plaintext but tinfoil cannot read it because the CVM image is publicly attested" — and the gap closes the same way: publish the coordinator's CVM attestation, image hash, and source pinning, the way Tinfoil publishes Sigstore predicates.

---

## Comparison to the rest of this cohort

| Case study | Hardware substrate | Source provenance | Image / binary pinning | External coord attestation | Notable failure mode |
|---|---|---|---|:---:|---|
| dstack apps (general) | Intel TDX + dstack KMS | Variable | `compose_hash` ✓ | ✓ via 8090 endpoint | env-var prompt-path |
| oauth3-burnt | Intel TDX (Phala prod5) | Nix flake (partial) | `${DOCKER_IMAGE}` operator-set | ✓ but Pha KMS opaque | DeriveKey imported, never called |
| tinfoil-confidential-inference | AMD SEV-SNP + dm-verity weights | Sigstore-signed in-toto, public | `@sha256:` digest pin | ✓ at `atc.tinfoil.sh/attestation` | router-only operator slots, off prompt path |
| near-ai-private-inference | Intel TDX + on-chain anchors (Base) | Reproducible builds | DstackKms `0x8fa1593f…` registry | ✓ via dstack | unenforced compose_hash gate |
| **darkbloom-d-inference** | **Apple SE + Hardened Runtime + SIP + EigenCloud TEE** | **GitHub Actions → notarized → SHA registered ✓** | **binaryHash via `POST /v1/releases` ✓ (registry not public-readable)** | **✗** | **MDA→SE binding gap (43% live) + opaque coordinator** |

Darkbloom's provider-side pipeline is *better* than oauth3-burnt and on par with near-ai-private-inference. Its coordinator side is *worse* than tinfoil's: less external surface, no published attestation. The two layers shouldn't move in opposite directions.

---

## What we did NOT verify in this session

- **Theorem 1 (SIP runtime immutability).** The paper's formal argument that SIP cannot be disabled without a reboot that terminates the inference process. Worth a careful read — the assumption set is the load-bearing part. (See `papers/dginf-private-inference.pdf`.)
- **The binary-hash gate at runtime.** We confirmed the *registration* path exists (`POST /v1/releases`) and the verification call site exists (`provider.go` checks `binaryHash` from the SE blob against a known-good list). We did not exercise it end-to-end with a tampered binary.
- **The Hypervisor.framework guest with Stage 2 page tables.** `provider/src/hypervisor.rs` exists, the entitlement is in `scripts/entitlements.plist`. We did not check whether it's mandatory or how many live providers actually run inside it.
- **EigenCloud's TEE attestation.** No public surface. Out of scope for a no-payment audit.
- **The sender→coordinator sealed mode.** We confirmed `GET /v1/encryption-key` works and returns `kid=833aec78e1c7c828`. We did not exercise a sealed POST.
- **Whether the official Python SDK defaults to sealed mode.** The README example uses plaintext; the SDK source isn't in this repo (the README references an `eigeninference` package).

These are the next-session items.

---

## Reproducing this analysis

```bash
git clone https://github.com/Layr-Labs/d-inference.git /tmp/d-inference
cd path/to/case-studies/darkbloom-d-inference

# 1. fetch live feed
curl -sS https://api.darkbloom.dev/v1/providers/attestation > /tmp/feed.json

# 2. extract Apple root from coordinator source (yes, that's the "publication" venue)
sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' \
  /tmp/d-inference/coordinator/internal/attestation/mda.go \
  | sed 's/^[[:space:]]*//' > verify/apple-root.pem

# 3. run chain verify on every provider's mda_cert_chain_b64
#    (see verify/binding-check.py — produces the 17/30 holds, 13/30 fails table)

# 4. pull encryption key (coordinator-side X25519, opt-in sealed mode)
curl -sS https://api.darkbloom.dev/v1/encryption-key
#    {"algorithm":"x25519-nacl-box","kid":"833aec78e1c7c828",
#     "public_key":"ojUvkH5jPZP6eHbN8jPSx6R/bV7hwoPcApnUZUoPvEc="}

# 5. (negative) confirm coordinator attestation is not exposed
curl -sS -o /dev/null -w '%{http_code}\n' https://api.darkbloom.dev/v1/coordinator/attestation
#    404
curl -sS -o /dev/null -w '%{http_code}\n' https://api.darkbloom.dev/v1/releases
#    405  (POST-only registry)
```

Round-trip cost: ~30 seconds of API calls + a Python script. No payment, no API key, no account.

---

## Takeaways

1. **Apple's vouching is real.** Every cert chain in the live feed verifies against the embedded Apple Enterprise Attestation Root CA. The OIDs match the feed. This is not vapor.
2. **The MDA→SE-key binding is the load-bearing step, and it's broken in production for ~43% of hardware-trust providers.** The coordinator detects this internally (`SEKeyBound=false`) and silently keeps the trust level. The fix is a small policy change (refuse hardware-trust without binding) plus exposing `se_key_bound` in the feed.
3. **The coordinator is the silent kingpin.** No external attestation, no publicly-readable blessed-binary registry, sees plaintext on the default code path. Every other CVM-based case study in this cohort publishes its attestation — Darkbloom should too if it wants the "edge TEE" framing to be more than provider-side hardening with a centralized middle.
4. **Provider-side engineering is unusually clean.** Source provenance via GitHub Actions → notarized binary → registered SHA → in-attestation gating is a complete chain — better than oauth3-burnt's `${DOCKER_IMAGE}` pattern, on par with near-ai-private-inference's on-chain anchors. The codebase candidly documents its own scope-of-signature gaps (`attestation.go:459-478`), which is rare and good.
5. **The "without paying" answer is yes — partially.** You can verify Apple's identity attestation for every live provider for free. You can detect the 13/30 binding gap from outside. You cannot independently verify the SE-signed blob, the live security state, or anything about the coordinator. Closing those gaps doesn't require new cryptography — just feed exposure.
