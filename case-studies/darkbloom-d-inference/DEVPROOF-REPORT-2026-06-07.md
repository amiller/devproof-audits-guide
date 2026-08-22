# Darkbloom (d-inference) DevProof Audit

**Status as of:** 2026-06-07
**Subject:** [Layr-Labs/d-inference](https://github.com/Layr-Labs/d-inference) — product brand "Darkbloom" by Eigen Labs
**Repo HEAD:** `069a6c3`
**Live coordinator:** `https://api.darkbloom.dev` — EigenCloud app **`d-inference`**, id `0x2ea79ae13e30c0c127d684c3e145a974abce1ce3`
**Live providers:** 64–67 Apple Silicon Macs at probe time

> **Headline.** A malicious provider — *any* Mac owner who joins the network, with **no Darkbloom credential** — can run modified code that reads and tampers with the private prompts it is paid to serve, while passing every attestation check as "hardware verified." This is **not defended against**, it is **inside Darkbloom's own stated threat model**, and it **cannot be fixed on consumer Macs**. That is the finding. Everything else here (the coordinator, the verifiability plumbing) is secondary and, in the coordinator's case, basically fine.

**Document set.**
- **This file** — current canonical report (2026-06-07).
- `DEVPROOF-REPORT-2026-05-10.md` — original audit, frozen at HEAD `cf4c0ef`. Architecture diagrams, paper concordance, as-first-written findings.
- `FOLLOWUP-REPORT.md` — 2026-06-07 multi-agent re-examination of F1–F6 after vendor-claimed fixes.
- `CHAIN-OF-TRUST.md` — deep cert-chain walk (provider side).
- `ISSUES-DRAFT.md` — file-able GitHub issues.

**Sources consulted.** (1) The `Layr-Labs/d-inference` repo at `069a6c3` — code is ground truth for behavior. (2) The whitepaper `papers/dginf-private-inference.pdf` — Eigen's own architecture, incl. Definition 2 (threat model), Table 10 ("Coordinator TEE: Intel TDX"), and the §1 admission that App Attest is unavailable on macOS. (3) Live `api.darkbloom.dev`. (4) **EigenCloud** `verify.eigencloud.xyz` + `userapi-compute.eigencloud.xyz/v2/apps/{app}/attestations` — where the coordinator's TDX quotes are published. (5) Eigen's engineering blog `blog.eigencloud.xyz/project-darkbloom-…` ("the coordinator remains part of the trusted routing layer"). (6) Marketing site `darkbloom.dev` and press (Bankless, "replicates Apple PCC"). Claims diverge by venue: the **paper and blog are largely candid; the marketing/press overclaim.**

---

## 1. The core finding — a malicious provider can read and tamper with your prompts

The threat that decides whether the product delivers what it sells: **can a participant who rents out their Mac read and tamper with the prompts they're paid to serve?** Our assessment: **yes — this is not defended against, and it cannot be defended against on consumer Macs.**

This adversary is **squarely inside the whitepaper's own threat model**, not one we invented ([Definition 2](https://github.com/Layr-Labs/d-inference/blob/069a6c3cd5c4072928c6acc98595e0aea11ae4ea/papers/dginf-private-inference.pdf) grants the adversarial provider the ability to *"execute arbitrary code as root"* and *"install any user-level software"*). It is explicitly *not* limited to running the genuine binary. So the paper is on the hook to defend against exactly this.

**What the Apple anchor (MDA) actually proves — and what it can't.** The only Apple-rooted attestation in the system is **[Managed Device Attestation (MDA)](https://support.apple.com/guide/deployment/managed-device-attestation-dep28afbde6a/web)**, Apple's MDM feature for proving facts about a managed *device*. Mechanically: the Mac generates a Secure Enclave key; Apple's attestation servers confirm it is genuine Apple hardware and issue an X.509 certificate — chaining to Apple's attestation root — whose fields carry the device's serial, UDID, OS/SepOS versions, security-configuration bits, and a freshness nonce. Verifying that chain proves exactly three things: *this is genuine Apple silicon*, *with these device/OS properties*, *and a particular SE key lives in its enclave*. It proves **nothing about which application or code is running** — MDA has no concept of an app binary or its hash; it binds a key to a *device*, never to a *program*. That is by design: MDA is a fleet-management tool for an organization verifying its own cooperative devices, not a mechanism for attesting code on an adversary-owned machine. Darkbloom uses MDA correctly *as far as it goes* — it even works around the fact that Apple's attested key is locked in a platform keychain by binding its own SE key through the nonce (`freshness = sha256(se_pubkey)`, §9.3). But the anchor MDA provides is **device authenticity, not code authenticity.**

**The unsupported leap — `binaryHash`.** To cross from "genuine device" to "running the blessed code," the design adds one more field, and this is where the chain breaks. The paper's defense against a modified binary is the `binaryHash` field (§7.1, Table 1): *"binaryHash — the SHA-256 hash of the running provider binary… A non-matching hash indicates modified code, and the provider is rejected. This prevents an adversary from patching the binary to bypass security checks."* The flaw is that **`binaryHash` is computed by the provider binary over itself and then signed by the provider's own Secure Enclave key. The SE signs the bytes it is handed; it does not *measure* the binary** (unlike SGX `EREPORT` or a TDX launch measurement). So the defense asks a possibly-malicious binary to honestly report whether it is malicious. An adversary who "can execute arbitrary code as root" — the paper's own Definition 2 — simply reports a blessed hash while running different code. The check is circular. Two conflations make it *look* airtight: (1) MDA's *device* attestation is treated as if it carried over to *code* (it doesn't); and (2) "binaryHash in the **SE-signed** attestation" sounds hardware-measured, but it is only hardware-**signed over a self-supplied value** — *signed ≠ measured.* Neither device-attested nor SE-signed gets you code-attested.

**The attack, concretely.** A malicious owner runs a prompt-logging (and/or answer-tampering) build on one genuine, MDM-enrollable Mac. They never touch the System volume, so SIP/Secure Boot/SSV stay genuinely on and MDA passes; they generate their own SE key, bind it via the MDA nonce, and report a blessed `binaryHash` (and `mlx_metallib`). All coordinator checks (`provider.go:835-907`) pass, the provider is marked "hardware verified," real users' prompts are routed to it, and it is **paid** to receive them. Responses it returns are signed by its own hardware-verified key, so manipulated answers also read as verified.

**Two questions, stated so they cannot be misread:**

> **Q1 — Does the coordinator verify the provider binary is code-signed by Darkbloom?**
> **No.** There is *no* code-signing / Team-ID / cdhash check of the provider anywhere in the coordinator (grep of the tree: the only code-signing logic is the coordinator signing its *own* MDM profiles). The coordinator's sole input about provider code is the self-reported `binaryHash`.
>
> **Q2 — Does the attack require Darkbloom's code-signing key?**
> **No.** The attacker signs their own build with their own identity (or ad-hoc), and uses their own self-generated SE key. The *legitimate* protocol already uses a self-generated SE key bound only to the *device* via the MDA nonce — by design (§9.3), because Apple's app-bound attested keys are inaccessible to third-party apps. The attacker does the identical thing. **No Darkbloom credential is involved at any step.**

Because no Darkbloom key is needed, the attack is open to **any of the Mac owners who join the network**, not just a Darkbloom insider. (The insider variant — Eigen Labs shipping a backdoored build under the real Team ID, or blessing a backdoored hash via `POST /v1/releases` — also works and is strictly broader, but it is not required.)

**Is this fixable? Three tiers:**

| Tier | Adversary | Fixable on macOS? | Why |
|---|---|---|---|
| 1 | external auditor can't *check* a claim (F-list) | **Yes — engineering** | publish the SE-signed blob + binding; complete the web verifier. No Apple dependency. |
| 2 | lone Mac owner runs a self-signed build, reports a blessed hash | **No stock Apple primitive** | The signer-granular option — **App Attest** — returns [`isSupported == false` on macOS](https://developer.apple.com/documentation/devicecheck/dcappattestservice/issupported) (Apple's own docs: "if you read isSupported from an app running on a Mac device, the value is always false"; the whitepaper says so too, §1); it is iOS/iPadOS-only. The SE key is bare (`SecureEnclave.P256.Signing.PrivateKey()`, no Apple cert); no public boot-measurement/PCR API exists. So **nothing remotely anchors *which app* is running.** The only defenses are the SIP/code-signing arguments — which protect the *System* volume, not the writable-Data-volume provider binary the owner can re-sign. |
| 3 | malicious/compromised Darkbloom signer | **No — Apple doesn't offer it** | Build-exact remote attestation of third-party code (cdhash export) exists only for Apple's own PCC servers. Even on iOS, App Attest would be *signer-granular* (MRSIGNER), never build-exact (MRENCLAVE). |

So **provider code identity has no remote cryptographic anchor on today's macOS at all** — it is *self-report only*. Be precise about which half this is: the **device + posture** layer (genuine Apple hardware, SIP/Secure Boot/SSV on) **is** soundly and remotely attested via MDA/MDM/SE — that part works. It is specifically the **inference-code identity** — the thing that determines whether the running code reads your prompt — that is unanchored. A server-TEE provider (TDX/SGX, like Darkbloom's *own* coordinator) measures the code at launch and has none of this gap; the consumer-Mac thesis inherently does.

**What the whitepaper claims vs. what holds.** The paper's Theorem 1 ("SIP Runtime Immutability") is correct but narrow — it proves SIP cannot be *disabled* mid-process (doing so needs a reboot, which kills the process). It says nothing about *which binary* is running. The paper over-extends it: §9.3 ("SIP enforcement preventing binary replacement") and Table 1 ("Code signing + SIP: macOS refuses modified signed binaries") treat binary replacement as blocked, and Table 10 lists the **residual attack as "physical probing," the same as Apple PCC.** That is too strong: the substitution attack above is a *software* residual that needs no physical probing — a self-signed build on the Data volume with a self-reported blessed hash is caught by none of SIP (System-volume only), code signing (signer-granular, owner self-signs), or the hash check (self-reported). To the paper's credit it is candid elsewhere — it states App Attest is unavailable on macOS, that the hardware owner is adversarial (a harder setting than PCC), and that MDA enrollment for arbitrary consumers is unsolved. The gap is localized, but it is load-bearing: it is the exact property the product is sold on.

---

## 2. How it works

A request crosses **two trust domains** and is decrypted **twice** — once at the coordinator, once at the provider. There is no consumer→provider end-to-end encryption.

```
Consumer (OpenAI-compatible client / web console / curl)
   │  HTTPS to api.darkbloom.dev.
   │  Default = plaintext JSON. Sealed mode (opt-in) = encrypted to the
   │  COORDINATOR's X25519 key (kid 833aec78…) — protects the wire to the coordinator.
   ▼
COORDINATOR  (Go) — runs in a GCP Confidential VM with Intel TDX, under EigenCloud
   │  • Decrypts the request (box.Open, sender_encryption.go:177) to read the model.
   │  • Routes by model/capacity; RE-ENCRYPTS the body to the chosen provider's
   │    X25519 key and forwards (consumer.go dispatchOneProvider).
   │  • Holds plaintext in memory only. Persists token COUNTS for billing
   │    (store RecordUsage*, no prompt columns). Telemetry allowlist-filtered
   │    ("prompt/response content MUST NEVER appear", telemetry_handlers.go:46).
   │  • ATTESTED: live Intel TDX quote (MRTD/RTMRs) + GCP vTPM, published on
   │    EigenCloud (§3). The operator does NOT see the plaintext — the TEE seals it.
   ▼
PROVIDER  (Swift) — third-party Apple Silicon Mac, in-process MLX (no vLLM)
   │  • Apple SE P-256 key + MDA cert chain → Apple attestation root.
   │    Attests genuine device + posture (SIP/Secure Boot/SSV) + OS versions.
   │  • Self-reports binaryHash + mlx_metallib hash, signed by its own SE key;
   │    coordinator checks them against a Darkbloom allowlist (NOT a measurement — §1).
   │  • Decrypts the prompt; runs inference on hardware the owner controls.
   ▼
   plaintext exists in two places: coordinator TEE memory, and provider memory.
```

The two ends are not symmetric, and this is the whole story:

- **At the coordinator**, the process decrypts each prompt to route it — but it runs inside an **attested Intel TDX TEE**, so **Eigen Labs, the operator, does not see the plaintext.** The TEE is exactly what makes "the operator can't read it" *true* on this side (verified in §3).
- **At the provider**, the prompt is decrypted on a Mac whose owner can read its own memory, and — per §1 — the attestation **cannot prove the running code won't.** This is where "the operator/host can't see your data" actually fails.

So the marketing line "the operator cannot see your data" is *true for the coordinator* (via the TEE) and *false for the provider* (the substitution attack). The danger is the node that ultimately decrypts your prompt, not the matchmaker in the middle.

---

## 3. Is the operator (Eigen Labs / the coordinator) honest? — largely yes, and verifiable

The coordinator decrypts your prompt, so a natural worry is "can Eigen Labs read my inference at the coordinator?" Our assessment: **this is substantially addressed and nearly fully verifiable — we do not consider the coordinator a meaningful avenue for Eigen to read prompts.** The chain:

| Link | What it establishes | Status |
|---|---|---|
| (a) Coordinator runs in a real TEE | the cloud host / operator can't read VM memory or attach a debugger | **✓ verified** — live Intel TDX quote + GCP vTPM on EigenCloud |
| (b) The attested code doesn't retain plaintext | even decrypted, prompts aren't logged/stored/exfiltrated | **✓ audited in source** |
| (c) Attested image ⇄ public source | the code in the TEE *is* the audited, non-logging code | **provisionally accepted** — closeable, see below |
| (d) `api.darkbloom.dev` ⇄ this attested app | you're talking to that TEE, not a proxy in front of it | **not yet surfaced** — wiring, not a hole |

**(a) is verified.** EigenCloud publishes the coordinator's attestations (`verify.eigencloud.xyz/app/0x2ea79ae1…`; API `userapi-compute.eigencloud.xyz/v2/apps/…/attestations`): `platform: INTEL_TDX`, `mrtd feb74866…`, `rtmr0..3`, GCP vTPM, `image_reference docker.io/eigenlayer/eigencloud-containers@sha256:e891031f…`, with a **35-entry dated history (2026-04-10 → 2026-06-06)** of every image digest. This is a real TEE, externally checkable, no account.

**(b) is audited.** In the public tree: decrypt → route → re-encrypt → forward, in memory; billing stores token counts only (`store RecordUsage*`, no prompt columns); telemetry is allowlist-filtered ("prompt/response content MUST NEVER appear", `telemetry_handlers.go:46`); no body logging or persistence.

**(c) is provisionally accepted, not a gap we weight.** The attested artifact is EigenCloud's generic platform container launched via `compute-source-env.sh`, so the MRTD/RTMRs don't *by themselves* prove "commit X of `Layr-Labs/d-inference`, reproducibly built." Closing this is ordinary work — a reproducible build checked against EigenCloud's `/builds/verify` — and we provisionally accept the correspondence. It is unfinished verification, not a meaningful hole. (EigenCloud's own README notes Mainnet Alpha "still trusts the developer," so the platform doesn't yet *enforce* image↔source, but that bounds the strength of the guarantee, it doesn't open a practical avenue.)

**(d) is a surfacing/wiring task.** The attestation isn't linked from `darkbloom.dev`, not bound to the TLS endpoint, and not checked by the SDK before sending — so a user has no in-band reason to even look at it. That's worth fixing (the TEE the company runs is currently invisible to the user it protects), but it's plumbing, not a broken guarantee.

**Bottom line for the operator threat:** sound trust model, real TEE, non-retaining code, two items of unfinished verification that are straightforward to close. Contrast sharply with §1, which is a real, unfixable hole.

---

## 4. Other findings (F1–F6 + new)

| # | Finding | Status | Note |
|---|---|---|---|
| **F1** | MDA→SE binding not gated / not in feed | **Partially fixed** | Live binding 60/60 (incidental — forced re-attestation, `a391376`), but no server-side gate and `se_key_bound` still unpublished. (This is device-binding; it does **not** touch the §1 code-identity hole.) |
| **F2** | Provider feed omits SE-signed blob + signature | **Not fixed** | Posture/`binary_hash`/`encryption_public_key` are coordinator-asserted to outsiders. Publishing them makes the *device + posture* attestation externally checkable; it does **not** fix §1 (the SE signs self-measured values). |
| **F3** | Coordinator attestation not surfaced to the consumer | **Open (infra exists)** | The TDX quote + image-digest history exist on EigenCloud (§3) but are absent from `api.darkbloom.dev` and unbound to the endpoint (gap d). |
| **F4** | Provider-binary release registry has no public log | **Open (coordinator covered)** | EigenCloud keeps a dated coordinator image-digest history. The *provider-binary* allowlist (`POST /v1/releases`) still has no public read-only log / Sigstore / on-chain anchor. |
| **F5** | Client-side verifiers incomplete | **Partially fixed** | Web verifier stops at "Genuine Apple device" (no binding check) though `se_public_key` is now in the feed; no consumer SDK. |
| **F6** | Marketing misstates the decryption mechanism | **Valid (nitpick)** | `darkbloom.dev` says *"the coordinator routes ciphertext, only the matched provider's hardware-bound key can decrypt"* — false as a mechanism (the coordinator decrypts, `consumer.go:303`), **but the conclusion holds via the TDX TEE**, so it's a wording error, not a broken guarantee. The eng blog is honest; the marketing/press overclaim. Substrate confirmed **GCP + Intel TDX** (paper Table 10; the "AMD SEV-SNP" source comments are wrong). |
| **NEW** | Unauthenticated MDM webhook trust-injection | **Fixed (in code)** | Solicited-UUID gate + UDID cross-check (#270/#233); not externally distinguishable from a no-op (live endpoint returns 200 to forged POSTs). |

---

## 5. Recommendations

**The one that matters (Threat §1 — and it's a disclosure, not a patch):**
1. **Stop claiming a guarantee the substrate can't provide.** On macOS there is no remote way to prove the running inference binary (App Attest unavailable, no cdhash export), so "a malicious provider cannot see your prompt" is not enforceable. Either say so plainly, or move the inference workload onto a substrate that *can* measure code (a server TEE, like the coordinator's own TDX path) — at the cost of the consumer-Mac thesis. Realistic interim mitigations are non-cryptographic (signed/notarized distribution + the SIP/Hardened-Runtime arguments, which bound *tampering* but not a *self-signed replacement*) and should be described as such.

**Coordinator (Threat §3 — close the verification, it's nearly done):**
2. **Bind `api.darkbloom.dev` to the attested app (d).** Surface the EigenCloud quote in-band and have the SDK/console verify it (ideally TLS-key-bound) before sending.
3. **Publish the reproducible-build recipe (c)** tying `image_digest` → a `Layr-Labs/d-inference` commit via `/builds/verify`.
4. **Fix F6 wording:** "the coordinator decrypts inside an attested TEE that doesn't retain prompts"; correct the SEV-SNP→TDX lines.

**Provider verifiability (the half Apple *does* support):**
5. **Publish the SE-signed blob + `se_key_bound` in the provider feed (F1/F2)** and complete the web verifier's binding check (F5) — makes device + posture externally checkable.
6. **Route a read-only `GET /v1/releases`** (or Sigstore-sign each registration) so the provider-binary allowlist is auditable (F4).

The honest claim Darkbloom *can* make: **"the operator decrypts inside a verifiable TEE that doesn't retain your prompt, and routes only to genuine, posture-attested Apple devices."** It cannot honestly add "running provably-unmodified inference code" for the provider — Apple offers no mechanism for that on macOS. The distance between that honest claim and "only the node can decrypt" / "replicates Apple PCC" (whose fifth requirement is *verifiable transparency* — build-exact, inspectable images) is the finding.

---

## 6. Reproducing

```bash
# Coordinator TEE attestation (no account) — the operator IS in a real TDX TEE
app=0x2ea79ae13e30c0c127d684c3e145a974abce1ce3
curl -sS "https://userapi-compute.eigencloud.xyz/v2/apps/$app/attestations" \
  | jq '.[0].verified_claims.tee_claims, .[0].verified_claims.container_claims.image_reference, .[0].created_at'
#   INTEL_TDX, mrtd feb74866…, image docker.io/eigenlayer/eigencloud-containers@sha256:e891031f…
# Dashboard: https://verify.eigencloud.xyz/app/0x2ea79ae13e30c0c127d684c3e145a974abce1ce3

# Provider device chain + F1 binding (no account) — device attested, code NOT
curl -sS https://api.darkbloom.dev/v1/providers/attestation > /tmp/feed.json
python3 verify/binding-check.py /tmp/feed.json     # HOLDS 60 / FAILS 0

# The §1 hole, in the code:
#   provider.go:835-907     coordinator checks a SELF-REPORTED binaryHash vs allowlist
#   (no codesign/TeamID/cdhash check anywhere — grep the tree)
#   RuntimeHashReporter      provider hashes currentExecutableURL() over ITSELF
#   SecureEnclaveIdentity    bare SE key signs the blob — signs bytes, doesn't measure code
#   whitepaper §1            "App Attest (DCAppAttestService) returns false for isSupported on macOS"
```

---

## 7. References (first-party)

**Apple — Managed Device Attestation (attests the *device*, not the code):**
- [Managed Device Attestation for Apple devices](https://support.apple.com/guide/deployment/managed-device-attestation-dep28afbde6a/web) — overview: an org's ACME service requests an attestation of *device* properties (serial, etc.) and provisions a hardware-bound *device* identity.
- [Deploy Managed Device Attestation](https://support.apple.com/guide/deployment/deploy-managed-device-attestation-dep54e5ac1fd/web) — ACME `device-attest-01` deployment.

**Apple — App Attest (the *code*-level primitive — unavailable on macOS):**
- [`DCAppAttestService`](https://developer.apple.com/documentation/devicecheck/dcappattestservice) · [`DCAppAttestService.isSupported`](https://developer.apple.com/documentation/devicecheck/dcappattestservice/issupported) — "if you read isSupported from an app running on a Mac device, the value is always false." First-party confirmation of the §1 limitation.

**Darkbloom whitepaper** (pinned to commit `069a6c3`):
- [`papers/dginf-private-inference.pdf`](https://github.com/Layr-Labs/d-inference/blob/069a6c3cd5c4072928c6acc98595e0aea11ae4ea/papers/dginf-private-inference.pdf) — Definition 2 (adversary "execute arbitrary code as root"); §7.1 + Table 1 (the `binaryHash` defense); §9.3 (self-generated SE key bound via MDA nonce; App Attest unavailable); Table 10 (Coordinator TEE = Intel TDX; residual = physical probing).

**Code — `Layr-Labs/d-inference` @ `069a6c3` (the §1 hole, in source):**
- [`coordinator/api/provider.go#L835-L878`](https://github.com/Layr-Labs/d-inference/blob/069a6c3cd5c4072928c6acc98595e0aea11ae4ea/coordinator/api/provider.go#L835-L878) — provider acceptance checks a **self-reported** `binaryHash` against the allowlist; **no** codesign / Team-ID / cdhash check exists anywhere.
- [`coordinator/api/consumer.go#L303`](https://github.com/Layr-Labs/d-inference/blob/069a6c3cd5c4072928c6acc98595e0aea11ae4ea/coordinator/api/consumer.go#L303) — `e2e.Encrypt(rawBody, …)`: coordinator holds plaintext and re-encrypts to the provider.
- [`coordinator/api/sender_encryption.go#L177`](https://github.com/Layr-Labs/d-inference/blob/069a6c3cd5c4072928c6acc98595e0aea11ae4ea/coordinator/api/sender_encryption.go#L177) — `box.Open(...)`: coordinator decrypts the sealed request.
- [`coordinator/api/telemetry_handlers.go#L46-L48`](https://github.com/Layr-Labs/d-inference/blob/069a6c3cd5c4072928c6acc98595e0aea11ae4ea/coordinator/api/telemetry_handlers.go#L46-L48) — telemetry allowlist: "prompt or response content MUST NEVER appear here."
- [`coordinator/store/interface.go#L95`](https://github.com/Layr-Labs/d-inference/blob/069a6c3cd5c4072928c6acc98595e0aea11ae4ea/coordinator/store/interface.go#L95) — `RecordUsage(...)`: token counts only, no prompt columns.
- [`provider-swift/.../Security/SecurityFoundation.swift#L254-L287`](https://github.com/Layr-Labs/d-inference/blob/069a6c3cd5c4072928c6acc98595e0aea11ae4ea/provider-swift/Sources/ProviderCore/Security/SecurityFoundation.swift#L254-L287) — `RuntimeHashReporter`: the provider hashes `currentExecutableURL()` **over itself**.
- [`provider-swift/.../Security/SecureEnclaveIdentity.swift#L56`](https://github.com/Layr-Labs/d-inference/blob/069a6c3cd5c4072928c6acc98595e0aea11ae4ea/provider-swift/Sources/ProviderCore/Security/SecureEnclaveIdentity.swift#L56) — bare `SecureEnclave.P256.Signing.PrivateKey()` (no Apple cert; signs bytes, doesn't measure code).
- [`provider-swift/.../Security/BinaryHasher.swift#L135`](https://github.com/Layr-Labs/d-inference/blob/069a6c3cd5c4072928c6acc98595e0aea11ae4ea/provider-swift/Sources/ProviderCore/Security/BinaryHasher.swift#L135) — `metallibHash()` (the GPU-kernel hash, also self-reported).

**Coordinator TEE attestation (EigenCloud — the operator IS in a real TDX TEE):**
- Dashboard: [verify.eigencloud.xyz/app/0x2ea79ae1…](https://verify.eigencloud.xyz/app/0x2ea79ae13e30c0c127d684c3e145a974abce1ce3)
- API: [`userapi-compute.eigencloud.xyz/v2/apps/0x2ea79ae1…/attestations`](https://userapi-compute.eigencloud.xyz/v2/apps/0x2ea79ae13e30c0c127d684c3e145a974abce1ce3/attestations)

**Vendor venues (claims diverge — paper/blog candid, marketing overclaims):**
- [Eigen engineering blog — Project Darkbloom](https://blog.eigencloud.xyz/project-darkbloom-unlocking-idle-compute-for-ai/) — "the coordinator remains part of the trusted routing layer."
- [darkbloom.dev](https://www.darkbloom.dev/) — "the coordinator routes ciphertext, and only the matched provider's hardware-bound key can decrypt" (false as a mechanism; see F6).
