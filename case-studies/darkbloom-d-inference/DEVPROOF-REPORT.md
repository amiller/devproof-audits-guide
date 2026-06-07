# Darkbloom (d-inference) DevProof Audit

**Status as of:** 2026-06-07
**Subject:** [Layr-Labs/d-inference](https://github.com/Layr-Labs/d-inference) — product brand "Darkbloom" by Eigen Labs
**Repo HEAD:** `069a6c3`
**Live coordinator:** `https://api.darkbloom.dev` — EigenCloud app **`d-inference`**, id `0x2ea79ae13e30c0c127d684c3e145a974abce1ce3`
**Live providers:** 64–67 Apple Silicon Macs at probe time

**Document set.**
- **This file** — current canonical report (2026-06-07).
- `DEVPROOF-REPORT-2026-05-10.md` — original audit, frozen at HEAD `cf4c0ef`. Architecture diagrams, paper concordance, as-first-written findings.
- `FOLLOWUP-REPORT.md` — 2026-06-07 multi-agent re-examination of F1–F6 after vendor-claimed fixes.
- `CHAIN-OF-TRUST.md` — deep cert-chain walk (provider side).
- `ISSUES-DRAFT.md` — file-able GitHub issues.

**Sources consulted.** (1) The `Layr-Labs/d-inference` repo at `069a6c3` — code is ground truth for behavior. (2) The whitepaper `papers/dginf-private-inference.pdf` — Eigen's own architecture, incl. Table 10 (which lists "Coordinator TEE: Intel TDX") and the §1 admission that App Attest is unavailable on macOS. (3) Live `api.darkbloom.dev`. (4) **EigenCloud** `verify.eigencloud.xyz` + `userapi-compute.eigencloud.xyz/v2/apps/{app}/attestations` — where the coordinator's TDX quotes are actually published. (5) Eigen's engineering blog `blog.eigencloud.xyz/project-darkbloom-…` (honest: "the coordinator remains part of the trusted routing layer"). (6) Marketing site `darkbloom.dev` and press (Bankless, "replicates Apple PCC") — which overclaim. Claims diverge by venue: the **paper and blog are largely candid; the marketing/press kit overclaim.**

---

## 1. How it actually works

A request crosses **two trust domains** and is decrypted **twice** — once at the coordinator, once at the provider. There is no consumer→provider end-to-end encryption; the coordinator is a decryption point by design.

```
Consumer (OpenAI-compatible client / web console / curl)
   │  HTTPS to api.darkbloom.dev.
   │  Default = plaintext JSON. Sealed mode (opt-in, Content-Type
   │  application/eigeninference-sealed+json) = encrypted to the COORDINATOR's
   │  X25519 key (kid 833aec78e1c7c828) — protects the wire, not from the coordinator.
   ▼
COORDINATOR  (Go) — runs in a GCP Confidential VM with Intel TDX, under EigenCloud
   │  • Decrypts the request (box.Open, sender_encryption.go:177) to read the model.
   │  • Routes by model/capacity; RE-ENCRYPTS the body to the chosen provider's
   │    X25519 key and forwards (consumer.go dispatchOneProvider).
   │  • Holds plaintext in memory only. Persists token COUNTS for billing
   │    (store RecordUsage*, no prompt columns). Telemetry is allowlist-filtered
   │    ("prompt/response content MUST NEVER appear", telemetry_handlers.go:46).
   │  • ATTESTED: Intel TDX quote (MRTD/RTMRs) + GCP vTPM, published on EigenCloud
   │    (see §2). Decrypts-but-doesn't-retain is enforced by the TEE + the code,
   │    not by withholding the plaintext.
   ▼
PROVIDER  (Swift) — third-party Apple Silicon Mac, in-process MLX (no vLLM)
   │  • Apple SE P-256 key + MDA cert chain → Apple Enterprise Attestation Root CA.
   │    Attests genuine device + posture (SIP/Secure Boot/SSV) + OS versions.
   │  • Self-reports binaryHash + mlx_metallib hash, signed by its own SE key;
   │    coordinator checks them against a Darkbloom-controlled allowlist.
   │  • Decrypts the prompt; runs inference in a hardened, SIP-locked process.
   ▼
   plaintext exists in exactly two places: coordinator memory, provider memory.
```

The crucial structural fact: **"the operator cannot see your data" is not what the system does.** The coordinator (Eigen Labs) decrypts every prompt. The privacy argument is therefore not "they never see it" — it is "they see it inside a TEE, running code that doesn't retain it." That argument is only as strong as the attestation behind it, which is the subject of this report.

---

## 2. What is verifiable today (the positive findings)

These are real and we re-verified them from outside, no account:

**Coordinator runs in a genuine, attested Intel TDX TEE.** EigenCloud publishes the coordinator's attestations at `https://verify.eigencloud.xyz/app/0x2ea79ae1…` and via API `GET https://userapi-compute.eigencloud.xyz/v2/apps/0x2ea79ae1…/attestations`. The latest quote (2026-06-06):

- `platform: INTEL_TDX`, `debug: false`
- `mrtd: feb7486608382c1ff0e15b4648ddc0acea6ca974eb53e3529f4c4bd5ffbaa20bf335cb75965cea65fe473aed9647c162`
- `rtmr0..3` populated, `tee_tcb_svn: 0d0108…`, plus a GCP **vTPM** quote (`gce` platform claim) — i.e. a GCP Confidential VM with Intel TDX.
- `image_reference: docker.io/eigenlayer/eigencloud-containers@sha256:e891031fb483…`, args `compute-source-env.sh start.sh`, coordinator env (MDM URL, step-ca paths, port 8080).
- **35 dated attestations, 2026-04-10 → 2026-06-06, ~28 distinct image digests** — a queryable history of every image the coordinator has run.

**Provider side is Apple-anchored and externally checkable up to the SE key.** Every MDA cert chain in the live feed verifies to Apple's Enterprise Attestation Root CA; the freshness binding (`sha256(se_public_key) == freshness OID`) now holds 60/60 (was 13/30 failing). See `CHAIN-OF-TRUST.md`.

**Coordinator source does not retain plaintext.** Audited in the public tree (provisionally accepting it corresponds to the attested image — see §5): decrypt → route → re-encrypt → forward, in memory; billing stores token counts only; telemetry allowlist excludes prompt/response; no body logging or persistence.

This is the verifiable core of the coordinator-side story: the operator-honesty threat (§3) is therefore *largely addressable* — unlike the provider-side hole (§4), which is not.

---

## 3. Threat model A — is the operator (Darkbloom) honest? *(the one most users mean)*

The coordinator decrypts your prompt. So "can Eigen Labs read my inference?" reduces to whether you can trust the thing doing the decryption. The chain of what you'd need, and where each link stands:

| Link | What it would establish | Status |
|---|---|---|
| (a) Coordinator runs in a real TEE | the cloud host / operator can't read VM memory or attach a debugger | **✓ verified** — Intel TDX quote + vTPM on EigenCloud (§2) |
| (b) The attested code doesn't retain plaintext | even decrypted, prompts aren't logged/stored/exfiltrated | **✓ in source** (audited), **⚠ not bound to (c)** |
| (c) Attested image ⇄ public source | the code in the TEE *is* the audited, non-logging code | **✗ not established** — see below |
| (d) `api.darkbloom.dev` ⇄ this attested app | you are actually talking to that TEE, not a plaintext proxy in front of it | **✗ not established** |

**(c) is the real gap.** The attested artifact is EigenCloud's *generic platform container* (`eigenlayer/eigencloud-containers@sha256:…`) launched via `compute-source-env.sh start.sh` — EigenCloud "source mode," where the coordinator code is brought up inside a wrapper. So the MRTD/RTMRs attest *a genuine TDX VM running EigenCloud's container with this config*; they do **not**, by themselves, prove "running commit X of `Layr-Labs/d-inference`, built reproducibly." EigenCloud exposes a build-verification surface (`/builds/image/`, `/builds/verify/`) that may bridge this, but EigenCloud's own README states Mainnet Alpha "does not enable full verifiable and trustless execution — the developer is still trusted [and] can upgrade code." So today the image→source binding rests on trusting Eigen, not on a reproducible-build proof a third party checks.

**(d) is the second gap.** A consumer hits `api.darkbloom.dev` over ordinary web TLS. Nothing in that handshake proves the endpoint is the attested TDX app `0x2ea79ae1…` rather than a plaintext front-end that forwards into (or around) it. The attestation is not linked from darkbloom.dev, not surfaced in the SDK, and not bound to the TLS identity. A user has no in-band reason to even look at EigenCloud, let alone a cryptographic tie.

**The honest answer:** the operator-honesty defense is *half-built and half-verifiable*. The TEE is real (a) and the published code behaves (b) — but until (c) and (d) close, "Darkbloom can't secretly read my prompts" rests on **trusting Eigen Labs' word** that the attested image is the audited source and that the endpoint is the attested TEE. The infrastructure to make it checkable largely exists (EigenCloud quotes + build verify); the bindings and the user-facing surfacing do not.

**Higher-privilege variant (collusion).** Even with (a)–(d) closed, Eigen Labs still (i) controls the provider allowlist (`POST /v1/releases`) and (ii) signs provider releases. So a malicious/compromised Eigen insider could bless or ship a backdoored *provider* that decrypts the prompt downstream. Defending against that needs build-exact attestation of the provider code — which, on Apple, does not exist (§4, Tier 3). So the operator-collusion threat ultimately collides with the Apple ceiling at the provider, not the coordinator.

---

## 4. Threat model B — is the *provider* (the Mac owner) honest? *(the core finding)*

This is the threat that decides whether the product delivers what it sells: **can a participant who rents out their Mac read and tamper with the prompts they're paid to serve?** Our assessment: **yes — this is not defended against, and it cannot be defended against on consumer Macs.**

It is worth stating plainly that this adversary is **squarely inside the whitepaper's own threat model**, not a setting we invented. Definition 2 grants the adversarial provider the ability to *"execute arbitrary code as root"* and *"install any user-level software."* The adversary is explicitly *not* limited to running the genuine binary. So the paper is on the hook to defend against exactly this.

**What the Apple anchor (MDA) actually proves — and what it can't.** The only Apple-rooted attestation in the system is **Managed Device Attestation (MDA)**, Apple's MDM feature for proving facts about a managed *device*. Mechanically: the Mac generates a Secure Enclave key; Apple's attestation servers confirm it is genuine Apple hardware and issue an X.509 certificate — chaining to Apple's attestation root — whose fields carry the device's serial, UDID, OS/SepOS versions, security-configuration bits, and a freshness nonce. Verifying that chain proves exactly three things: *this is genuine Apple silicon*, *with these device/OS properties*, *and a particular SE key lives in its enclave*. It proves **nothing about which application or code is running** — MDA has no concept of an app binary or its hash; it binds a key to a *device*, never to a *program*. That is by design: MDA is a fleet-management tool for an organization verifying its own cooperative devices, not a mechanism for attesting code on an adversary-owned machine. Darkbloom uses MDA correctly *as far as it goes* — it even works around the fact that Apple's attested key is locked in a platform keychain by binding its own SE key through the nonce (`freshness = sha256(se_pubkey)`, §9.3). But the anchor MDA provides is **device authenticity, not code authenticity.**

**The unsupported leap — `binaryHash`.** To cross from "genuine device" to "running the blessed code," the design adds one more field, and this is where the chain breaks. The paper's defense against a modified binary is the `binaryHash` field (§7.1, Table 1): *"binaryHash — the SHA-256 hash of the running provider binary… A non-matching hash indicates modified code, and the provider is rejected. This prevents an adversary from patching the binary to bypass security checks."* The flaw is that **`binaryHash` is computed by the provider binary over itself and then signed by the provider's own Secure Enclave key. The SE signs the bytes it is handed; it does not *measure* the binary** (unlike SGX `EREPORT` or a TDX launch measurement). So the defense asks a possibly-malicious binary to honestly report whether it is malicious. An adversary who "can execute arbitrary code as root" — the paper's own Definition 2 — simply reports a blessed hash while running different code. The check is circular. Two conflations make it *look* airtight: (1) MDA's *device* attestation is treated as if it carried over to *code* (it doesn't); and (2) "binaryHash in the **SE-signed** attestation" sounds hardware-measured, but it is only hardware-**signed over a self-supplied value** — *signed ≠ measured.* Neither device-attested nor SE-signed gets you code-attested.

**The attack, concretely.** A malicious owner runs a prompt-logging (and/or answer-tampering) build on one genuine, MDM-enrollable Mac. They never touch the System volume, so SIP/Secure Boot/SSV stay genuinely on and MDA passes; they generate their own SE key, bind it via the MDA nonce, and report a blessed `binaryHash` (and `mlx_metallib`). All coordinator checks (`provider.go:835-907`) pass, the provider is marked "hardware verified," real users' prompts are routed to it, and it is **paid** to receive them. Responses it returns are signed by its own hardware-verified key, so manipulated answers also read as verified.

**Two questions, stated so they cannot be misread:**

> **Q1 — Does the coordinator verify the provider binary is code-signed by Darkbloom?**
> **No.** There is *no* code-signing / Team-ID / cdhash check of the provider anywhere in the coordinator (grep of the tree: the only code-signing logic is the coordinator signing its *own* MDM profiles). The coordinator's sole input about provider code is the self-reported `binaryHash`.
>
> **Q2 — Does the attack require Darkbloom's code-signing key?**
> **No.** The attacker signs their own build with their own identity (or ad-hoc), and uses their own self-generated SE key. In fact the *legitimate* protocol already uses a self-generated SE key bound only to the *device* via the MDA nonce — by design (§9.3), because Apple's app-bound attested keys are inaccessible to third-party apps. The attacker does the identical thing. **No Darkbloom credential is involved at any step.**

This is the severity-defining fact: because no Darkbloom key is needed, the attack is open to **any of the Mac owners who join the network**, not just a Darkbloom insider. (The insider variant — shipping a backdoored build under the real Team ID — also works and is strictly broader; see the collusion note in §3.)

**Is this fixable? Three tiers:**

| Tier | Adversary | Fixable on macOS? | Why |
|---|---|---|---|
| 1 | external auditor can't check a claim (F1, F2, F5) | **Yes — engineering** | publish the SE-signed blob + binding in the provider feed; complete the web verifier. No Apple dependency. |
| 2 | lone Mac owner runs a self-signed logging build, reports a blessed hash | **No stock Apple primitive** | The signer-granular option — **App Attest** — returns `isSupported == false` on macOS (the whitepaper says so itself, §1); it is iOS/iPadOS-only. The SE key is bare (`SecureEnclave.P256.Signing.PrivateKey()`, no Apple cert); no public boot-measurement/PCR API exists. So **nothing remotely anchors *which app* is running.** The only defenses are the SIP/code-signing arguments — which protect the *System* volume, not the writable-Data-volume provider binary the owner can re-sign. |
| 3 | malicious/compromised Darkbloom signer | **No — Apple doesn't offer it** | Build-exact remote attestation of third-party code (cdhash export) exists only for Apple's own PCC servers. Even on iOS, App Attest would be *signer-granular* (MRSIGNER), never build-exact (MRENCLAVE). |

So **provider code identity has no remote cryptographic anchor on today's macOS at all** — it is *self-report only*, which is *weaker* than the "signer-only" ceiling (on iOS, App Attest would at least bind the signer; on macOS even that is unavailable). Be precise about which half this is: the **device + posture** layer (genuine Apple hardware, SIP/Secure Boot/SSV on) **is** soundly and remotely attested via MDA/MDM/SE — that part works. It is specifically the **inference-code identity** that is unanchored. A server-TEE provider (TDX/SGX, like the coordinator) measures the code at launch and has none of this gap; the consumer-Mac thesis inherently does.

**What the whitepaper claims vs. what holds.** The paper's Theorem 1 ("SIP Runtime Immutability") is correct but narrow — it proves SIP cannot be *disabled* mid-process (doing so needs a reboot, which kills the process). It says nothing about *which binary* is running. The paper then over-extends it: §9.3 ("SIP enforcement preventing binary replacement") and Table 1 ("Code signing + SIP: macOS refuses modified signed binaries") treat binary replacement as blocked, and Table 10 lists the **residual attack as "physical probing," the same as Apple PCC.** That is too strong: the substitution attack above is a *software* residual that needs no physical probing — a self-signed build on the Data volume, with a self-reported blessed hash, is not caught by SIP (System-volume only), by code signing (signer-granular, owner self-signs), or by the hash check (self-reported). To the paper's credit it is candid elsewhere — it states App Attest is unavailable on macOS, that the hardware owner is adversarial (a harder setting than PCC), and that MDA enrollment for arbitrary consumers is unsolved. The gap is localized to the binary-integrity claim.

---

## 5. What the problem actually is (synthesis)

Putting both threat models together, here is the trust a real user extends today, prompt in hand:

1. **Trust web PKI** for `api.darkbloom.dev` — and trust, on Eigen's word, that this endpoint is the attested TDX coordinator (gap (d)).
2. **Trust the coordinator's TEE** — this part is *verifiable* (real TDX quote), so the cloud host can't peek. Good.
3. **Trust that the attested image is the audited, non-logging source** — *not* provable today; EigenCloud source-mode + "developer still trusted" (gap (c)).
4. **Trust the provider** that finally decrypts — its **inference-code identity has no remote anchor on macOS at all** (self-reported hash; App Attest unavailable, no cdhash export). Device + posture (genuine HW, SIP on) *are* attested; the running code is not.

The asymmetry is the whole story. The **coordinator** sits on a real TEE (Intel TDX) whose attestation *can* be build-exact — so "the operator decrypts inside a sealed, measured box" is a sound trust model; closing gaps (c)/(d) makes it checkable. The **provider** sits on Apple Silicon, where no third-party-code attestation exists — so provider integrity is *self-report-only*, and no amount of engineering reaches build-exact (or even signer-granular) on macOS. The system is therefore **strongest where earlier drafts called it weakest** (the coordinator TEE is real and verifiable) and **structurally capped where it must be strongest** (the Mac that actually decrypts your prompt cannot prove what code it runs).

**One-line verdict:** the coordinator trust model is sound and nearly verifiable (two bindings short); the provider trust model is not — on macOS, the node that decrypts your prompt can only *say* what code it runs, and Apple offers no way to check. That, not the coordinator, is where "private inference on consumer Macs" hits its real ceiling.

---

## 6. Findings — current status

| # | Finding | Status | Note |
|---|---|---|---|
| **F1** | MDA→SE binding not gated / not in feed | **Partially fixed** | Live binding 60/60 (incidental — forced re-attestation, `a391376`), but no server-side gate and `se_key_bound` still unpublished. |
| **F2** | Provider feed omits SE-signed blob + signature | **Not fixed** | `binary_hash`/`encryption_public_key`/posture remain coordinator-asserted to outsiders. Signing the blob would defeat a transport MITM but **not** the §4 substitution attack (SE signs self-measured hashes). |
| **F3** | Coordinator attestation not surfaced to the consumer | **Open (infra exists)** | The coordinator publishes a live Intel TDX quote + vTPM + image-digest history on EigenCloud (§2) — but it is absent from `api.darkbloom.dev`, unlinked from the product, and not bound to the TLS endpoint. **Residual:** image⇄source (gap c) and endpoint⇄app (gap d) bindings. |
| **F4** | Provider-binary release registry has no public log | **Open (coordinator covered)** | EigenCloud keeps a dated 35-entry coordinator image-digest history (a de-facto transparency log). The *provider-binary* allowlist (`POST /v1/releases`) still has no public read-only log / Sigstore / on-chain anchor. |
| **F5** | Client-side verifiers incomplete | **Partially fixed** | Web verifier still stops at "Genuine Apple device" (no binding check) though `se_public_key` is now in the feed; no consumer SDK. |
| **F6** | Public claims misstate the decryption mechanism | **Valid (nitpick)** | The **marketing site** (`darkbloom.dev`) states *"the coordinator routes ciphertext, and only the matched provider's hardware-bound key can decrypt"* — **false as a mechanism**: the coordinator decrypts every request (`consumer.go:303` `e2e.Encrypt(rawBody,…)`) and re-encrypts to the provider. **But the threat-model conclusion it sells is sound via the TDX TEE** (decrypt-in-a-sealed-box ≈ operator-can't-see), so this is a wording/mechanism error, not a broken guarantee. Eigen's **engineering blog is honest** ("the coordinator remains part of the trusted routing layer"); the **real** defense (attested TDX) is *absent* from the marketing. `CLAUDE.md:3,181` repeats "never sees plaintext." Substrate confirmed **GCP + Intel TDX** (paper Table 10 correct; "AMD SEV-SNP" source comments wrong). |
| **NEW** | Unauthenticated MDM webhook trust-injection | **Fixed (in code)** | Solicited-UUID gate + UDID cross-check (#270/#233); not externally distinguishable from a no-op since the live endpoint returns 200 to forged POSTs. |

---

## 7. Recommendations

**Close the operator-honesty bindings (Threat A) — highest user value:**
1. **Bind `api.darkbloom.dev` to the attested app (gap d).** Surface the EigenCloud attestation in-band (e.g. an endpoint that returns the app id + a TLS-key-bound quote), and have the SDK/console verify it before sending. Without this, the TEE the company runs is invisible to the user it protects.
2. **Bind the attested image to public source (gap c).** Publish the reproducible-build recipe and the EigenCloud `/builds/verify` result tying `image_digest` → a `Layr-Labs/d-inference` commit; document the residual "developer still trusted" caveat honestly until EigenCloud removes it.
3. **Fix F6.** Remove the two false "coordinator never sees plaintext" claims; state plainly "the coordinator decrypts inside an attested TEE that doesn't retain prompts," and correct the SEV-SNP→TDX substrate lines.

**Close what's closable on the provider (Threat B):**
4. **Publish the SE-signed blob + `se_key_bound` in the provider feed (F1/F2)** and complete the web verifier's binding check (F5a). This makes the *device + posture* attestation externally checkable — the half that Apple *does* support.
5. **Route a read-only `GET /v1/releases`** (or Sigstore-sign each registration) so the provider-binary allowlist is externally auditable (F4 residual).
6. **Be honest about the provider code-identity ceiling.** App Attest is unavailable on macOS, so there is no remote way to prove the running inference binary; do not imply otherwise. Realistic mitigations are non-cryptographic (signed-and-notarized distribution + the SIP/Hardened-Runtime arguments, which bound tampering but not a self-signed replacement) — or move the inference workload onto a substrate that *can* measure code (the coordinator's own TDX path), at the cost of the consumer-Mac thesis.

**Nitpick (not load-bearing):** the marketing line "the coordinator routes ciphertext, only the provider can decrypt" is technically false (the coordinator decrypts), but the *threat-model conclusion* it sells is sound via the TDX TEE — so this is a wording/mechanism error to correct, not a broken guarantee. Replace it with the true and equally strong claim: "the coordinator decrypts inside an attested TEE that doesn't retain prompts."

The honest target Darkbloom can reach: **"the operator decrypts inside a verifiable TEE that provably doesn't retain your prompt, and routes only to genuine, posture-attested Apple devices."** It cannot honestly add "running provably-unmodified inference code" for the provider — Apple offers no mechanism for that on macOS. The gap between that honest claim and the current marketing ("only the node can decrypt," "replicates Apple PCC") is itself a finding: PCC's fifth requirement is *verifiable transparency* (build-exact, publicly-inspectable images), which the provider side cannot meet on this substrate.

---

## 8. Reproducing

```bash
# Coordinator TEE attestation (no account)
app=0x2ea79ae13e30c0c127d684c3e145a974abce1ce3
curl -sS "https://userapi-compute.eigencloud.xyz/v2/apps/$app/attestations" | jq '.[0].verified_claims.tee_claims, .[0].verified_claims.container_claims.image_reference, .[0].created_at'
#   INTEL_TDX, mrtd feb74866…, image docker.io/eigenlayer/eigencloud-containers@sha256:e891031f…
# Dashboard: https://verify.eigencloud.xyz/app/0x2ea79ae13e30c0c127d684c3e145a974abce1ce3

# Provider chain + F1 binding (no account)
curl -sS https://api.darkbloom.dev/v1/providers/attestation > /tmp/feed.json
python3 verify/binding-check.py /tmp/feed.json     # HOLDS 60 / FAILS 0

# Confirm the consumer-path gaps
curl -sS -o /dev/null -w '%{http_code}\n' https://api.darkbloom.dev/v1/coordinator/attestation  # 404 — not surfaced on darkbloom's own API
curl -sS https://api.darkbloom.dev/v1/encryption-key   # coordinator X25519 (sealed mode targets the COORDINATOR, kid 833aec78…)

# Coordinator source audit (provisional image⇄source): plaintext handling
#   sender_encryption.go:177  box.Open (decrypt)
#   consumer.go               dispatchOneProvider (re-encrypt to provider, forward)
#   store/interface.go        RecordUsage* (token counts only, no prompt columns)
#   telemetry_handlers.go:46  "prompt/response content MUST NEVER appear here"
```
