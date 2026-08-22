# Darkbloom (d-inference) DevProof Audit — 2026-08-22

**Status as of:** 2026-08-22 (paid-product relaunch)
**Subject:** [Layr-Labs/d-inference](https://github.com/Layr-Labs/d-inference) — product brand "Darkbloom" by Eigen Labs
**Repo HEAD audited:** `232911ca690b78cbd3c8f65668d69f75a8f6bef0` (2026-08-22) — **251 commits** since the June review (`069a6c3`)
**Provider line:** v0.8.10 (Swift/MLX; the Rust+PyO3 provider is gone)
**Coordinator:** self-operated **GCE VM, AMD SEV** — no longer EigenCloud/Intel TDX (§4)

> **Method note.** This pass is **source-only**. `api.darkbloom.dev` is blocked by this session's egress policy, so no live probe of the feed, `/v1/stats`, or the release registry was possible. Every claim below is anchored to a file/line at the pinned commit; each claim that a live probe would settle is marked **[LIVE]** with the exact command in §9. The June report's live numbers (60/60 binding, 35-entry EigenCloud attestation history) are **not** re-confirmed here — and §4 gives reason to believe the second one no longer exists.

---

## TL;DR

**They built the thing we said was missing.** The June report's headline was that provider code identity had *no remote anchor* on macOS — `binaryHash` was self-measured and self-signed, so a malicious Mac owner could run prompt-logging code and pass every check. Darkbloom's answer, shipped in v0.6.0, is an **APNs code-identity challenge**: the coordinator pushes `E_K(nonce)` to the provider's Apple push token; only a binary carrying Darkbloom's Team ID, App ID, and Apple-signed push provisioning profile can receive that push (AMFI enforces this at launch); the provider decrypts with its registered X25519 key and returns `Sign_SE(nonce)`. Self-reported `binaryHash` has been explicitly **demoted to drift telemetry** in their own threat model. This is the most serious attempt at third-party code attestation on macOS we have audited, and it deserves to be said plainly: **the June finding was taken seriously and substantially engineered against.**

**Four things now stand between that mechanism and the guarantee the product sells:**

| # | Finding | Severity |
|---|---|---|
| **N1** | **The code-identity proof is not bound to the attested device.** Posture (MDM/MDA), key possession (SE), and code identity (APNs token) are three independent legs, and *none* of them is cryptographically tied to the machine that actually decrypts the prompt. The pivot is a **self-asserted serial number**. One clean enrolled Mac can vouch for inference running anywhere. | **critical** |
| **N2** | **Enforcement is an operator env var, defaulting to grace.** `APNS_ENFORCE_AFTER` unset ⇒ un-attested providers still route. Fleet economics push against flipping it (67/176 attestable at last documented count; headless Macs *structurally cannot* attest). Externally checkable only via one aggregate boolean in `/v1/stats`. | **high** |
| **N3** | **The coordinator TEE leg regressed.** June: Intel TDX on EigenCloud with a public, dated, 35-entry image-digest history — the one link we marked ✓ verified. Today: a self-run GCE VM that GCP reports as **AMD SEV (not SEV-SNP)** with `--maintenance-policy=MIGRATE`, **no published attestation of any kind**, and the boot-time "am I actually confidential?" assertion their own runbook calls a blocker is **not implemented**. | **high** |
| **N4** | **The paid product's verification UI asserts four guarantees its own code contradicts** — including "Not even Darkbloom servers can read them" — while the Terms and Privacy Policy in the same repo state the opposite, correctly. | **high** |

**Prior findings F1–F6: one fixed, one superseded, four still open** (§6).

The honest claim Darkbloom can make today: *"we route only to Macs that Apple's MDM channel says are SIP-locked and Secure-Boot-full, and — when enforcement is on — only to processes that could receive an Apple push addressed to our signed application."* It still cannot say "the node operator never sees your data" (N1, N2), and it can no longer say the coordinator side is externally verifiable at all (N3).

---

## 1. What changed since 2026-06-07

| Area | June (`069a6c3`) | Today (`232911ca`) |
|---|---|---|
| Provider code identity | self-reported `binaryHash` only | **APNs code-identity round-trip** (v0.6.0); `binaryHash` demoted to telemetry, enforcement behind default-off `EIGENINFERENCE_BINARYHASH_ENFORCE` (`main.go:399`) |
| Coordinator substrate | EigenCloud app `0x2ea79ae1…`, Intel TDX, public quote history | **self-run GCE VM, AMD SEV, `MIGRATE`**, nothing published (§4) |
| Provider runtime | Rust + PyO3 + embedded Python | Swift + mlx-swift only; Python backend un-routable (`privateTextBackendSupported`) |
| Posture signature scope | nonce+timestamp only (fields unsigned) | **`BuildStatusCanonical`** now signs `sip_enabled`, `secure_boot_enabled`, `binary_hash`, `model_hashes`, `runtime_hash`, templates over a coordinator nonce (`attestation/attestation.go:390`) — a real fix |
| Prompt at rest | "memory wiped after each request" | **encrypted SSD prefix cache** on provider disk (AES-256-GCM, SE-rooted KEK, HMAC-named blocks), per-account scope |
| Commercial surface | none | Stripe checkout + Connect payouts, API keys, Privy auth, invite codes, referrals, provider-set pricing, **OpenRouter as a wholesale consumer** |
| New coordinator surfaces | — | `mediafetch` (server-side URL fetch), `promptsidecar` (Rust prompt-render subprocess), prompt-contract cache routing |
| Threat modelling | none in repo | `docs/threat-model.yaml` — 2,665 lines, STRIDE, per-finding mitigations and status |

Two commits are worth naming for credit: **#612 "harden provider plaintext egress paths"** (Aug 14) closed real leaks — inline video plaintext hitting disk, free-form provider error strings crossing to clients, automatic provider log upload, browser free-form telemetry — and **#530**'s `mediafetch` SSRF guard is genuinely good work (§7).

---

## 2. N1 — the code-identity proof is not bound to the device it vouches for

### The mechanism

`docs/architecture/decisions/apns-code-attestation.md` states the security argument: *"Only a process that (a) is signed with our Developer ID, (b) carries our globally-unique App ID `io.darkbloom.provider`, and (c) is authorized by an Apple-signed provisioning profile with the `aps-environment` entitlement can receive a push for our topic. AMFI enforces code signature, entitlements, and provisioning-profile validity at launch."*

That argument is correct **about the machine on which AMFI is enforcing.** The gap is that the coordinator never learns which machine that is.

### Three legs, one unverified pivot

| Leg | What proves it | Bound to a specific device? |
|---|---|---|
| **Posture** (SIP, Secure Boot, SSV) | Apple MDM `SecurityInfo`, queried through MicroMDM | Bound to the **enrolled device whose serial the provider claims** — `s.mdmClient.VerifyProvider(ctx, attestResult.SerialNumber, …)` (`api/provider.go:2689`). The serial is a field in the provider's own attestation blob. |
| **Key possession** | P-256 signature over a coordinator nonce | **No.** The SE key carries **no Apple certificate** (`SecureEnclaveIdentity` / `PersistentEnclaveKey` create a bare key). Remotely it is an ordinary P-256 key; nothing distinguishes a Secure Enclave key from `openssl ecparam`. |
| **Code identity** | APNs round-trip to a device token | **No.** `APNsDeviceToken` is copied verbatim from the provider's `RegisterMessage`/`HeartbeatMessage` (`registry/registry.go:2854`, `api/provider_codeattest.go:252`). Nothing cross-checks it against the MDM-enrolled device — not the MDM push token the coordinator already holds for that device, not the UDID, not the serial. |

The MDA leg does not close this. Its freshness nonce is `sha256(se_public_key)`, chosen **by the coordinator** and echoed by Apple into the cert (`api/provider.go:3145`). It proves *"the enrolled device answered an attestation request that was about this SE key, just now"* — a sound anti-replay check for cached chains, which is exactly where it is enforced (`attachCachedMDAProof`, `provider.go:3093`). It cannot prove the SE key resides in that device's enclave, because Apple is echoing a value the coordinator supplied, not measuring a key. And on the **fresh** path it is not enforced at all: `provider.MDAVerified = true` is set unconditionally (`provider.go:3221`), with a `Warn` log the only consequence of a mismatch. That is **F1, still open** after 15 months.

### The assembly attack

An attacker who wants to read and tamper with paid prompts needs:

1. **One clean Mac (A)** — genuinely SIP-locked, Secure-Boot-full, enrolled in Darkbloom's MDM through normal onboarding. It never runs modified code; it only answers `SecurityInfo` and `DevicePropertiesAttestation`. Its posture reports are *honest*.
2. **Machine B** — runs the attacker's own inference server. Its posture is never checked, because the coordinator is checking A's. B holds the X25519 key `K` the coordinator encrypts prompts to, and any P-256 key it likes.
3. **A push-token source** — a machine where AMFI is not enforcing (SIP disabled + `amfi_get_out_of_my_way`), running a process that claims bundle ID `io.darkbloom.provider` with `aps-environment`, to obtain an APNs device token for Darkbloom's topic. The `E_K(nonce)` payload it receives is **encrypted to the attacker's own key**, so the attacker only needs the ciphertext bytes, which they can relay to B in a second.

B connects to `/ws/provider` — **which requires no authentication whatsoever** (`handleProviderWS`, `provider.go`; `auth_token` is optional and used only for payout account linkage, `provider.go:327`) — registers claiming A's serial, self-reports every `PrivacyCapabilities` flag, the runtime hashes from the published manifest, and the token from (3). The coordinator queries MDM about A (healthy), pushes the challenge to (3)'s token, B decrypts and signs, and B is marked hardware-trusted and code-attested. Prompts route to B. Responses B returns are stamped `X-Provider-Attested: true`.

**Cost to the attacker: one idle clean Mac plus one out-of-policy machine.** No Darkbloom credential, no Apple compromise, no Developer ID.

### What we could not verify, and how they can

The load-bearing assumption is step (3): *can a process on an AMFI-disabled Mac obtain an APNs device token for another team's bundle ID?* Client-side entitlement checking is the only gate we can find in Apple's design, and disabling AMFI removes it — but we could not test this from a Linux sandbox, and we are not going to assert an Apple internal we did not observe.

**The experiment Darkbloom can run in an afternoon** (they have the Macs and the `.p8`): on a spare Mac, disable SIP and boot with AMFI off; ad-hoc-sign a trivial app with `aps-environment` and `CFBundleIdentifier = io.darkbloom.provider`; call `registerForRemoteNotifications`; if a token comes back, push to it with the production `.p8` and topic. If the push arrives, N1 is confirmed as written. If Apple refuses the registration server-side, N1 downgrades to "the binding is missing but the attack is blocked by an Apple property you are not documenting" — which is still worth documenting, because the whole guarantee then rests on it.

**Either way the fix is the same and is cheap:** bind the token to the attested device. The coordinator is already an MDM server for this Mac — it holds *its own* APNs push token for device A. Push the code-identity challenge (or a second, correlating nonce) over the **MDM** channel to A's token and require both to be answered by the same connection, or have the provider include the device token inside the SE-signed status canonical *and* require an MDA round-trip whose freshness nonce covers `sha256(se_pubkey ‖ apns_token)`. Then the three legs collapse into one identity.

### What N1 does *not* say

It does not say the APNs mechanism is worthless. Against the *straightforward* attack — patch the binary in place on your own enrolled Mac and report a blessed hash — it works, and that attack is now closed. The keychain access group (`SLDQ2GJ6TL.io.darkbloom.provider`, `PersistentEnclaveKey.swift:78`) genuinely stops a re-signed binary from reusing the real key or the SSD cache KEK, so the "run the real binary once, then swap" variant is closed too. N1 is about the *composed* system: every individual leg is sound, and the identity they add up to is not.

---

## 3. N2 — enforcement is a config flag, and the fleet argues against flipping it

`providerSupportsPrivateTextLocked` (`registry/registry.go:663`) is a genuinely well-built single chokepoint: no self-route exemption, fail-closed, consulted live so the policy can flip without a reconnect. But:

```go
func (r *Registry) codeAttestationEnforcedLocked() bool {
    if !r.codeAttestationConfigured || r.codeAttestationDeadline.IsZero() {
        return false          // ← grace: un-attested providers still route
    }
    return !time.Now().Before(r.codeAttestationDeadline)
}
```
(`registry/registry.go:1016`; deadline comes from `APNS_ENFORCE_AFTER`, `main.go:789-809`.)

Unset or future ⇒ **the code-identity gate is off and the network behaves exactly as it did in June.** `APNS_ENFORCE_AFTER` is listed in `deploy/gcp/prod/required-env-keys.txt`, so prod is *expected* to set it — but the value lives in Secret Manager and is not in the repo. **[LIVE]** `/v1/stats.code_attestation_enforced` is the only external witness, and it is a single fleet-wide boolean with no per-provider detail (`api/stats.go:262`).

The pressure against enforcing is documented in their own planning docs (`routing-v2-attestation-churn.md`, 2026-06-16): the routable pool was **≈67 of 176 providers**, and the rollout runbook expects the pool to *"grow from ~67/176"* only after `APNS_MODE=alert` — a change gated on a security sign-off checklist. Some of the shortfall is structural, not transitional:

- **Headless Macs can never attest.** APNs delivery requires a logged-in GUI session (`ProviderAppKitHost` runs an `NSApplication`); the ADR lists "headless/login-screen providers cannot receive APNs and will be derouted once enforcement begins" as an accepted negative.
- **Background push is budget-throttled** to ~2–3/hour/device, which is why there is no periodic re-challenge and why a 30-minute **reuse cache** exists — including a **cross-version** reuse path that carries a proof across a binary update without a new round-trip (`provider_codeattest.go:60-115`). The fences on that path (attestation valid, runtime verified, manifest checked, SIP challenge verified, min version, same token) are all values the provider self-reports; the only unforgeable element is the SE key, and per N1 that key is not bound to the device either.
- The alternative, `APNS_MODE=alert`, sends priority-10 pushes and is safe only because the provider never requests notification authorization — an invariant maintained by code comments and review (their INV-6), not by a platform mechanism.

None of this is dishonest — it is all written down in their own docs, which is more than most subjects manage. The devproof point is narrower: **the single most load-bearing security control in the system is a runtime configuration value that no external party can audit beyond one boolean**, and the commercial incentive (a paid network needs capacity) points the wrong way.

---

## 4. N3 — the coordinator TEE leg went from verifiable to unverifiable

This is the largest *net regression* since June, and it is the leg the June report scored **✓ verified**.

`docs/operations/eigencloud-to-gcp-migration.md` records the move off EigenCloud onto a GCP VM in Eigen's own project. `docs/operations/coordinator-deploy.md:27` describes what actually shipped:

> | Confidential compute | GCP reports AMD **SEV** with maintenance policy `MIGRATE`; Shielded VM Secure Boot, vTPM, and integrity monitoring are enabled. **Do not claim SEV-SNP for this VM.** |

Consequences, in order of importance:

1. **No published attestation, anywhere.** The June evidence — `verify.eigencloud.xyz/app/0x2ea79ae1…` with `platform: INTEL_TDX`, an `mrtd`, RTMRs, a pinned container digest and a **dated 35-entry image history** — described an app that no longer serves this traffic. There is no `/v1/coordinator/attestation` route (full route table, `api/server.go:1719-1992`), nothing in the console or landing page references EigenCloud, TDX, or SEV, and `/api/version` reports the *provider* release, not the coordinator build (`api/version handler`). An outside auditor has **no artifact at all** tying `api.darkbloom.dev` to any particular coordinator code.
2. **Memory encryption without a published measurement does not constrain the operator.** A TEE protects the guest from the *host*. What protected users from *Eigen* in June was the published image digest — the fact that swapping in a prompt-logging build would have changed a value on a public page. That constraint is gone; only the cloud-host threat is still addressed.
3. **AMD SEV is not SEV-SNP.** Plain SEV encrypts memory but does not protect its integrity, and its remote-attestation story is materially weaker than SNP's. The runbook's own target was `--confidential-compute-type=SEV_SNP --maintenance-policy=TERMINATE`; what runs is SEV with `MIGRATE`, meaning the platform may live-migrate the VM. Meanwhile the whitepaper's Table 10 still says **Intel TDX**, and `coordinator/api/server.go:11` says "GCP Confidential VM (AMD SEV)". The paper is now wrong about the deployed substrate.
4. **The confidential-boot assertion was never implemented.** The migration runbook flags it as a Phase-1 blocker in bold: *"the coordinator (or vm-startup) must verify it's actually on a confidential VM and refuse to serve if not. Omitting the flag silently produces a non-confidential VM where the host can read decrypted prompts, with zero error today."* A grep of `coordinator/` and `deploy/` for any confidential-compute assertion returns **only comments** — no check, and `deploy/gcp/bootstrap.sh:296-309` (the committed VM-create path) passes no `--confidential-compute-type` at all. Whether prod was created with the flag is invisible from the repo, and a future rebuild that drops it fails open and silent.

Fixing (1) is a day of work and would restore the strongest verifiable property the system ever had: expose the vTPM/SEV attestation and the running container digest at a public endpoint, keep an append-only history of digests, and publish the build recipe tying a digest to a commit.

---

## 5. N4 — the consumer-facing guarantees contradict the code, the threat model, and the company's own legal pages

The console's verification panel (`console-ui/src/components/verification/NormalMode.tsx:33-70`) shows four claims to every paying user:

| UI claim | Reality at this commit |
|---|---|
| **"Hardware Identity** — sealed in Apple's Secure Enclave — it can't be cloned, copied, or faked." Ticked when `trust.secureEnclave`. | That flag is the provider's **self-reported** `secure_enclave` boolean from the feed. The SE key has no Apple certificate; remotely it is an unattested P-256 key (§2). |
| **"Software Integrity** — its hash matches the signed release." Info text: *"SHA-256 hash of the provider binary is verified against the CI-signed release."* Ticked when `isHardware`. | The hash check is **default-off** and demoted to telemetry (`main.go:399`; threat model T-034: *"no longer relied on as a code-identity control"*). The tick is driven by trust level, not by any hash check. **The UI asserts precisely the control the vendor's own threat model retired — and never mentions the one that replaced it.** |
| **"Data Protection** — Your prompts are encrypted end-to-end. Not even Darkbloom servers can read them." Info: *"The coordinator only sees ciphertext."* Hardcoded `ok: true // E2E is always active`. | False as a mechanism and as a conclusion. The coordinator decrypts every request to route, meter and render prompts (`sealedTransport` middleware, `consumer.go`, and now the `promptsidecar`). Their **own Privacy Policy** says so: *"The current service architecture requires our coordinator to process request payloads in plaintext"* (`landing/privacy.html:295`), and the **Terms** cite *"the current absence of end-to-end encryption between consumer and provider"* (`landing/terms.html:196`). |
| **"Anti-Tampering** — memory is wiped after each request." | Prompt-derived KV state now **persists on the provider's SSD across requests and reboots** (encrypted, per-account scoped — see §7). The claim is stale. |

`landing/index.html:1304` still carries the June wording verbatim — *"The coordinator routes ciphertext, and only the matched provider's hardware-bound key can decrypt the request"* — so **F6 is unfixed 10 weeks later**, now on a page that sells a paid service.

Two mechanical problems in the verifier itself:

- **It can verify the wrong machine.** `useDeviceVerification.ts:32-36` looks up the serving provider by serial and falls back to `data.providers?.[0]` — *any* provider in the feed — then runs the chain check and reports success. A user whose provider is absent from the feed sees a green "Verified" for a machine that did not serve them.
- **It still stops at "genuine Apple device."** The five steps in `lib/cert-verify.ts:144-148` are parse → identity → chain → root fingerprint → confirm; the freshness OID is explicitly *filtered out as "binary data"*, so the MDA→SE binding is not checked (F5, unchanged), and there is no code-attestation check because **the feed does not carry one**.

Which is the deeper problem: **`/v1/providers/attestation` (`provider.go:3269`) does not expose `code_attested` at all** — nor `se_key_bound`, nor the SE-signed blob and signature. The response headers don't either (`X-Provider-Attested`, `-Trust-Level`, `-Mda-Verified`, `-Secure-Enclave`; `dispatch.go:2931-2951`). The public feed advertises the signals that no longer carry the guarantee and omits the one that does. Per-provider, an outsider cannot check the thing that matters.

---

## 6. Prior findings F1–F6

| # | June status | Today | Note |
|---|---|---|---|
| **F1** MDA→SE binding not gated / not published | partially fixed | **Open** | Enforced only on the cached-proof path (`provider.go:3077-3093`); the fresh path sets `MDAVerified = true` regardless and logs a warning (`provider.go:3221`). `se_key_bound` reaches only the owner's own `/v1/me/providers`, never the public feed. |
| **F2** SE-signed blob + signature absent from feed | not fixed | **Open**, partly mitigated | The blob still isn't published, so posture remains coordinator-asserted to outsiders. But `BuildStatusCanonical` (`attestation/attestation.go:390`) now brings `sip_enabled`, `binary_hash`, `model_hashes`, `runtime_hash` **inside** the SE signature over a coordinator nonce — a real fix to the signature-scope hole. (The doc comment at `attestation.go:485-505` still says these fields are *not* signed; stale and misleading.) |
| **F3** No coordinator attestation surfaced | open (infra existed) | **Worse — see N3** | The infrastructure that made it merely "unsurfaced" no longer exists. |
| **F4** Release registry has no public log | open | **Open** | `POST /v1/releases` (scoped key), `GET /v1/releases/latest` (public, single record), `GET|DELETE /v1/admin/releases` (admin only). No public history, no Sigstore, no anchor; admin DELETE still silent (`server.go:1836-1903`). Their threat model puts the release supply chain explicitly **out of scope**. |
| **F5** Client verifiers incomplete | partially fixed | **Open + new defect** | No binding check, no code-attest signal, plus the `providers[0]` fallback (§5). Still no consumer SDK enforcing anything. |
| **F6** Marketing misstates the mechanism | valid (nitpick) | **Open, upgraded to high** | Same sentence, still shipping (`landing/index.html:1304`), now contradicted by the company's own Terms and Privacy Policy, on a paid product (§5). |
| *NEW (June)* MDM webhook trust-injection | fixed in code | **Fixed** | Solicited-UUID gate + UDID cross-check retained. |
| *§1 (June)* no code identity | unfixable-as-stated | **Superseded by N1** | A real remote anchor now exists; it is unbound rather than absent. Genuine progress. |

---

## 7. What genuinely improved — credit where it is due

- **APNs code identity** (§2) — a creative, correct-in-outline use of the only Apple-gated channel available on macOS, with fail-closed handling throughout: `CodeAttested` is per-connection and never persisted; a rotated token resets it and forcibly invalidates cached proofs; a failed push clears the outstanding nonce; the SE key used for verification is the one bound at registration, never one supplied in the response (`provider_codeattest.go:230-435`).
- **Signature scope closed** — posture and hashes are now inside the SE signature over a coordinator nonce (F2 above).
- **Plaintext egress hardening (#612)** — provider inference failures now cross the boundary only as closed-vocabulary codes; free-form provider/browser telemetry and automatic log upload were removed; inline video decodes through a memory-backed asset instead of a temp file; regression tests (`InferenceFailurePrivacyTests`, `ProviderLoggerPrivacyTests`) pin the behaviour. These were real leaks and they were closed properly.
- **`mediafetch` SSRF guard** (`coordinator/mediafetch/ssrf.go`) — dial-time `Control` hook (so DNS rebinding cannot slip past a pre-flight check), IPv4-in-IPv6 unmapping, IPv6 zone stripping, and explicit denies for NAT64/6to4/Teredo/CGNAT/metadata. Better than most production SSRF filters we read.
- **Prefix-cache privacy design** (`docs/architecture/cache-aware-routing.md`) — cache scope is a domain-separated HMAC over the **authenticated account**, so the classic cross-user prefix-cache oracle is structurally excluded, not merely rate-limited; disk blocks are AES-256-GCM under a Secure-Enclave-rooted KEK with HMAC-derived filenames, closing the disk confirmation oracle. The honest caveat is the one in §5: prompt-derived state now survives the request, which the UI still denies.
- **Model weight-hash gate** — per-model aggregate hashes are refreshed from each verified challenge and gate catalog routing, so a swapped model build is a tripwire rather than a silent integrity break.
- **`docs/threat-model.yaml`** — 2,665 lines of STRIDE with per-mitigation status, open items marked open (e.g. T-034's "reproducible build + public transparency log of blessed cdhashes: **open**"), and T-042 anticipating the log/disk payload-harvest variant of the APNs attack. Very few subjects in this guide have written down where their own controls stop. It is also the reason N1 is stated the way it is: their model assumes the adversary "cannot bypass SIP, Hardened Runtime, or the Secure Enclave" **on their own machine** — N1 needs neither, because it uses a *different* machine.

---

## 8. Recommendations, ranked

1. **Bind the APNs device token to the attested device (N1).** Cheapest correct version: push a correlating nonce over the **MDM** channel — the coordinator already holds Apple's push token for that enrolled device — and require both to be answered on the same WebSocket. Alternative: fold `apns_device_token` into the SE-signed status canonical *and* into the MDA freshness nonce (`sha256(se_pubkey ‖ token)`), so Apple's signature covers the pair. Until then, do not describe the APNs round-trip as proving *which machine* runs genuine code.
2. **Restore a published coordinator attestation (N3).** Expose the vTPM/SEV quote and the running container digest at a public endpoint, keep an append-only digest history, and publish the digest→commit build recipe. Also: implement the boot-time confidential-compute assertion the runbook already specifies, and correct the whitepaper's Intel TDX claim.
3. **Fix the four UI claims and the landing-page sentence (N4).** The Terms and Privacy Policy already contain accurate language — use it. Replace "Software Integrity: hash matches the signed release" with the control that actually runs, and stop hardcoding `ok: true` on a claim that is false.
4. **Publish `code_attested` and `se_key_bound` per provider** in `/v1/providers/attestation`, add `X-Provider-Code-Attested` to responses, and have the console verify the binding (`FreshnessCode == sha256(se_public_key)`) instead of discarding it. Fix the `providers[0]` fallback to a hard failure.
5. **Gate on the MDA binding on the fresh path (F1)**, matching what the cached path already enforces.
6. **Publish `APNS_ENFORCE_AFTER`'s value and the per-cohort attestation coverage** (N2). If enforcement is deliberately off while the fleet catches up, say so on the page that sells the privacy property.
7. **Route a read-only `GET /v1/releases`** with an append-only, signed history (F4).

---

## 9. Reproducing

Source-only checks (any machine, no account):

```bash
git clone https://github.com/Layr-Labs/d-inference && cd d-inference
git checkout 232911ca690b78cbd3c8f65668d69f75a8f6bef0

# N1 — the APNs token is taken verbatim from the provider, never cross-checked
grep -n "APNsDeviceToken" coordinator/registry/registry.go coordinator/api/provider_codeattest.go
# N1 — posture is looked up by the provider's SELF-REPORTED serial
sed -n '2689,2695p' coordinator/api/provider.go
# N1 — no codesign / Team-ID / cdhash logic anywhere in the coordinator
grep -rin "codesign\|cdhash\|teamid" --include=*.go coordinator/          # → no matches
# N2 — grace is the default
sed -n '1016,1021p' coordinator/registry/registry.go
# N3 — the deployed substrate, in their words
sed -n '27p' docs/operations/coordinator-deploy.md
# N3 — no confidential-boot assertion exists
grep -rin "confidential" --include=*.go --include=*.sh coordinator/ deploy/   # → comments only
# N4 — the four UI claims, and the legal pages that contradict them
sed -n '33,70p' console-ui/src/components/verification/NormalMode.tsx
sed -n '295p'   landing/privacy.html
sed -n '1304p'  landing/index.html
```

Live checks — **not run in this pass** (`api.darkbloom.dev` was blocked by this session's egress policy):

```bash
# Is the code-identity gate actually ON? (the single external witness for N2)
curl -sS https://api.darkbloom.dev/v1/stats \
  | jq '{enforced: .code_attestation_enforced, attested: .code_attested_providers, active: .active_providers}'

# Feed: does it now carry code_attested / se_key_bound / the SE-signed blob? (N4, F1, F2)
curl -sS https://api.darkbloom.dev/v1/providers/attestation | jq '.providers[0] | keys'

# MDA→SE binding, recomputed from the feed (F1) — unchanged from the June pass
python3 verify/binding-check.py <(curl -sS https://api.darkbloom.dev/v1/providers/attestation)

# Does the coordinator publish anything about itself yet? (N3)
for p in /v1/coordinator/attestation /api/version /v1/releases; do
  printf '%-32s ' "$p"; curl -sS -o /dev/null -w '%{http_code}\n' "https://api.darkbloom.dev$p"
done
```

---

## 10. References — `Layr-Labs/d-inference` @ `232911ca`

**The code-identity mechanism (N1)**
- `docs/architecture/decisions/apns-code-attestation.md` — the design and its stated security argument.
- `coordinator/api/provider_codeattest.go:230-435` — token intake, challenge, fail-closed verification, reuse fast-paths.
- `coordinator/registry/registry.go:2854` — `APNsDeviceToken` taken verbatim from `RegisterMessage`.
- `coordinator/api/provider.go:2689` — MDM posture looked up by self-reported serial.
- `coordinator/api/provider.go:3145`, `:3221`, `:3077-3093` — MDA freshness nonce; unconditional `MDAVerified = true`; binding enforced only on the cached path.
- `provider-swift/Sources/ProviderCore/Security/PersistentEnclaveKey.swift:78` — keychain access group `SLDQ2GJ6TL.io.darkbloom.provider` (this part *is* device- and signer-bound).
- `docs/threat-model.yaml` T-034, T-042 — the vendor's own account of what the mechanism does and where they think it stops.

**Enforcement (N2)**
- `coordinator/registry/registry.go:663` (chokepoint), `:1016` (grace default).
- `coordinator/cmd/coordinator/main.go:789-809` (`APNS_ENFORCE_AFTER`), `:399` (`binaryHash` demoted).
- `docs/architecture/routing-v2-attestation-churn.md` (≈67/176), `docs/operations/routing-v2-rollout.md` Stage 5.

**Coordinator substrate (N3)**
- `docs/operations/coordinator-deploy.md:27` — "Do not claim SEV-SNP for this VM."
- `docs/operations/eigencloud-to-gcp-migration.md` — the move, and the unimplemented confidential-boot blocker.
- `deploy/gcp/bootstrap.sh:296-309` — VM create with no confidential-compute flags.
- `coordinator/api/server.go:1719-1992` — full route table; no coordinator-attestation endpoint.

**Consumer-facing claims (N4)**
- `console-ui/src/components/verification/NormalMode.tsx:33-70`; `useDeviceVerification.ts:32-36`; `lib/cert-verify.ts:144-148`.
- `coordinator/api/provider.go:3269` (feed shape); `coordinator/api/dispatch.go:2931-2951` (response headers).
- `landing/index.html:1304`; `landing/privacy.html:295`; `landing/terms.html:196`.

**Credit**
- `coordinator/attestation/attestation.go:390` — `BuildStatusCanonical`.
- `coordinator/mediafetch/ssrf.go` — the SSRF guard.
- `docs/architecture/cache-aware-routing.md`, `docs/reference/ssd-kv-cache.md` — per-account cache scope, SE-rooted KEK.
- commit `6f7960eb` (#612) — plaintext-egress hardening.
