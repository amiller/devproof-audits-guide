# NEAR AI — GPU Attestation Evasion Plan

**Frame:** devproof. The adversary is NEAR-the-provider (controls host, GPU
firmware/CC-mode settings, the inner compose, and the orchestration that
assembles `GET /v1/attestation/report`). The defenders are the verification
tools a client might run:

| | Tool | What it gates the GPU verdict on |
|---|---|---|
| T1 | `nearai-cloud-verifier` (`py`/`ts`) | `x-nvidia-overall-att-result` + `eat_nonce == request_nonce` |
| T2 | Phala `private-ai-verifier` | same (delegates to NRAS) |
| T3 | `awesome-private-inference` daily probe | same |
| T4 | `hermes-agent` near provider (strictest) | same NRAS check + Block B anchor pins + Block C inner-compose closure |

**Goal of the plan:** enumerate deployment configurations under which all of
T1–T4 return ✅ while the operator can (a) read the supposedly-private prompts
and responses, or (b) substitute the served model. The attacks below are ranked
by how many tools they defeat. The strongest two (A1, A3) defeat **all four,
including hermes**, because none of our tools inspect the GPU *sub-claims* — we
delegate the entire GPU-confidentiality verdict to NVIDIA's opaque
`overall-att-result` boolean.

---

## The structural root (why any of this works)

Three facts, all confirmed against the deployed code and live NRAS responses:

1. **We gate on one boolean.** Every tool reads `x-nvidia-overall-att-result`
   and the nonce. The full per-GPU claim set NVIDIA returns —
   `dbgstat`, `secboot`, `hwmodel`, `ueid`, `measres`, and the
   `x-nvidia-gpu-{driver,vbios}-rim-*` measurements — is **not inspected by any
   tool.** Whatever NVIDIA folds into that one boolean is the entirety of our
   GPU trust, and we have never independently established what `True` excludes.

2. **The TDX↔GPU weld is the bare nonce.** Model-CVM `report_data` is
   `signing_address ‖ nonce`; the GPU evidence commits to `nonce` only
   (`collect_gpu_evidence_remote(nonce)`, confirmed live: `eat_nonce` = the raw
   32-byte nonce). The signing/E2E key is **not** in the GPU evidence. So the
   GPU attestation and the TDX quote are joined only by a shared client nonce —
   that proves *freshness* and *co-presentation*, not *co-location* (same box)
   or *key-binding*. Contrast Chutes, which binds GPU evidence to
   `SHA256(nonce ‖ e2e_pubkey)` — one notch stronger.

3. **The enclave collects, it does not enforce.** `inference-proxy` collects
   GPU evidence and staples it into the report; `vLLM` serves unconditionally
   (healthcheck is `GET /v1/models`). There is no server-side
   "verify-then-serve." GPU confidentiality is enforced only by the in-guest
   NVIDIA driver + the host's CC-mode setting, and *verified* only client-side.

Source: `inference-proxy/src/attestation.rs:625–664`, `gpu_evidence_worker.py`,
`cvm-compose-files/gpt-oss-single.yaml`; live NRAS replays of
`attestation-captures-2026-05-05/`.

---

## Attack A1 — DevTools-mode fleet (side-channel / debug exposure) — E1 RESOLVED

**Goal:** degrade GPU confidentiality by re-opening the side-channel / profiling
attack surface that CC-On exists to close. The correct model runs; no
substitution. **Correction after E1:** this is *not* a direct plaintext memory
dump — the CPR memory encryption and AES-GCM-256 DMA stay active in DevTools.
What is lifted is the side-channel protection: CC-On disables GPU performance
counters specifically to block side-channel attacks, and **CC-DevTools
re-enables them plus profiling/debug access** (NVIDIA HCC whitepaper / gpu-admin-tools).
The exposure is profiler/debug-assisted inference inspection, not a memcpy.

**Setup recipe:** deploy the genuine, pinned compose on genuine H100s, but set
the cards to **CC-DevTools** instead of **CC-On** (`gpu-admin-tools` /
`nvidia-smi conf-compute`, mode `devtools`, GPU reset to activate). The GPU still
produces a valid, signed, RIM-matching attestation.

**Why every tool stays green:** all four read only `overall-att-result`. The
DevTools state **is** surfaced in the attestation report (NVIDIA designs it to be
detectable — via `dbgstat` / a measurement), but **none of T1–T4 inspect
`dbgstat`** or any mode field. Compose hash, TDX quote, report_data, anchors (B),
inner compose (C) are all genuine and unchanged — hermes passes too.

**What's compromised:** confidentiality margin — the side-channel surface CC-On
closes is re-opened, against a host that controls the box.

**E1 result (resolved from NVIDIA docs — see Sources):**
- *Confirmed:* CC-DevTools is a real deployable mode; it **re-enables
  performance counters / profiling** that CC-On disables for anti-side-channel
  reasons; memory stays encrypted.
- *Confirmed:* the mode **is reflected in the attestation report** ("CC DevTools
  mode shows in the attestation report when enabled, allowing detection"), so it
  is a checkable signal — NVIDIA puts the detection burden on the verifier.
- *Confirmed:* none of our tools read that signal; they gate on
  `overall-att-result` only.
- *Confirmed:* our live captures show `dbgstat=disabled` → NEAR's current fleet
  is CC-On. **A1 is latent, not active**: a config the operator can flip with no
  verifier noticing.
- *Last empirical gap:* whether NRAS's `overall-att-result` stays `True` for a
  DevTools card or flips `False`. NVIDIA's "detection is the verifier's job"
  framing strongly implies overall stays `True` (the mode is a separate claim,
  not an auto-fail), but confirming needs a physical DevTools card.

**Verdict:** **confirmed verifier blind-spot.** A1 is no longer speculative — the
degraded mode is real, deployable, and *detectable in the very report we fetch*,
and we simply don't look. Not a crypto break; a "we ignore a claim NVIDIA hands
us" gap.

**Closure (one line):** verifiers must assert `dbgstat == "disabled"` **and**
`secboot == True`, and require CC-On (reject DevTools); or run NVIDIA's `LOCAL`
verifier with a pinned policy instead of trusting the hosted `overall` boolean.
(Mirrors Chutes F4's "offer the LOCAL verifier" fix.)

---

## Attack A2 — Decoy-GPU attestation (nonce-only weld)

**Goal:** run actual inference on non-confidential or cheaper hardware while
presenting genuine CC-On attestations harvested elsewhere — confidentiality leak
and/or cost fraud.

**Setup recipe:** because the GPU evidence is bound only to the nonce, the
report-assembling code can collect genuine CC-On evidence from one source
(a dedicated attestation-oracle box, or the CC-On subset of cards) while the
`/v1/chat/completions` path computes on a different, host-readable GPU. Both the
TDX quote and the GPU evidence carry the same client nonce, so the bundle is
internally consistent.

**Why tools stay green:**
- T1/T2/T3: check only nonce-match + `overall=True`. The relayed evidence is
  genuine and shares the nonce. They never verify "the GPU that computed ==
  the GPU that attested." **Defeated.**
- T4 (hermes): pins app_id/compose/os_image and closes Block C, so the
  report-assembling `inference-proxy` is the audited binary, and audited code
  collecting evidence from its *local* GPUs implies same-box for the *evidence*.
  This defeats the **separate-box** variant. It does **not** defeat the
  **same-box mixed-mode** variant: nothing in the bundle enumerates which GPU
  `ueid`s vLLM actually ran on, so attesting the CC-On cards while computing on a
  CC-Off/DevTools card in the same chassis is invisible. (And A2-same-box
  reduces to A1 if the compute card is DevTools.)

**What's compromised:** confidentiality (compute on host-readable GPU) and/or
honest-hardware claims.

**Confirmed vs pivotal:**
- *Confirmed:* the weld is nonce-only (code + live `eat_nonce`); no tool checks
  compute-GPU `ueid` against evidence `ueid`.
- *Pivotal:* whether a single CVM can simultaneously hold CC-On and non-CC GPUs
  and still produce a clean all-GPU PASS (if every visible GPU must attest, a
  CC-Off card in the same CVM would fail collection and break the bundle —
  pushing the adversary toward A1/DevTools instead). See **Experiment E2**.

**Closure:** bind GPU evidence to the signing key (`SHA256(nonce ‖ pubkey)`,
Chutes-style), **and** have the audited inference-proxy include the vLLM compute
GPU `ueid`s in its measured report_data, cross-checked against the evidence
`ueid`s. This upgrades the weld from "shared nonce" to "same enumerated cards,
bound to the E2E key."

---

## Attack A3 — Multi-GPU fabric not attested (PPCIE off)

**Goal:** for multi-GPU tensor-parallel models, expose cross-GPU activations
(which carry prompt/response representations) to a host that can snoop the
NVLink/PCIe fabric.

**Setup recipe:** serve a multi-GPU model (`GLM-5.1`, `DeepSeek-V3.1`,
`Qwen3.5-122B`) exactly as deployed today. Evidence is collected in standalone
per-GPU mode (`ppcie_mode=False`, attestation.rs:648). Each card attests CC-On
and green; the inter-GPU fabric has no attestation in the bundle.

**Why every tool stays green (confirmed empirically):** replayed the 8-GPU GLM
payload through NRAS → `overall=True`, 8 green submodules, and the **union of
all claim keys across all 8 GPUs contains no fabric / NVLink / PPCIE / topology
claim.** No tool could check it because it isn't there. Hermes included.
**Defeats all four** for multi-GPU models.

**What's compromised:** confidentiality of cross-GPU traffic — *if* CC-On
single-GPU mode leaves NVLink peer traffic unprotected.

**Confirmed vs pivotal — important honesty note:** `ppcie_mode=False` is the
*evidence-collection* flag (the in-tree comment: "required on PPCIE systems… safe
on non-PPCIE too"), **not** proof the hardware fabric runs unprotected. What is
confirmed is only that **the attestation bundle contains no fabric protection
claim**, so a client cannot tell a protected fabric from an unprotected one.
Whether the NVLink traffic is actually plaintext under CC-On-without-PPCIE is
**unverified** and must not be asserted. See **Experiment E3**.

**Closure:** require PPCIE/multi-GPU CC for tensor-parallel models and surface an
explicit fabric-protection claim that verifiers assert; until then, document that
multi-GPU models carry an unattested fabric assumption.

---

## Attack A4 — Model substitution / unmeasured decryptor (compose context)

Included for completeness — this is the **already-documented Critical**
(inner-compose not in RTMR3; the code that decrypts prompts is unmeasured) and it
*composes* with the GPU attacks. Against T1/T2/T3 (which do **not** close Block
C), the operator swaps the inner model YAML, decrypts with the hardware-bound key
inside a modified `inference-proxy`, and leaks plaintext or serves a substituted
model — TDX + GPU attestations stay green throughout (model_name is self-asserted
by the proxy in the signed `"{model_name}:{req}:{resp}"` string). **Hermes (T4)
closes this** via Block B/C. The significance for *this* plan: A1 and A3 are the
attacks that survive **even hermes**, precisely because they live in the GPU
sub-claims that Block B/C never reach.

---

## Tool-defeat matrix

| Attack | T1 nearai-verifier | T2 phala-verifier | T3 awesome-probe | T4 hermes |
|---|---|---|---|---|
| A1 DevTools fleet | ✅ green | ✅ green | ✅ green | ✅ green* |
| A2 decoy-GPU (separate box) | ✅ green | ✅ green | ✅ green | ❌ caught (compose/os pin) |
| A2 decoy-GPU (same-box mixed) | ✅ green | ✅ green | ✅ green | ✅ green* |
| A3 PPCIE-off fabric (multi-GPU) | ✅ green | ✅ green | ✅ green | ✅ green* |
| A4 substitution / unmeasured decryptor | ✅ green | ✅ green | ✅ green | ❌ caught (Block B/C) |

`✅ green` = attack succeeds, tool reports fine. `*` = survives hermes. A1 is a
**confirmed** blind-spot (E1 resolved; only the NRAS-overall-True residual is
unconfirmed). A2-same-box / A3 survive hermes conditional on E2 / E3.

**Sources (E1):**
[NVIDIA HCC Whitepaper WP-11459](https://images.nvidia.com/aem-dam/en-zz/Solutions/data-center/HCC-Whitepaper-v1.0.pdf) ·
[NVIDIA/gpu-admin-tools](https://github.com/NVIDIA/gpu-admin-tools/blob/main/README.md) ·
[NVIDIA Attestation Claims schema](https://docs.nvidia.com/attestation/nv-attestation-sdk-cpp/latest/sdk-c/claims_schema.html) ·
[NVIDIA GPU-CC Demystified (arXiv 2507.02770)](https://arxiv.org/html/2507.02770v1) ·
live NRAS replays of `attestation-captures-2026-05-05/`.

---

## Pivotal experiments (run these before publishing any as a confirmed break)

**E1 — DevTools verdict. ✅ RESOLVED (from NVIDIA docs).** CC-DevTools is a real
mode that re-enables performance counters / profiling (side-channel surface
CC-On closes); memory stays encrypted. The mode **is surfaced in the attestation
report** and is meant to be checked by the verifier; NVIDIA's claim schema has
**no** CC-mode claim, only `dbgstat`/`secboot`. Our tools check neither. Residual
empirical gap (needs a physical DevTools card, not blocking): confirm whether
NRAS `overall-att-result` stays `True` for DevTools — strongly implied yes.

**E2 — Mixed-mode CVM.** Can one TDX CVM hold both CC-On and non-CC GPUs and
still produce an all-GPU NRAS PASS? Determines whether A2-same-box is realizable
or collapses into A1. *Owner action:* read `cc_admin.collect_gpu_evidence_remote`
enumeration behavior; confirm whether a non-CC card in the set aborts the bundle.

**E3 — Fabric exposure.** Under CC-On without PPCIE, is NVLink peer traffic
encrypted? Determines whether A3 is a real leak or only a
"missing-claim/unverifiable" finding. *Owner action:* NVIDIA CC multi-GPU
threat-model docs; do not assert without this.

---

## Closure summary (what NEAR + our verifiers should do)

For NEAR (provider side):
- Attest CC-mode explicitly (On vs DevTools) and `dbgstat=disabled`; require
  CC-On for serving.
- Bind GPU evidence to the signing key (`SHA256(nonce ‖ pubkey)`), not the bare
  nonce; include compute-GPU `ueid`s in measured report_data.
- Use PPCIE for multi-GPU models and surface a fabric-protection claim.

For our tools (T1–T4):
- Stop gating on the single `overall-att-result` boolean. Assert the
  sub-claims we actually depend on: `dbgstat`, `secboot`, per-card `ueid`
  set, and (when available) a CC-mode/fabric claim. Prefer NVIDIA's `LOCAL`
  verifier with a pinned policy so "what `True` means" is ours, not NVIDIA's.
- Cross-check the attested GPU `ueid`s against the GPUs the response claims to
  have run on, once NEAR exposes them.

**One-line thesis:** every NEAR verifier today reduces GPU confidentiality to a
single NVIDIA-issued boolean and a freshness nonce; the provider can satisfy both
while running the cards in a host-readable mode or on un-welded hardware, so a
green check proves the GPUs are *genuine and fresh* — not that the host is
cryptographically locked out of where the prompt is decrypted.
