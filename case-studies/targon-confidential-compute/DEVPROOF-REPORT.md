# Targon (SN4) Confidential Compute — DevProof Audit

**Audit date:** 2026-05-25
**Target:** Targon — Bittensor **subnet 4**, by **Manifold Labs**. "Confidential Decentralized AI Cloud": a GPU-rental auction marketplace on **Intel TDX + NVIDIA Confidential Compute** (Hopper H100/H200, Blackwell B200) and **AMD SEV-SNP** (CPU-only). Co-authored an Intel TDX whitepaper.
**Repo (HEAD at clone):** `manifold-inc/targon` `46c5e47` (2026-05-21, published squashed). Mostly Go.
**Deleted upstream:** `Manifold-Archive/targon-hub-api` (the older inference-API product) — 404 as of audit date.
**Manifold-operated services (hardcoded):** `tower.targon.com` (attestation verdict + auctions), `tvm.targon.com` (image gateway), `stats.targon.com`.

This is a **devproof** audit: the question is whether Targon's confidentiality / "verifiable, trustworthy, decentralized" claims are *externally verifiable by a relying party without trusting Manifold* — not whether the system is "secure" in the abstract. Findings are framed as verifiability gaps suitable for public issues.

---

## Quick Status

| Property | Verifiable without trusting Manifold? | Notes |
|---|:--:|---|
| Genuine Intel TDX + NVIDIA CC hardware exists | ⚠️ | real DCAP/NRAS underneath, but verdict only via Tower |
| TDX quote verdict (DCAP, debug-off, MRTD/RTMR match) | ❌ | **F1** — delegated to `tower.targon.com`, returns only `{valid:bool}` |
| Client / renter receives any quote | ❌ | **F2** — attestation is validator↔miner↔Tower; user never in the loop |
| E2E encryption of the workload/prompt | ❌ | **F2** — none in the repo (no ML-KEM-equivalent) |
| Which model / code runs in the CVM | ❌ | **F3** — `user_data` binds no workload identity |
| Golden measurements / CVM image provenance | ❌ | **F4** — image is a Manifold-built encrypted qcow2; agent in no repo; no published MRs |
| Provisioning gated on a hardware quote | ❌ | **F5** — gated on a self-reported host-posture report (`tvm/install`) |
| Quote freshness / nonce ↔ report_data binding | ❌ | **F6** — local check is a JSON string-compare; binding is Tower's job |
| Emission / price / burn policy | ❌ | **F7** — pulled from `tower.targon.com/api/v2/auctions` |
| Per-VM disk key (vs fleet-wide static) | ✅ | **credit** — random per-VM key in ITA-KBS, better than the Chutes cohort |
| Anti-clone (IP binding) | ✅ | **credit** — but protects emissions integrity, not the user |

---

## TL;DR

Targon's **hardware root is real** — it runs genuine Intel TDX + NVIDIA CC nodes, verified through **Intel Trust Authority (ITA)** and NVIDIA NRAS, with sensible operator-side hardening (per-VM disk keys in a Key Broker Service, IP-bound anti-cloning, unified CPU+GPU attestation, ~72-min re-attestation). As an **incentive mechanism** — "should this miner earn emissions for running real confidential hardware?" — the design is credible.

But measured against the **devproof bar** — "verify without trusting us" — it fails at every layer, because **every verdict is centralized in Manifold's closed `tower.targon.com`**:

1. **F1 — the attestation verdict is a boolean from Tower (Critical).** Validators forward the opaque quote to `tower.targon.com/api/v1/verify-attestation` and trust `{valid: bool}`. There is **zero** local quote crypto in the entire Go tree (no DCAP, MRTD, RTMR, report_data, or JWT parsing). ITA produces a signed JWT; Tower strips it and never passes it back. A compromised or dishonest Tower can bless any node, network-wide.
2. **F2 — the user is never in the attestation loop, and there is no E2E channel (High).** The whole protocol is validator↔miner↔Tower. The renter whose data runs on the GPU receives no quote and no encrypted channel; their confidentiality rests entirely on trusting Manifold's control plane to place them on a genuine node.
3. **F3 — no workload/model identity is measured (Medium–High).** The quote covers Manifold's base boot chain only; `user_data` binds node/GPU/auction metadata but nothing about the code or model running inside.
4. **F4 — the CVM image and in-CVM agent are closed and non-reproducible (High).** The image is a Manifold-generated **encrypted** qcow2; the agent that produces quotes lives inside it; the host tool ships as a stripped binary. No golden MRTD/RTMR is published, no reproducible build, no transparency log.
5. **F5 — initial provisioning is gated on a *self-reported host-posture report*, not a quote (Medium).**

The shape is the mirror image of [Chutes](../chutes-confidential-inference/DEVPROOF-REPORT.md): Chutes exposes a **client-verifiable quote + ML-KEM E2E** but rolls its own measurement registry (TOFU on golden values); Targon uses a **real verification service (ITA)** but exposes **no client-facing artifact at all** and adds no E2E. Both fall short of the dstack cohort's on-chain KMS/compose registry + reproducible MRs.

---

## Architecture

The whole subnet is an attestation-gated **GPU-rental auction**. There is no inference path in this repo (`grep` for `completion|chat|inference|openai|prompt|/v1/` over the Go tree is empty); the old inference hub (`targon-hub-api`) is deleted.

```
                         ┌──────────────── Manifold Labs (the trust root you can't verify) ───────────────┐
                         │  tvm.targon.com   — generates per-VM ENCRYPTED qcow2, holds golden values       │
                         │  tower.targon.com — holds ITA API keys; returns {valid:bool}; sets auctions/burn │
                         │  ITA-KBS          — per-VM disk key, released post-attest, IP-bound              │
                         └────────▲───────────────────────────────▲────────────────────────────────────────┘
   host-posture report           │ /api/cvm/generate              │ /api/v1/verify-attestation  (verdict)
   (8 BIOS/kernel checks) ───────┘                                │ /api/v2/auctions            (prices/burn)
        via tvm/install (closed)                                  │
                                                                  │
   validator (in its own Manifold CVM) ── GET /cvm ──► miner axon (lists CVM node IPs; vpermit+stake gated)
        │  nonce = sha256(vali_ss58)[:16]+uuid                         │
        │  POST {nonce} ─────────────────────────────────────────────►│  in-CVM agent  http://node:8080/api/v1/evidence
        │  ◄──────────────── {quote (opaque), user_data} ─────────────┘  (agent is baked INSIDE the encrypted image)
        │  local check: user_data.nonce == sent nonce   ← the ONLY client-side check
        └─ POST quote ► tower.targon.com ─ trusts {valid:bool} ─ passing nodes win auction emissions

   RENTER / inference user ─────────────────────────────────────────────► (not in this picture at all)
        receives no quote, no E2E key — trusts Manifold to place them on a genuine node
```

**Trust boundary in one line:** TDX/CC protects a workload from the **GPU host/provider**; it does **not** protect the renter from **Manifold** (Tower + TVM gateway + KBS + validators), who control verdict, image, keys, and economics — and who is exactly the party the "trustless / verifiable / decentralized" marketing says you needn't trust.

---

## Findings

### F1 — The attestation verdict is a boolean from a closed central service (Critical)

**Claim audited:** "verifiable and trustworthy operations … in a decentralized fashion" (README); remote attestation gives hardware-rooted, independently checkable assurance.

**Finding:** the validator performs **no cryptographic verification of the quote**. `Attester.VerifyAttestation` (`targon/internal/cvm/cvm.go:175-230`) marshals the attestation, does one local check — `nonce != attestRes.UserData.Nonce` (`:184`) — then POSTs the whole thing to `https://tower.targon.com/api/v1/verify-attestation` (`:190`) and trusts the reply `GPUAttestationResponse{Valid bool, Error string}` (`targon/internal/targon/types.go:32-35`); `!Valid` → reject (`:227`). The `quote` is an opaque base64 string the validator never parses. A grep for `dcap|sgx|report_data|mrtd|rtmr|ita|jwt|x509|ecdsa|measurement` across the entire Go tree returns **nothing**.

Per the whitepaper, Tower holds the ITA API keys, forwards the quote to ITA, and ITA returns **a signed JWT** — an artifact any relying party could verify against Intel's public keys offline. **Targon discards that JWT**: the validator receives only Manifold's unsigned boolean. The GPU NRAS tokens *do* ride along in `user_data.attestation` (`types.go:68-79`) but are likewise never verified locally — only Tower's verdict counts.

**Impact:** the entire network's belief that miners run genuine, non-debug TDX+CC hardware reduces to **"Tower said true."** A compromised, coerced, or buggy Tower can mark arbitrary nodes valid (or invalid) for every validator simultaneously, with no detectable artifact. This is a single, closed, off-chain, non-reproducible trust root under one company's control — the opposite of the decentralization claim. **Severity: Critical** for the stated posture.

**Fix:** have Tower return the **ITA-signed JWT** (and the NRAS JWTs) to the validator, and verify them client-side against Intel/NVIDIA roots; publish the expected measurement policy so the JWT claims can be checked against known-good values. Better: let validators call ITA directly (the "validators don't have ITA keys" constraint is a business decision, not a technical one).

### F2 — No client/renter-facing attestation, and no end-to-end encryption (High)

**Finding:** attestation is exclusively a **validator↔miner↔Tower** protocol (`callbacks/cvms.go: getPassingAttestations`). The renter — whose data actually runs inside the CVM — is never issued a nonce, never sees a quote, and has no attested key to encrypt to. There is **no end-to-end encryption of the workload** anywhere in the repo (contrast Chutes' in-TD ML-KEM-768 keypair with `report_data[0:32]=SHA256(nonce‖pubkey)` binding). Re-attestation every ~72 min (`callbacks.go`, 361-block interval) is a *liveness/emissions* check, not a per-session user proof.

**Impact:** a renter's confidentiality depends on **trusting Manifold's control plane** to (a) actually schedule them onto an attested node and (b) not interpose. The TEE defends against the GPU host, but the relying party gets no cryptographic evidence that *their* session landed in a genuine enclave. This is the gap between "the network knows node X is genuine" and "I can prove my workload ran on a genuine node." **Severity: High.**

**Fix:** expose a renter-facing attestation handshake (issue a renter nonce → return quote bound to a session/transport public key) and an E2E-encrypted channel terminated *inside* the CVM, so the renter — not just validators — can verify-then-use.

### F3 — Workload / model identity is not measured (Medium–High)

**Finding:** `user_data` (`types.go:54-65`) carries `gpu_cards`, `cpu_cards`, `node_type`, `attestation` (NVCC tokens), `auction_name`, `nonce`, `cvm_id`, `quote_type` — and **nothing identifying the code, container, or model** running in the CVM. The TDX measurements cover Manifold's base Ubuntu 24.04 boot chain only. A passing attestation proves "a genuine CC box booted Manifold's blessed image," not "running workload/model X."

**Impact:** same model-/code-substitution family as our [NEAR-AI](../near-ai-private-inference/) and [Chutes F1](../chutes-confidential-inference/DEVPROOF-REPORT.md) findings. For a pure rental product this is partly expected (the renter brings the workload) — but combined with F2 the renter can't even verify the *base* measurement, so nothing about what runs is ever surfaced to them. **Severity: Medium–High** depending on whether Targon markets per-workload integrity.

**Fix:** extend a workload digest (`SHA256(image‖model‖revision)`) into an RTMR or `report_data` and surface it; publish expected per-workload values.

### F4 — CVM image and in-CVM agent are closed and non-reproducible; no golden values published (High)

**Finding:** the CVM is a **per-VM encrypted (LUKS) qcow2 generated server-side** by the Image Gateway (`tvm.targon.com/api/cvm/generate`) and bound to the provider IP. The **attestation agent** that answers `/api/v1/evidence` lives *inside* that encrypted image and is in **no public repo**. The host tool that pulls it, `tvm/install`, ships as a **stripped Go ELF binary** (8.2 MB, `BuildID e8f5df5b…`; embedded module `HostVerification/…`) — no source. There is **no published MRTD/RTMR golden set, no `dstack-mr`-equivalent, no reproducible build, no transparency log.** The whitepaper says the pipeline "deterministically computes the expected measurement and records it in KBS" — entirely inside Manifold's infrastructure. Even the **validator** runs inside a Manifold-pulled CVM (`docs/validator/validator.md`).

**Impact:** even if you fully trusted Tower's verdict (F1), you still cannot know *what image* was measured — no operator-backdoor review, no "is prompt logging absent" check, no version history. Textbook TOFU, but worse than Chutes (which at least publishes its golden MRTD/RTMRs via `/servers/tee/measurements`): Targon publishes none, and the agent and image are closed and encrypted. **Severity: High.**

**Fix:** publish the guest-image + agent source and a reproducible build that recomputes MRTD/RTMR0-2; publish the accepted measurement set with version history and anchor it (on-chain / transparency log).

### F5 — Provisioning is gated on a self-reported host-posture report, not a hardware quote (Medium)

**Finding:** `tvm/install` is fundamentally a **host-configuration checker + provisioner**, not a quote verifier. Its 8 checks (embedded `checker/{bios_info,cpu_cc,cpu_info,cpu_vendor,secureboot,security,os_support,tpm}.go`; strings `crypto_config_check`, `Intel TDX supported`, `seam_loader_enabled`, `Secure Boot is disabled`, `MANIFOLD HOST VERIFICATION REPORT`) inspect the host's own BIOS/kernel posture. The flow (`client/attestation_client.go`): `VerificationReport.ToAttestationRequest` → `SubmitReport` → receive `attest_token` (`json:"attest_token"`) → `GetVMStatus` → `DownloadVM`. So the decision *"does this host get a CVM image?"* is gated on a **self-reported report produced by a closed tool running on the untrusted host**. The hardware quote is only enforced *later*, by the in-CVM agent during validator re-attestation.

**Impact:** the provisioning gate is softer than "hardware attestation" implies; it leans on the integrity of a tool the host operator controls, plus whatever server-side `PrevalidateAttests` / `CheckNonZeroSender` (epistula) logic Tower runs. Bounded — the later in-CVM quote is the real gate for emissions — but worth stating so the "attested from boot" framing isn't over-read. **Severity: Medium.**

### F6 — Quote freshness is delegated; the local nonce check is a JSON string-compare (Medium)

**Finding:** the validator's sole local freshness check is `nonce != attestRes.UserData.Nonce` (`cvm.go:184`) — comparing the nonce it sent to the nonce the node **echoed back as a JSON field**, *not* to the quote's `report_data`. Whether the nonce is actually bound into the TDX quote (and the GPU evidence) is — if checked at all — Tower's job. A node could echo the right nonce in JSON while presenting a stale/forged quote and the validator would not catch it; replay protection rests entirely on Tower (compounding F1). **Severity: Medium.**

**Fix:** parse the quote client-side and assert `report_data` embeds the validator nonce (and the GPU evidence nonce), independent of the JSON echo.

### F7 — Emission, price, and burn policy are dictated by Tower (Medium / informational)

**Finding:** auction prices, target cluster sizes, and the burn distribution are pulled from `tower.targon.com/api/v2/auctions` (`internal/tower/tower.go:50,56`; consumed in `callbacks.go` → `TaoPrice`, `Auctions`, `BurnDistribution`). So Manifold's central service controls **both** which nodes pass attestation (F1) **and** the economic split that turns those verdicts into TAO. **Severity: Medium** — beyond the security model, the "decentralized" claim is undercut at the incentive layer too.

### Credit (genuine improvements over the cohort)

- **Per-VM random disk key** in the ITA Key Broker Service, released only after attestation and bound to the requesting agent (whitepaper) — strictly better than Chutes' single static fleet-wide `LUKS_PASSPHRASE` ([Chutes F5](../chutes-confidential-inference/DEVPROOF-REPORT.md)).
- **IP-bound anti-clone**: KBS records the provider IP on first attestation; an IP change permanently bricks the VM — sound anti-Sybil for emissions integrity (though it protects the *network*, not the renter).
- **Unified attestation**: NVIDIA NRAS GPU/switch tokens nested in the TDX quote `user_data`, tying the GPUs and CPU TD to one machine/session.
- **Uses Intel Trust Authority** (a real DCAP verification service) instead of a hand-rolled parser — the verification is plausibly *sound*. The entire problem is that it's **locked behind Tower with no artifact passed to the relying party** (F1).

---

## Stage Assessment

Against the framework's external-verifiability rubric:

- **Confidentiality (operator can't read the workload):** for the **GPU host/provider**, yes — TDX + CC + per-VM keys + IP binding are real. For **Manifold**, **not verifiable**: no client-facing quote and no E2E channel (F2), so the renter trusts the control plane by construction.
- **Integrity / "right code & hardware":** does **not** reach the cohort's posture. The hardware verdict is a Tower boolean (F1), the image/agent/golden-values are closed and non-reproducible (F4), and no workload identity is measured (F3). A relying party gets *no* independently checkable artifact end-to-end.

**Net:** the hardware root and the operator-incentive design are credible, and several choices (per-VM keys, IP binding, ITA, unified attestation) are ahead of the Chutes cohort. But Targon is built as a **trust-Manifold** system wearing **trustless/verifiable/decentralized** marketing: verdict, image, keys, freshness, and economics all live behind closed Manifold services, and the end user is never handed a single thing to verify. The cheapest high-value fix by far is **F1** — pass the ITA-signed JWT through and let relying parties check it.

---

## Recommendations (priority order)

1. **(F1)** Pass the **ITA-signed JWT** (and NRAS JWTs) back to validators and verify them client-side against Intel/NVIDIA roots; or let validators call ITA directly. This alone converts "trust Tower" into "trust Intel," which is the actual hardware root.
2. **(F4)** Publish the guest-image + agent source and a reproducible build (a `dstack-mr`-style MRTD/RTMR recomputation); publish the accepted measurement set with version history and anchor it.
3. **(F2)** Add a renter-facing attestation handshake + an E2E channel terminated inside the CVM, so the user — not just validators — can verify-then-use.
4. **(F6)** Verify `report_data` ↔ nonce binding client-side, not via the JSON echo.
5. **(F3)** Measure and surface a workload/model digest.
6. **(F7)** Move auction/burn policy to a public, on-chain, or at least independently auditable source.

---

## Reproduction

```bash
# 1. Clone (squashed single commit)
git clone --depth 1 https://github.com/manifold-inc/targon.git refs/targon

# 2. Confirm there is NO inference path and NO local quote crypto
grep -rniE "completion|chat|inference|openai|prompt|/v1/" --include=*.go refs/targon         # → empty
grep -rniE "dcap|sgx|report_data|mrtd|rtmr|ita|jwt|x509|ecdsa|measurement" --include=*.go refs/targon  # → empty

# 3. The verdict delegation (the whole audit in one function)
sed -n '175,230p' refs/targon/targon/internal/cvm/cvm.go     # POST tower.targon.com, trust {valid:bool}

# 4. user_data carries no workload identity
sed -n '54,79p' refs/targon/targon/internal/targon/types.go

# 5. The closed host tool: what it actually checks + where it submits
strings -n 8 refs/targon/tvm/install | grep -E "HostVerification/.*\.go|/api/cvm|attest_token|HOST VERIFICATION"

# 6. Live auctions (also the verdict service)
curl -s https://tower.targon.com/api/v1/auctions | jq .
```

---

## Source

| Path | Role |
|---|---|
| `manifold-inc/targon@46c5e47` `targon/internal/cvm/cvm.go` | validator attester; **delegates verdict to Tower** (`:184`,`:190`,`:227`) |
| `…/internal/targon/types.go` | `AttestationResponse`, `GPUAttestationResponse{Valid bool}`, `UserData` (no workload id) |
| `…/internal/tower/tower.go` | Tower client; `/api/v2/auctions`, in-CVM `/api/v1/evidence` |
| `…/internal/callbacks/cvms.go`, `callbacks.go` | `getPassingAttestations`; emission/auction wiring |
| `miner/cmd/miner/miner.go` | miner axon `GET /cvm` → lists CVM node IPs (vpermit+stake gated) |
| `tvm/install` (stripped ELF) | closed host-posture checker + VM provisioner; `HostVerification/…` |
| `docs/{miner,validator}/*.md` | auction model, `tvm.targon.com` provisioning, validator-in-CVM |
| Whitepaper | manifold.inc/releases/intel-whitepaper — ITA/KBS, per-VM key, IP binding, 72-min re-attest |

## Prior art / cross-references

- Mirror-image of [chutes-confidential-inference](../chutes-confidential-inference/DEVPROOF-REPORT.md): Chutes = client-verifiable quote + ML-KEM E2E but TOFU golden values; Targon = real ITA verification but **no** client artifact and **no** E2E.
- Model/code-substitution gap (F3): [near-ai-private-inference](../near-ai-private-inference/), [redpill-federated-inference](../redpill-federated-inference/).
- Reproducible-MR baseline (what F4 lacks): the dstack cohort (`dstack-mr`, `meta-dstack`, on-chain KMS/compose registry).
