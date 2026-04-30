# ERC-733 stage analysis & multi-vendor lock-in — Tinfoil Containers

**Companion to:** [`DEVPROOF-REPORT.md`](DEVPROOF-REPORT.md), [`ARCHITECTURE-VS-DSTACK.md`](ARCHITECTURE-VS-DSTACK.md)
**Date:** 2026-04-30
**ERC-733 source:** [`framework/STAGE-1-CHECKLIST.md`](../../framework/STAGE-1-CHECKLIST.md), [`references/erc733-summary.md`](../../references/erc733-summary.md), [draftv4.erc733.org](https://draftv4.erc733.org)

This is a structured ERC-733 walkthrough for the Tinfoil-Containers third-party deploy product, plus the answer to "where is the platform locked in vs swappable?". It supersedes the brief Stage Assessment in [`DEVPROOF-REPORT.md`](DEVPROOF-REPORT.md#stage-assessment).

---

## Multi-vendor & bring-your-own — what's swappable today

| Layer | Vendor options | Swappable? |
|---|---|---|
| **TEE hardware** | AMD SEV-SNP, Intel TDX (with NVIDIA H100/H200/B200 confidential compute) | Yes — both are first-class. Operator picks via `--host` (or controlplane picks one matching the request) |
| **Container image registry** | `ghcr.io`, `gcr.io`, Docker Hub | Yes — three configurable; per-org enabled for private |
| **Container image** | Any sha256-pinned image | Yes — strictly content-addressed; bring whatever |
| **Custom domain** | Any DNS provider; CNAME / TXT verification | Yes via `--custom-domain` (but routing still goes through `*.containers.tinfoil.dev` infrastructure) |
| **Config repo** | **GitHub only** | No — Sigstore identity policy in `tinfoil-go`'s verifier matches `^https://github\.com/<org>/<repo>/.github/workflows/.*@refs/tags/.*` (see [`tinfoil.py`](https://github.com/amiller/awesome-private-inference/blob/main/verifiers/tinfoil.py) and [`sigstore.go:84-93`](https://github.com/tinfoilsh/tinfoil-go/blob/main/verifier/sigstore/sigstore.go#L84-L93)). Forking the verifier to accept Gitea / GitLab / self-hosted git would work but isn't a configurable knob |
| **Code-measurement signer** | GitHub Actions OIDC for `tinfoilsh/measure-image-action` | Forkable but not configurable; running the action in a TEE itself isn't documented |
| **Verification CDN** | `atc.tinfoil.sh`, `github-proxy.tinfoil.sh`, `tdx-proxy.tinfoil.sh` (and presumably an AMD KDS proxy) | In principle swappable per-client by overriding URLs in the SDK, but no documented config knob; the SDKs hardcode these |
| **Hardware operator** | **Tinfoil only** | No — no host marketplace; you cannot bring SEV-SNP machines or rent from someone else |
| **Controlplane** | **`api.tinfoil.sh` only — closed source** | No — `gh api repos/tinfoilsh/controlplane` returns 404; no path to self-host or rotate operators |

### Self-hosting story

Theoretically possible because `tinfoilsh/cvmimage` and `tinfoilsh/measure-image-action` are open-source. Required to actually do it:

1. Own SEV-SNP or TDX hardware
2. Own provisioning system replacing the closed controlplane (writes the attested config disk + external-config disk; manages CVM lifecycle)
3. Fork of `measure-image-action` for your repo, OR fork the verifier's identity policy to accept your action
4. Distribution of your verifier fork to clients

Realistically, "self-hosted Tinfoil" means "you're building your own TEE platform that happens to share the cvmimage base." Compare to dstack, which has documented self-host paths via `dstack-vmm` + your own KMS contract.

### Bring-your-own summary

- **Yes BYO**: hardware vendor (within AMD SEV / Intel TDX), container registry credentials, container image, domain
- **No BYO**: code repo (GitHub-only), code-measurement signer (Tinfoil's action), verification infrastructure (Tinfoil's CDN), hardware operator (Tinfoil-only), controlplane (closed)

The **lock-in is operational, not cryptographic.** The cryptographic primitives (SEV report, Sigstore signature, EHBP) are open and reproducible. The orchestration layer that ties them together — provisioning, hosts, secret store, billing — is Tinfoil-controlled and not a market.

---

## ERC-733 Stage 1 walkthrough

Stage 1 ("Dev-Proof") requires that the developer can't unilaterally alter, censor, or exfiltrate sensitive data without a notice period. Failing any of the seven Stage 1 requirements drops the platform to Stage 0.

### 1. Enclaves are attested on-chain

**Status: ❌ Fail (strict reading) / ⚠️ Conditional pass (liberal reading)**

Tinfoil's attestation chain ends in Sigstore (Fulcio CA + Rekor transparency log + GitHub Actions OIDC), not in a blockchain. The ERC-733 spec language reads "Enclaves are attested on-chain"; the project's own checklist allows "OR equivalent transparency." Sigstore + Rekor is a transparency log with publicly auditable history. So:

- Strict reading: **Fail** — no chain anchor, no on-chain compose hash registry.
- Liberal reading: **Conditional pass** — Sigstore + Rekor is "equivalent transparency" in the same sense the checklist allows, but the trust roots are TUF-rooted (Sigstore's root keys) rather than chain-anchored.

The pragmatic take: this requirement was written for dstack-style platforms where on-chain anchoring was the default reference design. Tinfoil chose a different transparency mechanism. Whether it satisfies the *spirit* of the requirement is a values judgment about whether GitHub-Actions-OIDC + Sigstore is acceptable as a trust root.

### 2. Project code is auditable through open-source or formal verification

**Status: ✅ Pass (with one caveat)**

Open-source under [github.com/tinfoilsh](https://github.com/tinfoilsh): `cvmimage`, `tinfoil-go`, `tinfoil-cli`, `measure-image-action`, `confidential-model-router`, `confidential-websearch`, etc. All audit-relevant code is public.

**Caveat:** The controlplane (`api.tinfoil.sh`) is closed-source — `gh api repos/tinfoilsh/controlplane` returns 404. From the Stage 1 perspective this is fine *if* you accept that the controlplane only handles orchestration (host selection, provisioning, secrets storage, billing) and never participates in the attestation trust chain. But "operator-side actions don't affect attestation" is exactly the kind of claim that needs source review to verify, which is impossible while the controlplane is closed.

### 3. Community can reproducibly compute code measurement

**Status: ✅ Pass**

`measure-image-action` is open source. The [Sigstore-signed deployment.json](https://github.com/tinfoilsh/tinfoil-containers-hello-world/releases/download/v0.0.5/tinfoil-deployment.json) embeds:
- `cmdline` (with `tinfoil-config-hash=` and `roothash=`)
- `hashes` (kernel, initrd, root, raw)
- `config` (base64'd YAML)
- `snp_measurement` and/or `tdx_measurement`

Anyone with the OVMF + kernel + initrd + cmdline can recompute the SEV/TDX launch measurement and check it matches. Our [`verifiers/tinfoil.py`](https://github.com/amiller/awesome-private-inference/blob/main/verifiers/tinfoil.py) does the cross-check today.

### 4. Developer has no access to application secrets

**Status: ⚠️ Conditional pass — depends on the deployment**

Per [`DEVPROOF-REPORT.md`](DEVPROOF-REPORT.md):
- A deployment with **empty `secrets:`** and only map-form `env:` slots has no operator-controllable runtime values. Pass.
- A deployment with **any `secrets:`** slot has values that, per Tinfoil's own [docs](https://docs.tinfoil.sh/containers/secrets-and-env-vars), "pass through the host on their way into the container." The host operator (Tinfoil) sees them in plaintext during deploy. Fail.

The stock `tinfoilsh/tinfoil-containers-hello-world` template ships with `secrets: [API_KEY]`, so every copy-paste user starts in fail mode. Removing the `secrets:` line is a one-character fix.

For Stage 1 specifically, this is "you can deploy in a Stage-1-passing config; the default is not it."

### 5. Well-defined upgrade process with notice period

**Status: ⚠️ Partial pass — operator-controlled, not timelock-enforced**

Tinfoil's update flow: GitHub release → workflow signs deployment.json → controlplane stages as `update_status: ready` → operator runs `tinfoil container update accept` → blue-green switch.

The Stage 1 checklist explicitly asks for "Timelock on compose hash changes (e.g., 7 days) OR DAO governance for upgrades." Tinfoil has neither — it has operator manual approval, which is faster but doesn't bind the operator to wait. **Auto-update mode (`tinfoil container auto-update --on`) eliminates the operator step entirely**, redeploying as soon as a new release is detected.

The "manual promote" pattern is good UX but not a notice period in the ERC-733 sense. A user trusting a Tinfoil deployment cannot know "this enclave will not be upgraded for the next 7 days" — only "this enclave will not be upgraded until the operator clicks accept" (which could be in 5 seconds).

For comparison, [`UpgradeOperator.sol`](https://github.com/amiller/dstack-replicatoor/blob/main/contracts/src/UpgradeOperator.sol) (the dstack-replicatoor pattern) enforces a 48-hour timelock on chain. That's the shape of "notice period" the checklist contemplates.

### 6. No dependency on centralized infrastructure except TEE vendors

**Status: ❌ Fail**

This is the cleanest fail. Tinfoil-Containers depends on, beyond AMD/Intel:

- **Tinfoil's controlplane** — closed-source, single-operator, can refuse to deploy / can deprovision running CVMs
- **Tinfoil's hardware fleet** — no host marketplace; if Tinfoil disappears, your CVMs disappear
- **Tinfoil's verification CDN** (atc / github-proxy / tdx-proxy) — high-availability operationally but a centralization point
- **GitHub** — the config repo and code-measurement signer
- **Sigstore (Fulcio + Rekor)** — for the keyless signing trust chain

The Stage 1 checklist allows "TEE vendor is only centralized dependency." Tinfoil's surface is much larger. Some dependencies are inherent to "supply-chain transparency" (Sigstore, GitHub OIDC) and would be hard to remove without losing the verification model. Others are operational (controlplane, hardware fleet) and would require platform-level decentralization to remove.

### 7. No backdoors or debug paths

**Status: ✅ Pass**

- `--debug` mode flips the SEV guest-policy debug bit; Tinfoil's own SecureClient refuses to connect to debug enclaves; the verifier explicitly checks bit 19. Clean signal, not a hidden backdoor.
- `--variable KEY=VALUE` is bounded to declared slots per [`buildEnv`](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/containers.go#L397-L432); undeclared keys silently dropped, map-form attested values cannot be overridden.
- Secrets pass through host plaintext (per docs) but this is a documented architectural choice, not a hidden backdoor.

### Stage 1 verdict

**Stage 1 conditional, with two real failures and two conditional passes:**

| Requirement | Status |
|---|---|
| 1. On-chain attestation | ❌ Fail (Sigstore is "equivalent transparency" only on liberal reading) |
| 2. Code auditable | ✅ Pass (controlplane caveat) |
| 3. Reproducible measurement | ✅ Pass |
| 4. No developer secrets access | ⚠️ Conditional — depends on deployment having no `secrets:` |
| 5. Upgrade notice period | ⚠️ Partial — operator-controlled but not timelock-enforced |
| 6. No centralized infra except TEE vendors | ❌ Fail — controlplane + hardware fleet are Tinfoil-controlled |
| 7. No backdoors | ✅ Pass |

A best-case Tinfoil-Containers deployment (no `secrets:`, manual updates with operator caution, accepting Sigstore as transparency-equivalent) sits at "Stage 1 with caveats." A typical deployment (using the stock template's `secrets:` slot, with auto-update on, accepting that `api.tinfoil.sh` is Tinfoil-only) is **Stage 0**.

---

## ERC-733 Stage 2 walkthrough

Stage 2 ("Decentralized TEE Network") adds requirements about distribution of privilege.

| Requirement | Status |
|---|---|
| Multi-TEE deployment for redundancy | ❌ Fail — "single instance per container" per platform docs |
| Responsive to TCB updates | ✅ Probable — Sigstore signing + measure-image-action runs per release; cvm-version field bumps in `tinfoil-config.yml` |
| No vendor lock-in (Intel TDX, AMD SEV, Nitro) | ⚠️ Partial — supports SEV-SNP and TDX but not AWS Nitro |
| Forward secrecy & data opt-out | ✅ Pass — HPKE keypair rotates per launch; data opt-out is trivial because nothing persists at the platform layer |
| Long-term reproducibility | ⚠️ Partial — Sigstore + GitHub releases are immutable but not actively mirrored; if either disappears, the trust chain breaks |
| Permissionless operation | ❌ Fail — only Tinfoil can operate hosts |
| Governance can veto faulty vendor TCB | ❌ Fail — no governance mechanism |

**Stage 2 verdict: clear fail.** Tinfoil-Containers is firmly Stage 1-with-caveats. The single-instance constraint, single-operator hardware fleet, and lack of governance are structural — Stage 2 would require a different platform shape entirely.

---

## ERC-733 Stage 3 walkthrough

Stage 3 ("Trustless TEE") adds: MPC DKG and signing, independence from Intel sealing key, indistinguishability obfuscation.

**Status: clear fail.** Not even a goal that fits Tinfoil-Containers' design. Stage 3 is a research frontier; no production platform has reached it.

---

## Side-by-side ERC-733 stages: Tinfoil vs dstack

| Stage | Tinfoil-Containers | dstack (Phala-KMS variant) | dstack (Base-KMS variant) |
|---|---|---|---|
| **Stage 0** | Default for the stock template (because of `secrets:`) | Default for many deployed apps | Default; few deployments use Base-KMS yet |
| **Stage 1** | Achievable per-deployment (no `secrets:`, manual updates); platform-level fails on centralized infra (closed controlplane + Tinfoil-only fleet) | Per-deployment achievable; platform-level fails on Phala-KMS opacity (Phala-operated, not on chain) | Per-deployment more naturally achievable (on-chain compose-hash registry, transparent upgrade history). Several deployed apps qualify |
| **Stage 2** | Clear fail — single instance, single operator, no governance | Clear fail — single Phala-KMS operator | **Conditional pass possible** — multiple CVMs sharing app_id via on-chain registry; vendor mix achievable; permissionless operator is in roadmap |
| **Stage 3** | Not a goal | Not a goal | Research goal; not a current target |

**The real story:** Tinfoil and dstack-Phala-KMS are roughly comparable on Stage 1 (both have one or two centralized dependencies). They diverge sharply at Stage 2 — dstack's on-chain `IAppAuth` + multi-CVM `app_id` model gives it a realistic path; Tinfoil's single-instance + single-operator model rules it out structurally. The operational simplicity Tinfoil prizes is precisely what blocks Stage 2.

---

## Path to Stage 1 for typical Tinfoil deployments

What a Tinfoil customer would need to do to claim Stage 1 today:

1. **Drop `secrets:`** from the YAML. Use map-form `env:` only, or move secrets out of the platform entirely (handle in-app via TEEBridge, customer-side KMS, or end-user-bound keys).
2. **Disable auto-update.** Confirm `tinfoil container get -o json | jq .auto_update` is `false`. Document the upgrade cadence and the operator's review process.
3. **Pin the verifier to a measurement.** Distribute clients with the expected measurement hardcoded; refuse to connect to other measurements. (Tinfoil's SDK doesn't make this easy — the SDK fetches the latest signed release per the repo, which means the SDK trusts the repo owner. A custom verifier would need to pin specifically.)
4. **Document the centralized-infra dependency.** The Stage 1 requirement around centralized infra fails strictly. Honest documentation: "Stage 1 modulo `api.tinfoil.sh` and Tinfoil's hardware fleet."

What Tinfoil-the-platform would need to do to clear Stage 1 unconditionally:

1. **Open the controlplane source.** This is the single biggest item.
2. **Document a host marketplace path** OR move to a model where multiple operators can run hosts.
3. **Add a real notice period option** (timelock contract or controlplane-enforced timer) for users who want it.
4. **Anchor Sigstore commitments on chain** for "equivalent transparency" → "actual on-chain attestation."

These are non-trivial. Items (1) and (2) would change Tinfoil's product shape significantly.

---

## Path to Stage 2

Stage 2 is structurally hard for Tinfoil-Containers because the architecture is single-instance-per-container. The shortest path:

1. Add multi-CVM mode (multiple hosts running the same `tinfoil-config.yml`, with shared identity).
2. Open the host operator marketplace (any attested operator can join).
3. Mirror Sigstore + GitHub state to other transparency layers.
4. Add governance for vendor TCB acceptance.

This is essentially "rebuild the platform with dstack-shaped constraints." Realistically, Tinfoil's path to Stage 2 is **via TEEBridge or equivalent cross-CVM coordination layers** — letting users compose multiple Tinfoil CVMs into a Stage-2-shaped system without changing Tinfoil's per-CVM model. The [`TinfoilAdapter` PR](https://github.com/Account-Link/tee-interop/pull/1) is exactly this layer; the missing piece is the host-marketplace one.

---

## Summary

**ERC-733 stage:** **Stage 1 conditional** for best-case deployments (no `secrets:`, manual updates, generous reading of "equivalent transparency"); **Stage 0** for the stock template's default configuration. Stage 2 is structurally out of reach without rebuilding the single-instance model.

**Multi-vendor / lock-in:** Hardware vendor (AMD/Intel) and image registry (3 options) are real choices. Code repo (GitHub), code-measurement signer (Tinfoil's action), verification CDN (Tinfoil), hardware operator (Tinfoil), and controlplane (Tinfoil, closed) are all locked in. The cryptographic primitives are open; the orchestration is closed.

**The biggest single thing Tinfoil could do for ERC-733 progress:** open the controlplane. It's the requirement-6 fail, the audit-coverage caveat for requirement 2, and the precondition for any host marketplace that would unlock Stage 2.
