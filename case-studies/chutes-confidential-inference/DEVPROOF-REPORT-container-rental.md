# Chutes Confidential **Container Rental** — DevProof Audit

**Audit date:** 2026-05-25
**Target:** `chutes.ai` confidential compute, viewed as a **GPU-container rental** surface — a tenant ships their own workload (a "chute") to be run confidentially on a permissionless miner's GPU (e.g. an 8×RTX PRO 6000 TEE node), rather than calling a Chutes-hosted model.
**Companion report:** [`DEVPROOF-REPORT.md`](./DEVPROOF-REPORT.md) covers the **inference-consumer** surface (F1–F6). This report does *not* restate the shared TDX/ML-KEM crypto core — it is verified there and assumed.

> **Why a separate report.** Confidential *inference* and container *rental* are different products with near-inverted threat models. The inference consumer asks *"is the operator serving model X, and can they read my prompts?"* (→ F1 model-identity, F3 verify-then-encrypt). The rental tenant asks *"does the platform run **my** image, unmodified, with the GPU owner unable to see inside — and can I **prove** it?"* The load-bearing mechanism here (a cosign admission controller) barely matters to the inference report; the model-identity question (F1) barely matters here because the tenant *is* the workload author.

**New ground covered since the inference report:** the guest-image build is published in a fourth repo, **[`chutesai/sek8s`](https://github.com/chutesai/sek8s)** (MIT). The org renamed `rayonlabs → chutesai` (301 redirect confirmed). This materially changes the provenance story (see R3) versus inference-F2.

---

## What "container rental" actually is on Chutes

Not a raw VM with SSH. The tenant defines a chute with the SDK (LLM templates *or* a custom `Image`/`Chute`), and Chutes' control plane builds and runs it as a Kubernetes Job inside a shared, security-hardened TDX VM (`sek8s`) on miner hardware. **TEE VMs have no SSH** (`sek8s/README.md`); management is via `chutes-miner-cli` + a read-only system-status API. So "rent the RTX 6000 + bring your own container" = *deploy your own (confidential) chute*; the observed live `-TEE` catalog is all LLM-serving, but the SDK build path is general.

---

## Quick Status (rental tenant's viewpoint)

| Property | Verifiable today? | Notes |
|---|:--:|---|
| Genuine TDX + GPU CC-mode (vs the miner/host) | ✅ | shared crypto core, verified in companion report |
| Base guest image is published & measurements re-derivable | ✅* | **R3** — `sek8s` ships builder + `tdx-measure` recompute; *bit-repro unproven (TODO) |
| Tenant data confidential **from the GPU owner (miner)** | ✅ | TDX memory encryption; miner is outside the trust boundary |
| Tenant data/code confidential **from Chutes (control plane)** | ❌ | **R4** — Chutes builds the image, holds the cosign key + the static LUKS key |
| Only signed images run (in-CVM enforcement exists) | ✅ | **R2** — measured OPA+cosign admission controller, default-deny `"*"` |
| **My exact image** is what ran (third-party-checkable) | ❌ | **R1** — not in any measured register; server-side build; Chutes-held key |
| Tenant-controlled signature / digest pinning | ❌ | **R1** — tenant signs nothing; cannot even compute "their" digest |
| Public transparency of what Chutes signed | ⚠️ | **R5** — cosign→Rekor tlog by default; pubkey not published |

---

## TL;DR

For the "I don't trust the GPU owner" case, Chutes is **strong**: the workload runs in a genuine, non-debug Intel TDX VM with CC-mode GPUs, the miner host is explicitly outside the trust boundary, and — unlike what the inference report (F2) concluded from the three app repos — the **base image is now published and its measurements are reproducible in principle** (`sek8s`, R3).

For the "can I *prove* my exact container ran, without trusting Chutes" case, it is **not devproof**:

1. **R1 — The tenant's image is built and signed by Chutes, server-side, with Chutes' key (High).** The tenant controls neither the resulting digest nor a signature. Nothing binds the tenant's image into a measured register (live RTMR3 = 0). A verified quote proves "a Chutes-signed image ran in genuine TDX," not "*this* image."
2. **R2 — Container integrity is enforced by a measured admission controller, not by the hardware quote (Medium).** A fail-closed default-deny cosign gate baked into the reproducible guest; its own integrity is anchored (fail-closed webhook, quote-gated LUKS key, RTMR3 policy-measurement on v1.3.0), so a *miner* cannot disable or rewrite it. The residual gap is that the enforced policy and the served workload are **invisible to a third-party verifier of the quote** — not that the host can tamper.
3. **R3 — Base-image provenance is largely solved (positive).** `sek8s` publishes the builder + `tdx-measure` recompute path + a pinned-SHA256 prebuilt qcow2. Residual: bit-for-bit rebuild unproven; image has a git-committed hash but no signature/SLSA provenance.
4. **R4 — Confidentiality is real vs the miner, weak vs Chutes (Medium).** Chutes is deep in the TCB: it builds the image, holds the cosign signing key, and holds the fleet-wide static LUKS passphrase (companion F5).
5. **R5 — A public transparency lever exists (Rekor) but isn't surfaced for tenants.**

---

## Findings

### R1 — Tenant image is built & signed server-side by Chutes; tenant holds no key and no digest (High)

**Claim audited:** that a tenant renting confidential GPU compute can rely on "my container, unmodified, ran in the TEE."

**Finding.** The build and signature are entirely control-plane-side:
- Chutes' `forge` builds the image with buildah from base `parachutes/python:3.12`, pushes to Chutes' registry, then **signs it with Chutes' key**: `cosign sign --allow-http-registry --key {settings.cosign_key} {image}@{digest} --yes`, password piped from `settings.cosign_password` (`chutes-api/api/image/forge.py:644-676`). The signed reference is `{validator_ss58}.localregistry.chutes.ai:5000/...` (`:656-662`).
- Inside the CVM, the `sek8s` admission controller verifies that signature against the baked-in `cosign.pub` before scheduling (`sek8s/ansible/guest/roles/admission-controller/templates/cosign-registries.json.j2`: the `localregistry` and catch-all `"*"` entries are `require_signature: true, verification_method: key`).
- The miner pulls by tag, not digest (`chutes-miner/.../k8s/util.py:259`, `image_pull_policy: Always`) — admission, not the pull ref, is the integrity gate.

**Why this isn't devproof for the tenant:**
1. **No measured binding.** The image identity is in *no* measured register a third party can read. Across all hardware classes the live golden MRTD is one value (`DDC6EFCD…`) and RTMR3 = `00…00` (live `/servers/tee/measurements`). RTMR3 is *designed* to carry an initramfs IMA-style file manifest (`sek8s/guest-tools/scripts/compute-rtmr3.sh`: sorted SHA-384 chain over `/etc/tdx-measure.conf`), but it measures fixed guest files, never the tenant container, and reads zero in production anyway.
2. **Chutes-held key (operator-trust, not a miner gap).** The signing key is Chutes', not the tenant's. A compromised/compelled *control plane* can build+sign a substitute image and it will be admitted and attested identically. But a malicious **miner cannot** swap: the in-guest admission gate is fail-closed and measured, and the LUKS key is released only into measured-guest TEE memory (see R2 / `EXPLOITABILITY-VALIDATION.md` F1). So this reduces to Chutes key-custody trust — the same substitution *family* as inference-F1, but with the host-side exploit refuted.
3. **Server-side build.** The tenant cannot even independently compute the digest of "their" image — `forge` builds it, so there is no tenant-side artifact to compare against.

**Impact:** the tenant (and, more importantly, the tenant's *end-users*) cannot externally distinguish "the tenant's audited image ran" from "a Chutes-modified image ran." **Severity: High** — it is the core rental claim.

**Fix:** let tenants sign their own image (their key in the admission policy, or a tenant-namespaced keyless identity), pin the tenant image digest into RTMR3, and publish the per-deployment digest so end-users can match the attested register to a tenant-published value.

### R2 — Container integrity rides on a measured admission controller, not the TDX quote (Medium; partly positive)

**Positive.** Unlike the picture from the app repos alone, there *is* a real in-CVM integrity gate: an OPA + cosign `ValidatingAdmissionPolicy` is part of the `sek8s` guest image (`ansible/guest/roles/admission-controller/`: `policies/*.rego`, `webhook-vap.yaml`, `tasks/{install,configure}-cosign.yml`). The registry policy is **default-deny** — a catch-all `"*"` entry requires a valid signature — so unsigned images don't schedule. Because the admission controller is inside the reproducible guest (R3), its *code* is auditable.

**Gaps.**
- **Invisible to the hardware verifier.** A third party verifying the TDX evidence sees only the generic `sek8s` MRTD/RTMR0–2 (identical across all workloads and all GPU classes — only RTMR0/2 vary by host firmware/ACPI). The "only signed images run" property is not expressed in the quote; it must be taken on trust that the running policy is the audited one.
- **The gate's own integrity is anchored — a miner cannot disable or rewrite it.** The webhook runs `enforce` / `failurePolicy: Fail` (fail-closed — `manifests/webhook-vap.yaml`), is self-protecting (`webhook.rego` denies editing webhooks), and its cert service `Requires=rtmr3-verify.service`. The rootfs is dm-crypt LUKS2 (no dm-verity), **but** the LUKS key is released *only into measured-guest TEE memory*: `fetch_key_and_unlock` generates an in-TD quote and the control plane returns the key over mTLS only if it matches golden measurements — so a miner can't extract the key to tamper the rootfs offline. On **v1.3.0** images RTMR3 additionally file-measures `/etc/opa/policies`, `/opt/sek8s/src`, and the admission CA (`tdx-measure.conf`, SHA-384 chain), making policy tampering tamper-evident. So "the right policy is enforcing" rests on operator-trust + the measured-boot/key-release chain, **not** an unverified link. *(Residual: pre-v1.3.0 golden configs show RTMR3 = 0; and a key-holder — Chutes — could still rewrite the dm-crypt rootfs, which is operator-trust, companion F5. See `EXPLOITABILITY-VALIDATION.md` F1.)*
- **Unsigned escape hatches.** Several registries are `verification_method: disabled` — `docker.io` root, `gcr.io` root, `registry.k8s.io`, `nvcr.io`, `quay.io` — so images from those namespaces are admitted unsigned. Chute images go via the signed `localregistry`, but the disabled namespaces widen the in-TEE software surface.

**Severity: Medium.** The integrity gap is *not* "a miner can swap the workload" (refuted) — it is that the enforced policy and the served workload are **invisible to a third-party verifier of the quote**, and that model/image identity is unmeasured. **Fix:** reflect the served `image_digest‖model‖revision` (and the admission-policy hash) in a measured register (RTMR3) so verifiers can confirm what ran; narrow the disabled-registry list.

### R3 — Base-image provenance is largely solved (positive; supersedes the inference-F2 framing)

The guest image the inference report called unbuildable TOFU is in fact published in **`chutesai/sek8s`** (MIT):
- `guest-tools/` + `ansible/guest/` build the encrypted TDX VM (k3s + attestation service + GPU drivers).
- Committed boot inputs: `firmware/TDVF.fd`, `metadata.json` (TDVF + kernel `vmlinuz`/`initrd` + fixed cmdline & root UUID).
- `guest-tools/scripts/{extract-vm-measurements,extract-acpi,compute-measurements}.sh` recompute MRTD + RTMR0–2 with Intel `tdx-measure`; `compute-rtmr3.sh` recomputes the RTMR3 file-manifest. README: *"Each measurement depends only on these inputs."*
- Prebuilt image at `https://vm.chutes.ai/tdx-guest.qcow2` (public, no auth) with a **git-committed SHA-256** `1d53800f1c18e353ce43bbad886f3b38555b7fc38c3362b04af30d11a16f7b46` (`host-tools/scripts/quick-launch.sh:17-20`).

So a tenant *can* download the exact base image, verify the hash, audit the boot chain + admission policy from source, and (TODO) recompute the live golden `DDC6EFCD…`. **Residual gaps:** (a) bit-for-bit rebuild from the Ansible source to the published artifacts is unproven — the realistic hard part; (b) the qcow2 is anchored only by a hash a maintainer committed to git — no detached signature, no GitHub build provenance (`.github/workflows` has CI/lint/openapi but **no** `attest-build-provenance`; the single `v1.3.0` release has empty assets); (c) the LUKS rootfs in the distributed image can't be inspected without the key, so policy/key auditing relies on the source matching the build (= the R3a reproducibility question). **Severity: Low** — provenance is reachable, just not yet *demonstrated*.

### R4 — Confidential from the miner, not from Chutes (Medium)

- **vs the miner (the rented GPU's owner):** strong. TDX memory encryption + GPU CC-mode keep the tenant's weights/data out of the host's reach; the miner is permissionless and explicitly outside the trust boundary. This is the threat the rental product most plausibly targets, and it holds.
- **vs Chutes (control plane):** weak. Chutes builds the tenant image (has the source), holds the cosign signing key (`settings.cosign_key`), holds the **fleet-wide static** `LUKS_PASSPHRASE` (companion F5 — never *miner*-extractable, released only into measured-guest TEE memory, so this is Chutes-trust not host exposure), and runs the attestation/key-release service. A tenant wanting "not even Chutes can see or alter my container" does not get it. (On the *inference* path the analogous exposure is sharper — the mainstream `llm.chutes.ai` route handles prompts in plaintext at the control plane; see `EXPLOITABILITY-VALIDATION.md` V0.) **Severity: Medium** (the product framing is "untrusted miner," so this is a scope clarification more than a defect — but it should be stated, because end-users often read "TEE" as "nobody, including the platform").

### R5 — A public transparency lever exists but isn't surfaced (informational → the "probe without building" answer)

The tenant's earlier question: *is there a Sigstore/GitHub build to probe/analyze the image without doing our own build?* Inventory:

- **Sigstore/Rekor transparency — yes, and it's the highest-value lever.** `forge` signs with cosign v2 (pinned `2.6.3`, `sek8s/.../defaults/main.yml`) using `--key` and **no** `--tlog-upload=false`; cosign v2 uploads key-signed entries to the public Rekor tlog (`https://rekor.sigstore.dev`) by default. The admission policy *also* sets `rekor_url` on the verify side, so tlog inclusion is effectively required for a pod to schedule. Net: **every chute image Chutes signs should produce a public, timestamped, append-only Rekor entry.** An auditor can enumerate Chutes' signing history from the public log without building anything and without access to the private registry. *Catch:* querying by key needs Chutes' `cosign.pub`, which is **not** published (baked into the LUKS rootfs); querying by image digest works if a digest is known. **Probe to run:** confirm `parachutes/*` / chute-image entries actually appear in Rekor, and ask Chutes to publish the cosign public key (cheap, high-value transparency win).
- **GitHub build provenance / SLSA — no.** No `attest-build-provenance` workflow; release assets empty. Nothing to verify the qcow2 against beyond the git-committed SHA-256.
- **The image itself — yes, partially.** Download `vm.chutes.ai/tdx-guest.qcow2`, verify the pinned SHA-256, and inspect the *unencrypted* boot chain (TDVF/kernel/initrd/cmdline/ACPI) — no LUKS key needed for the parts that determine MRTD/RTMR0–2. The rootfs (admission policy, cosign key) stays encrypted; audit those from `sek8s` source.

---

## Stage Assessment (rental surface)

- **Confidentiality vs untrusted host (the rental value prop):** strong and hardware-rooted. Reaches the "GPU owner can't see in" bar.
- **Confidentiality vs the platform:** not claimed-and-met — Chutes is in the TCB (R4).
- **Workload integrity / "my exact container ran," third-party-provable:** does **not** reach a devproof posture. There is a real measured admission gate (R2) — a step beyond the inference report's read — but the binding is to *a Chutes-signed image*, not *the tenant's image*, the key is Chutes', and nothing is anchored in a verifier-readable register (R1).
- **Provenance of the trusted base:** **reachable** (R3) — the strongest improvement over the inference-F2 conclusion, pending an actual reproducible-build demonstration.

Net: a renter who only distrusts the **miner** is well served. A renter (or their end-users) who wants to **prove the specific workload** without trusting Chutes cannot, today — the gap is tenant-controlled signing + a measured workload binding, not the base image.

---

## Probe / reproduction (no payment; no image build)

```bash
# Base image is published + hash-pinned — fetch and verify without building:
#   curl -sL https://vm.chutes.ai/tdx-guest.qcow2 -o tdx-guest.qcow2
#   sha256sum tdx-guest.qcow2   # expect 1d53800f1c18e353ce43bbad886f3b38555b7fc38c3362b04af30d11a16f7b46
# Audit the admission policy + cosign config from source:
#   github.com/chutesai/sek8s  ansible/guest/roles/admission-controller/
# Confirm one golden MRTD across all hardware (RTX 6000 == H200 == B200):
curl -s -H "Authorization: Bearer $(cat /tmp/ck)" https://api.chutes.ai/servers/tee/measurements \
  | jq -r '.[] | "\(.name)\t\(.mrtd[:16])\t\(.runtime_rtmrs.RTMR3[:8])"' | sort -u
# Transparency probe (R5): check whether chute-image signatures land in public Rekor.
```

## Source

| Repo | Role for this surface |
|---|---|
| [`chutesai/sek8s`](https://github.com/chutesai/sek8s) (MIT) | the rented TEE VM: guest builder, **OPA+cosign admission controller**, measurement-recompute tooling, prebuilt qcow2 + pinned SHA-256 |
| `chutesai/chutes-api` | `forge` server-side build + `cosign sign` (`api/image/forge.py:644-676`); measurement registry |
| `chutesai/chutes-miner` | k8s Job launch (`k8s/util.py:259`, tag pull / `image_pull_policy: Always`) |
| `chutesai/chutes` | SDK image/chute definition (tenant entry point) |

Cross-reference: companion [`DEVPROOF-REPORT.md`](./DEVPROOF-REPORT.md) (shared TDX/ML-KEM core, F1–F6). Model-substitution family: [near-ai-private-inference](../near-ai-private-inference/), [redpill-federated-inference](../redpill-federated-inference/).
