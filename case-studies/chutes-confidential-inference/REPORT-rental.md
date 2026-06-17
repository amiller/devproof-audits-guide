# Chutes Provider — DevProof Report

This report covers **Question 2** of [`PLATFORM.md §0`](./PLATFORM.md#0-setting-the-parties-and-the-two-questions):

> **Chutes customer → their own customers: "Can I prove that inference runs without me — or Chutes —
> seeing the data?"**

**Setting:** you are a **Chutes customer** — you deploy your own confidential chute (a vLLM/SGLang template,
custom `@chute.cord` handlers, or a `@chute.job`) and resell it to *your* users as private inference. You
want to hand them a guarantee they can check: that the code touching their plaintext is the audited,
non-exfiltrating code you wrote, and that neither you nor Chutes can quietly read their data. Secondarily,
because the chute runs on a permissionless miner's GPU, you also want the GPU owner unable to see inside.
**Shared facts** (crypto core, base-image provenance, miner containment, lower-tier F4/F5) live in
[`PLATFORM.md`](./PLATFORM.md) and are not restated here.

> **Why a separate report from the consumer one.** Same root cause (unmeasured plaintext-path code,
> [PLATFORM §4](./PLATFORM.md#4-the-root-gap-that-splits-the-two-reports)), inverted vantage point. The
> consumer (Question 1) wants to *remove trust in Chutes*; here you *are* the operator, so there is no
> victim from your own deployment — the gap is that you cannot **pass a confidentiality guarantee through**
> to your downstream users, because the code that sees their plaintext is built+signed by Chutes server-side
> and bound to no measured register you or they can check. The load-bearing platform mechanism here — a
> measured cosign admission controller — barely matters to the consumer report.

---

## What "container rental" is on Chutes

Not a raw VM with SSH. The tenant defines a chute with the SDK (LLM templates *or* a custom `Image`/`Chute`),
and Chutes' control plane builds and runs it as a Kubernetes Job inside the shared, security-hardened TDX VM
(`sek8s`) on miner hardware. **TEE VMs have no SSH** (`sek8s/README.md`) except via the `@chute.job` path
(see Jobs, below); management is otherwise via `chutes-miner-cli` + a read-only status API. So "rent the
RTX 6000, bring your container" = *deploy your own confidential chute*. The live `-TEE` catalog is all
LLM-serving, but the SDK build path is general.

---

## Quick status (tenant viewpoint)

| Property | Verifiable today? | Notes |
|---|:--:|---|
| Genuine TDX + GPU CC-mode vs the miner/host | ✅ | [PLATFORM §1](./PLATFORM.md#1-the-cryptographic-core-is-sound-verified-live) |
| Base guest image published & measurements re-derivable | ✅* | [PLATFORM §2](./PLATFORM.md#2-base-image-provenance-is-reachable-not-tofu) (*bit-repro unproven) |
| Tenant data confidential **from the GPU owner (miner)** | ✅ | TDX memory encryption; miner outside the trust boundary |
| Tenant data/code confidential **from Chutes** | ❌ | **R3** — Chutes builds the image, holds cosign + static LUKS keys |
| Only signed images run (in-CVM enforcement) | ✅ | **R2** — measured OPA+cosign admission controller, default-deny `"*"` |
| **My exact image** is what ran (third-party-checkable) | ❌ | **R1** — not in any measured register; server-side build; Chutes-held key |
| Tenant-controlled signing / digest pinning | ❌ | **R1** — tenant signs nothing; cannot even compute "their" digest |
| Jobs (SSH-in-TEE) attestation posture | ❓ | **R4** — quota-0, undocumented, unaudited |

**Bottom line.** A renter who only distrusts the **miner** is well served: the workload runs in a genuine,
non-debug TDX VM with CC-mode GPUs, the host is explicitly outside the trust boundary, and the base image is
published and reproducible-in-principle. A renter (or their end-users) who wants to **prove the specific
workload ran** without trusting Chutes cannot today — the gap is tenant-controlled signing + a measured
workload binding, not the base image.

---

## R1 — Tenant image is built & signed server-side by Chutes; tenant holds no key and no digest (High)

**Claim audited:** that a tenant renting confidential GPU compute can rely on "my container, unmodified, ran
in the TEE."

The build and signature are entirely control-plane-side:

- Chutes' `forge` builds the image with buildah from base `parachutes/python:3.12`, pushes to Chutes'
  registry, then **signs it with Chutes' key**: `cosign sign --allow-http-registry --key {settings.cosign_key}
  {image}@{digest} --yes`, password piped from `settings.cosign_password` (`chutes-api/api/image/forge.py:644-676`).
  The signed reference is `{validator_ss58}.localregistry.chutes.ai:5000/...` (`:656-662`).
- Inside the CVM, the `sek8s` admission controller verifies that signature against the baked-in `cosign.pub`
  before scheduling (`cosign-registries.json.j2`: `localregistry` and catch-all `"*"` are
  `require_signature: true`).
- The miner pulls by tag, not digest (`chutes-miner/.../k8s/util.py:259`, `image_pull_policy: Always`) —
  admission, not the pull ref, is the integrity gate.

**Why this isn't devproof for the tenant:**

1. **No measured binding.** The image identity is in *no* measured register a third party can read. Across
   all hardware classes the live golden MRTD is one value and RTMR3 = 0 in production. RTMR3 is *designed* to
   carry an initramfs file manifest (`sek8s/guest-tools/scripts/compute-rtmr3.sh`) but it measures fixed guest
   files, never the tenant container.
2. **Chutes-held key.** The signing key is Chutes', not the tenant's. A compromised/compelled *control plane*
   can build+sign a substitute image and it is admitted and attested identically. (A malicious **miner**
   cannot swap — [PLATFORM §3](./PLATFORM.md#3-the-miner-is-contained-a-malicious-host-cannot-swap-code-or-read-memory).)
   So this reduces to Chutes key-custody trust.
3. **Server-side build.** The tenant cannot even independently compute the digest of "their" image — `forge`
   builds it, so there is no tenant-side artifact to compare against.

**Impact:** the tenant — and, more importantly, the tenant's *end-users* — cannot externally distinguish "the
tenant's audited image ran" from "a Chutes-modified image ran." In confidentiality terms (Question 2): you
cannot prove to your users that the code which sees their plaintext is your non-exfiltrating code rather than
a substitute — the very gap the consumer report shows is exploitable in
[`OPERATOR-EXFIL-POC.md`](./OPERATOR-EXFIL-POC.md). **Severity: High** — it is the core guarantee a Chutes
customer would resell. **Fix:** let tenants sign their own image (their key in the admission policy, or a
tenant-namespaced keyless identity), pin the tenant image digest into RTMR3, and publish the per-deployment
digest so end-users can match the attested register to a tenant-published value.

---

## R2 — Container integrity rides on a measured admission controller, not the TDX quote (Medium; partly positive)

**Positive.** There *is* a real in-CVM integrity gate: the OPA + cosign `ValidatingAdmissionPolicy` shipped in
the `sek8s` guest, default-deny on a catch-all `"*"` registry, fail-closed and self-protecting, with its own
integrity anchored by the measured-boot / TEE-gated-key-release chain. A malicious miner can neither disable
nor rewrite it — the full mechanism is in
[PLATFORM §3](./PLATFORM.md#3-the-miner-is-contained-a-malicious-host-cannot-swap-code-or-read-memory). Because
the controller is inside the reproducible guest, its *code* is auditable from `sek8s`.

**Residual gaps (not "a miner can tamper" — that is refuted):**

- **Invisible to the hardware verifier.** A third party verifying the TDX evidence sees only the generic
  `sek8s` MRTD/RTMR0–2 (identical across all workloads). The "only signed images run" property is not
  expressed in the quote; that the *running* policy is the audited one must be taken on trust (mitigated on
  v1.3.0, where RTMR3 file-measures the policy dir + admission CA).
- **Unsigned escape hatches.** Several registries are `verification_method: disabled` — `docker.io` root,
  `gcr.io` root, `registry.k8s.io`, `nvcr.io`, `quay.io` — so images from those namespaces are admitted
  unsigned. Chute images go via the signed `localregistry`, but the disabled namespaces widen the in-TEE
  software surface.

**Severity: Medium.** The gap is that the enforced policy and the served workload are **invisible to a
third-party verifier of the quote**. **Fix:** reflect the served `image_digest‖model‖revision` and the
admission-policy hash in a measured register (RTMR3); narrow the disabled-registry list.

---

## R3 — Confidential from the miner, not from Chutes (Medium)

- **vs the miner (the rented GPU's owner):** strong. TDX memory encryption + GPU CC-mode keep the tenant's
  weights/data out of the host's reach; the miner is permissionless and explicitly outside the trust boundary.
  This is the threat the rental product most plausibly targets, and it holds.
- **vs Chutes (control plane):** weak. Chutes builds the tenant image (has the source), holds the cosign
  signing key (`settings.cosign_key`), holds the fleet-wide static `LUKS_PASSPHRASE`
  ([PLATFORM §5](./PLATFORM.md#5-lower-tier-shared-facts-operator-trust--enforced-server-side)), and runs the
  attestation/key-release service. A tenant wanting "not even Chutes can see or alter my container" does not
  get it.

**Severity: Medium** — the product framing is "untrusted miner," so this is a scope clarification more than a
defect; but it should be stated, because end-users often read "TEE" as "nobody, including the platform."

---

## R4 — Jobs (SSH-in-TEE) are the largest unaudited surface (open)

`@chute.job` exposes an interactive **SSH shell inside the TEE** (`ssh=True`) or a batch script, with an
`output_dir` and egress — a far larger in-TD code-exec surface than a cord. The path is quota-gated to 0
(`Daily job quota exceeded: job_quota=0`), so its attestation behaviour — what the validator checks for a job
vs a cord, whether the job binary is measured — is **undocumented and untestable without Chutes granting
quota**. That untestability is itself the finding: the rawest "bring your own container" surface has no
established devproof posture. **Ask:** grant audit quota, or document the job-path measurement model.

---

## Stage assessment (rental surface)

- **Confidentiality vs untrusted host (the rental value prop):** strong and hardware-rooted. Reaches the
  "GPU owner can't see in" bar.
- **Confidentiality vs the platform:** not claimed-and-met — Chutes is in the TCB (R3).
- **Workload integrity / "my exact container ran," third-party-provable:** does **not** reach a devproof
  posture. There is a real measured admission gate (R2), but the binding is to *a Chutes-signed image*, not
  *the tenant's image*, the key is Chutes', and nothing is anchored in a verifier-readable register (R1).
- **Provenance of the trusted base:** **reachable**
  ([PLATFORM §2](./PLATFORM.md#2-base-image-provenance-is-reachable-not-tofu)), pending an actual
  reproducible-build demonstration.

Net: a renter who only distrusts the **miner** is well served. A renter (or their end-users) who wants to
**prove the specific workload** without trusting Chutes cannot, today — the gap is tenant-controlled signing
+ a measured workload binding.

## Probe / reproduction (no image build)

```bash
# Base image is published + hash-pinned — fetch and verify without building:
#   curl -sL https://vm.chutes.ai/tdx-guest.qcow2 -o tdx-guest.qcow2
#   sha256sum tdx-guest.qcow2   # expect 1d53800f1c18e353ce43bbad886f3b38555b7fc38c3362b04af30d11a16f7b46
# Audit the admission policy + cosign config from source:
#   github.com/chutesai/sek8s  ansible/guest/roles/admission-controller/
# Confirm one golden MRTD across all hardware (RTX 6000 == H200 == B200):
curl -s -H "Authorization: Bearer $(cat /tmp/ck)" https://api.chutes.ai/servers/tee/measurements \
  | jq -r '.[] | "\(.name)\t\(.mrtd[:16])\t\(.runtime_rtmrs.RTMR3[:8])"' | sort -u
```

Cross-reference: companion [`REPORT-inference.md`](./REPORT-inference.md) (consumer surface) and the live
[`OPERATOR-EXFIL-POC.md`](./OPERATOR-EXFIL-POC.md) (which exercises the provider path to demonstrate the
unmeasured-code gap end-to-end). Model-substitution family:
[near-ai-private-inference](../near-ai-private-inference/), [redpill-federated-inference](../redpill-federated-inference/).
