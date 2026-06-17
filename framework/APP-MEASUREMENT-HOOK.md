# The App-Measurement Hook Gap

**Date:** 2026-06-16
**Status:** Cross-vendor gap pattern — recommendation for confidential-inference platforms

---

## Problem

A TEE quote can only attest what is **measured**. On the confidential-inference platforms
we've audited, the measured boundary stops at the **base image**: firmware, kernel, initramfs,
and a generic rootfs all land in MRTD/RTMR0-2, and `report_data` binds the session key
(`SHA256(nonce‖e2e_pubkey)`). But the **application layer** — the per-deployment code that
actually touches user plaintext, and the model weights it serves — is **outside** that
boundary, and there is **no developer-facing way to put it inside**.

Two structural reasons it falls outside:
1. **Application code is excluded from the measurement.** The handler source (e.g. chutes
   `/app/chute.py`) is excluded from the filesystem-integrity index, or injected at runtime
   into a generic signed image, so it is in no RTMR.
2. **Weights are pulled at runtime**, *after* the image is measured — nothing downloaded
   post-boot can be in the boot measurement.

The result: a fully verified quote proves "a genuine TEE running *some* platform-blessed base
image," not "*this* code, serving *these* weights." The developer is given **zero attested
surface** to declare what they run. This is the missing primitive — an **app-measurement
hook**: a way for the workload to extend a measurement (or contribute to `report_data`) with a
digest it chooses, so the quote carries an honest, third-party-checkable statement of the
application identity.

## Why it matters (two distinct failures from one root cause)

Both observed live on chutes (`case-studies/chutes-confidential-inference/`,
`OPERATOR-CODE-EXFIL-2026-06-16.md`); the root cause is general.

- **Model substitution.** The served model is in no measured register. An operator points the
  same named, `verified=True`, billed endpoint at arbitrary weights — demonstrated at **$0**
  (SmolLM2-1.7B served under a `…Euryale-70B…` name). The client verifies a perfect quote and
  is talking to a different model.
- **Prompt exfiltration (worse).** The decrypted plaintext is handed to unmeasured,
  operator-authored handler code *inside* the enclave. That code can log, accumulate
  cross-request in RAM, or return harvested prompts to a colluding client over the legitimate
  response channel — **egress-free**, undetectable to a verifying client. The TEE protects the
  prompt from the host and control plane, but **not from the operator's own in-enclave code**,
  because that code isn't attested.

The second is the load-bearing point: pinning the *model* is not enough. The measurement
target must be the entire **prompt-path surface** — handler code **and** weights.

## Cross-vendor

This is not a chutes-specific bug; it is what falls out of the "one golden image, app loaded
dynamically" architecture that confidential-inference platforms converge on (it's why all of a
platform's models can share a byte-identical MRTD). The same model-substitution gap is recorded
for `near-ai-private-inference/` and `redpill-federated-inference/`. The recommendation below
is therefore a **framework-level** ask, not a single finding.

## The fix: two halves, both required

A measurement is worthless without its preimage; a disclosed preimage is worthless if you
can't prove it's what runs. You need both.

### 1. The measurement hook
Expose a runtime API that extends a dedicated register (e.g. RTMR3, or a named app-measurement
slot) — or contributes bytes alongside the session key in `report_data` — with a
developer-chosen digest:

```
H_app = SHA256( canonical(handler_source) ‖ image_digest ‖ model ‖ revision ‖ weights_digest )
```

Critical detail — **measure after the runtime download.** Because weights arrive post-boot, the
hook must fire in the startup hook *after* the model is fetched, hash the **on-disk weight
files**, and extend that. Then the quote reflects the *actually loaded* weights, not just the
image. The base image keeps its shared golden MRTD/RTMR0-2; only the app register diverges per
deployment — so the platform keeps its fleet-of-identical-VMs operational model and loses only
the ability to **silently** substitute.

### 2. Preimage disclosure
A digest is uncheckable without knowing what it should be. The platform must expose the
deployed handler source + model/revision (+ a weights digest) at a public endpoint — today even
*public* chutes return `code: null`. Ideally with a reproducible derivation so a verifier can
recompute `H_app`. This is exactly dstack's pattern: `compose_hash` (measured into the quote)
+ `app_compose` (disclosed at the 8090 endpoint) + reproducible MRs (`dstack-mr`). The
inference cohort has the enclave half and is missing both the app-measurement half and the
disclosure half.

## Verifier flow once the hook exists

1. Fetch + verify the quote (DCAP sig, debug off, `report_data[0:32]==SHA256(nonce‖e2e_pubkey)`,
   golden MRTD/RTMR0-2 for the base image).
2. Fetch the disclosed preimage (handler source, model, revision, weights digest).
3. Recompute `H_app` and check it equals the app register in the quote.
4. (Optional, the residual trust) audit the disclosed handler source / diff the weights digest
   against a known-good reference.

## The honest caveat: identity, not intent

The hook pins *what runs*, not *that what runs is safe*. A malicious-but-measured handler, or a
model fine-tuned to steganographically leak, still passes its own measurement. The hook's value
is that it makes the prompt-path **auditable** — "is the disclosed code safe?" becomes a public,
tractable question instead of an invisible one — which is the most attestation can deliver. It
does not remove the need for source review; it makes source review *possible and binding*.

## Audit checklist (apply to any confidential-inference vendor)

- Does the quote's `report_data` / RTMRs bind anything beyond base image + session key? (Diff
  the quote across two different models on the same hardware — if MRTD+RTMR0-3 are byte-identical,
  the app/model is unmeasured.)
- Is the handler/application code in *any* measured register, or excluded / runtime-injected?
- Are weights measured (baked into the measured image, or hashed-on-disk post-download), or
  pulled at runtime with no measurement?
- Is the deployed code disclosed to a third-party verifier, with a reproducible derivation of
  its expected measurement?
- If any answer is "no": confidentiality and model-identity claims **reduce to operator-trust**,
  regardless of how sound the enclave crypto is.

## Cross-references

- Live demonstration + SDK trace: `case-studies/chutes-confidential-inference/OPERATOR-CODE-EXFIL-2026-06-16.md`
- Canonical chutes findings F1 (model not measured) / V0/F3 (plaintext exposure): same case study's `DEVPROOF-REPORT.md`, `EXPLOITABILITY-VALIDATION.md`
- Same gap, other vendors: `case-studies/near-ai-private-inference/`, `case-studies/redpill-federated-inference/`
- Reference design (measured + disclosed + reproducible): the dstack cohort (`compose_hash` / `app_compose` / `dstack-mr`)
- Related framework gaps: `DOMAIN-BINDING-GAP.md` (binding mutability), `TEE-SIGNED-USAGE-REPORTS.md` (proving users hit the attested code)
