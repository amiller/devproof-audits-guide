# ACI (Attested Confidential Inference) — DevProof Summary

**What:** A protocol spec for confidential inference, published by Phala/Dstack alongside a reference gateway. It defines a workload keyset bound into a TEE quote, channel binding by TLS SPKI or attested E2EE key, per-request signed receipts, and content-addressed "attested sessions" recording each verified upstream hop. One live deployment so far (`tee.redpill.ai`, audited [here](../redpill-phala-aci-gateway/)). Roughly 1,700 lines of spec against 38k LOC of Rust, three months old.

**Verdict: a transparency protocol, not an impossibility protocol — and it says so.** §11 opens by conceding that every guarantee is enforced by the measured code itself and that verification identifies that code but cannot vouch for it. The practical consequence for this guide: **a fully conformant ACI service can still be Stage 0.** ACI provides no upgrade history, no notice period, and no on-chain or transparency-log anchor — three ERC-733 Stage 1 items it leaves entirely to the deployment. A passing `aci verify` is not a Stage verdict; the live deployment passes every check and is Stage 0.

The spec is well made and unusually candid about its own limits. What follows is where a *correct* implementation still leaves a relying party exposed.

**The finding (P1): nothing attested tells a client which serving regime a host is in.** ACI deliberately permits an aggregator to route to upstreams with no TEE, so a client can choose one on purpose. The guards are the operator marking an endpoint TEE-only, or the client setting `provider.aci_verified: true` per request — both opt-in, neither visible in the attestation report. So a client can verify the workload completely, pin the live SPKI, send a prompt, and only learn from the receipt afterward that it was served unverified. For a prompt, afterward is too late.

Demonstrated live, with signed receipts: on the one deployment, a `claude-opus-5` prompt to the open host returns 200 under the same attested keyset, with `upstream.verified: result=failed, required=false` — served by a commercial API, disclosed after the fact, on a receipt that still verifies perfectly. The guard does work when invoked (`aci_verified: true` → 503, prompt never forwarded), which is what makes this a control clients must know to ask for rather than a missing one.

**The receipt machinery itself checks out.** This is the first end-to-end exercise of it: signature under the attested ed25519 key, both body hashes matching our own wire bytes, cited session recomputing to its id, `served_at` inside the window. Seven of seven §9.3 checks.

**Also:** the session list serves content addresses next to abbreviated content that doesn't hash to them (P2 — the spec's own author mis-diagnosed a live adapter this way); the compatibility rule constrains artifact bytes but not what a legacy surface may claim (P3, demonstrated live); and tooling collapses record integrity with policy satisfaction, so a session with a hardware-refuted TCB prints as accepted (P4).

**Fix:** put the effective serving policy for the requested host in the attestation report as a typed field and appraise it in §9.1. Mark abbreviated session entries, or drop `session_id` from them. Add a semantic clause to the compatibility rule: a compatibility surface must not assert a binding the ACI surface does not support.

**Ask them:** is the per-host serving regime meant to be verifiable before a prompt is sent, or is the receipt considered sufficient? That answer decides whether P1 is a spec gap or a deliberate boundary — and it is the one question where the protocol's design intent isn't clear from the text.

---

*Worth reading for the design: the keyset-as-identity construction removes the usual "keys published next to a quote" ambiguity, and the claim vocabulary — `hardware_proven` / `verifier_derived` / `provider_asserted`, with missing evidence as `unknown` rather than a pass — is the cleanest treatment of assertion provenance in any of the systems in this guide. Full detail in `DEVPROOF-REPORT.md`; the §3.1/§3.2/§9.2 checks are reimplemented from the spec text in `verify/aci_verify.py`.*
