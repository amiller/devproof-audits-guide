# Attested Confidential Inference (ACI) — protocol DevProof Report

**Date:** 2026-08-18 · **Subject:** `spec/aci.md` (1,696 lines) in `Dstack-TEE/private-ai-gateway`, read at `HEAD` (2026-08-14) · **Reference implementation:** ~38k LOC Rust, first commit 2026-05-19, 276 commits
**Reproduced by:** `verify/aci_verify.py` — the §3.1/§3.2/§9.2 checks reimplemented from the spec text alone — plus the §9.3 receipt checks in [`../redpill-phala-aci-gateway/verify/probe_receipts.py`](../redpill-phala-aci-gateway/verify/probe_receipts.py), both run against the only live deployment (`tee.redpill.ai`)

This is a protocol study, not a deployment one. The live deployment is audited separately in [redpill-phala-aci-gateway](../redpill-phala-aci-gateway/DEVPROOF-REPORT.md); findings here are properties of ACI itself and apply to anyone who implements it.

**DevProof question:** if a service implements ACI perfectly, what can its operator still do to a prompt?

**Verdict: ACI is a transparency-and-binding protocol, not an impossibility protocol — and it says so.** §11 opens with "every guarantee is enforced by the measured code itself; verification identifies that code but cannot vouch for it." That is the right disclosure, and it means **a fully conformant ACI deployment can still be ERC-733 Stage 0**. ACI supplies no upgrade history, no notice period, and no on-chain or transparency-log anchor — three Stage 1 requirements it leaves entirely to the deployment. Reading a passing `aci verify` as a Stage verdict is the error to guard against; the live deployment passes 6/6 and is Stage 0.

The spec is unusually honest. The findings below are places where a *correct* implementation still leaves a relying party worse off than the document reads.

---

## What the protocol delivers

| Property | How |
|---|---|
| The keyset is the identity | No long-lived service keypair: the quote binds the digest of the current keyset, and any key change forces a fresh quote (§3.1). Clean, and it kills the usual "keys published next to a quote" ambiguity — §3.2 states outright that a verifier MUST NOT accept keys not bound through the statement |
| Freshness is the verifier's, not the service's | The client's nonce goes into the statement whose SHA-256 is `report_data` (§3.2). A nonce-less report is permitted and explicitly labelled as proving no freshness |
| The channel is bound to the attested workload | TLS SPKI pinning or an attested E2EE key (§1.1); a WebPKI certificate alone is called out as proving nothing |
| Per-request integrity | Receipts hash the received bytes, the forwarded bytes, and the returned bytes inside the TEE, signed by an attested key (§7). Rewrites are visible as a hash difference. **Exercised live:** all seven §9.3 checks pass on a real completion — ed25519 signature over `JCS(receipt − signature)` under the key `key_id` names in the attested keyset, both body hashes matching our own wire bytes, cited session recomputing to its id, `served_at` inside the window |
| Fail-closed is real | `provider.aci_verified: true` against a host with no attested route returns HTTP 503 with `result: failed`, `required: true`, and **no `request.forwarded` event** — the prompt is not forwarded, and the refusal still carries a signed receipt (§7.5) |
| The upstream hop is auditable | Content-addressed attested sessions, immutable, re-fetchable, with the verifier's raw evidence attached (§8) |
| Claims keep their provenance | `hardware_proven` / `verifier_derived` / `provider_asserted` / `operator_asserted`, and missing evidence is `unknown` — "not a pass, not a refutation" (§8.3) |

Two design choices deserve credit specifically. Canonicalizing ACI's own documents while hashing foreign bytes exactly as observed (Appendix A) is the right split, and it makes receipts self-contained and re-verifiable offline. And the `unknown` status, applied honestly, is what lets a reader see that an aggregator asserting `tee_attested` from `verifier_derived` has proven less than one asserting it from `hardware_proven`.

---

## Findings

### P1 — Nothing attested tells a client which serving regime a host is in *(the finding)*

§1.2 lets an aggregator route to upstreams with no TEE at all, deliberately: "a service MAY also route to upstreams with no TEE (an ordinary commercial API), so a client can deliberately choose one." Protection comes from two levers — the operator marking an endpoint TEE-only, or the client setting `provider.aci_verified: true` per request (§5.3).

Both are opt-in, and neither is visible in the attestation report. A client can do everything §1.1 requires — verify the quote, recompute the keyset digest, pin the live SPKI — and still have its plaintext forwarded to a commercial API, learning this only afterward from `upstream.verified` with `required: false` (§7.5). For a prompt, afterward is too late: the bytes have left.

§5.2 makes it worse in a small way: `X-ACI-Keyset-Digest` and `X-Receipt-Id` are explicitly "unauthenticated hints", and `/v1/models` carries no trust metadata by design ("Clients MUST NOT infer trust from `/v1/models` entries"). So the pre-send surface is: verify the workload, then guess about routing, or opt in.

The live deployment shows the consequence, with signed receipts rather than inference. One attested keyset serves both a TEE-only host and an open one (25 models versus 67). A `claude-opus-5` prompt to the open host returns HTTP 200 under the same `X-ACI-Keyset-Digest`, with `upstream.verified: result=failed, required=false, session_id=None` — served by a commercial API, disclosed after the fact. The receipt still verifies: signature under the attested ed25519 key, both body hashes exact. A client checking the signature but not reading `required` sees a green chain over an unattested hop.

The guard works when invoked: the same request with `provider.aci_verified: true` is refused HTTP 503, with no `request.forwarded` event and a signed refusal receipt. So P1 is not a missing control. It is a control the client must know to ask for, on a surface that looks identical either way until the prompt is already gone.

**Suggested fix:** put the effective serving policy for the requested host in `service_capabilities` as a typed field, and have §9.1 appraise it. A client should be able to learn "this host forces attested serving" from the same document that proves the workload — not from a Compose blob it would have to parse itself, and not from a receipt that arrives after the prompt.

### P2 — The session list hands out ids that don't verify

§8.1 abbreviates list entries: each keeps its `session_id` and `evidence.digest`, and drops `evidence.data`. The spec is explicit that "an abbreviated entry does not hash to its id — fetch the full record to verify." So the list serves a content address next to content that isn't the content it addresses.

This is not theoretical. In [awesome-private-inference#12](https://github.com/amiller/awesome-private-inference/pull/12), the spec's own principal author hashed list entries and reported a spec violation in the Chutes adapter's id computation — a finding that does not survive fetching the full records, where every id recomputes correctly (`verify/aci_verify.py`, 18/18 across six adapters). If the author of the protocol trips on this, a third-party verifier will.

**Suggested fix:** mark abbreviated entries in the payload (`"abbreviated": true`), or omit `session_id` from list entries and make the client fetch. Either removes the trap; the second is stricter and costs a round trip a verifying client is making anyway.

### P3 — The compatibility rule constrains bytes, not meaning

Appendix B permits pre-ACI compatibility endpoints "provided these MUST NOT alter ACI artifacts… and legacy report bindings use their own quotes rather than repurposing the §3.2 statement."

The live deployment complies with both clauses and still ships a compatibility endpoint that returns a passing attestation for any model name, including models it does not serve in a TEE ([G1](../redpill-phala-aci-gateway/DEVPROOF-REPORT.md)). Nothing in the rule is violated: the ACI artifacts are untouched, and the legacy surface uses its own quote and its own `report_data` layout. The rule governs what the compatibility surface may *change*; it says nothing about what the compatibility surface may *claim*.

The deployment's second legacy surface makes the point twice. `spec/related-work.md` documents the pre-ACI per-chat signature convention as `model:sha256(request):sha256(response)` and calls it the ancestor of ACI receipts. The live `/v1/signature/{id}` signs `sha256(request):sha256(response)` — the model prefix is gone. So the compatibility surface is weaker than the convention it exists to be compatible with, and a legacy client written against the documented three-part form mis-parses it or silently skips the model check. Nothing in Appendix B is violated: ACI artifacts are untouched.

**Suggested fix:** add a semantic clause — a compatibility surface MUST NOT assert, or appear to assert, a binding the ACI surface does not support, and MUST NOT weaken a documented predecessor convention without removing the endpoint. Concretely: if the legacy shape was per-model and the ACI service is an aggregator whose quote is gateway-scoped, the legacy endpoint should stop accepting a model parameter rather than ignore it.

### P4 — "Accepted" collapses integrity and policy *(presentation)*

§9.2 separates them properly: steps 1–2 are record integrity, steps 3–4 are *your* policy. The reference client's JSON keeps the split too (`integrity_ok` and `unmet_claims` are distinct fields). Its human output does not — it prints `ACCEPTED` and a tally, so a live session whose `tcb_up_to_date` is `refuted` from `hardware_proven` prints as accepted alongside a clean one. Fifteen NEAR-gateway sessions read exactly that today.

The collapse then propagates: PR #12 rendered it as "every non-Chutes record passed," which in a registry that grades providers reads as an endorsement. Minor as a protocol matter, but this is the sentence downstream readers quote.

**Suggested fix:** have the CLI print policy outcomes beside integrity, e.g. `ACCEPTED (integrity) — 1 claim unmet: tcb_up_to_date refuted`.

### P5 — The chain terminates at an unreproduced build, by design

Everything above the hardware quote is enforced by the measured code: receipt hashing, route enforcement, session recording, `aci_verified`. §9.1(4) proves *which source* the workload declares; §11 concedes verification "cannot vouch for it." Reproducible builds are referenced (§12, Sigstore / reproducible builds / OpenSSF Model Signing) but never required for conformance.

So a conformant ACI service's integrity claims reduce to: the operator's build of the declared source behaves as the reviewed source says. That is a real constraint — the source is public and the commit is measured — and it is not the same as proof. Worth stating plainly in the guide, because the protocol's artifacts (signatures, content addresses, hash chains) read much stronger than the reduction.

### P6 — A rewrite is a boolean, never an explanation *(minor)*

§7.4 makes service-side rewrites visible: `request.forwarded.body_hash` differing from `request.received.body_hash` *is* the rewrite, and §9.3 closes with "whether a rewrite is acceptable is local policy."

A client cannot apply such a policy. It learns that the bytes changed, never how. On the live deployment every request was rewritten — the aggregator consumes the §5.3 `provider` block and normalizes the model id, both legitimate — so the signal is on for 100% of traffic and carries no information. A prompt-altering rewrite and a field-stripping one are the same boolean.

**Suggested fix:** let the receipt name the rewrite classes applied (e.g. `constraints_removed`, `model_id_normalized`) as a typed list. Naming a class is not disclosing content, and it turns an always-true flag into something a policy can act on.

---

## Not devproof surface

- **No non-repudiation** (§11): `served_at` is self-asserted, nothing orders receipts. Disclosed, with SCITT/COSE receipts named as the anticipated fix.
- **`gpu_attested` doesn't bind the GPU to the CPU TEE** (§8.3, §11). Disclosed in the claim's own definition.
- **Metadata exposure** — the service sees IPs, credentials, timing; OHTTP named as the composable fix (§11).
- **E2EE v2 is a stopgap** — flagged in-document with a support horizon and a migration note (§6).
- **Custody policy is deployment-defined** (§3.3). The spec requires verifier policies to specify how custody is checked; it does not check for you. That's the right layering, and it's why the public client's skip is a client gap, not a spec gap.

---

*The most useful thing this protocol does for devproof work is make the operator's choices nameable: which upstream, over which channel, under whose assertion, with what left `unknown`. The trap is that a document full of hash chains invites the reader to think the chain ends in proof, when §11 says plainly that it ends in measured code nobody has rebuilt. P1 and P3 are both versions of the same gap — the protocol binds what it describes very well, and stays silent about the surfaces around it.*
