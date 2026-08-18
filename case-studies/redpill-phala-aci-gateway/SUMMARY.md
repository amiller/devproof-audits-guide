# RedPill / Phala shared ACI gateway — DevProof Summary

**What:** One dstack TDX CVM serving three hostnames — `tee.redpill.ai`, `inference.phala.com`, `api.redpill.ai` — under one attested workload keyset. It is an aggregator: your prompt terminates here and is forwarded to a model backend (Phala direct, NEAR, Chutes, SecretAI, Tinfoil), with the hop recorded as a re-fetchable attested session. This replaces the old `api.red-pill.ai` per-model attestation surface, which is dead (502 everywhere) and which the [redpill-federated-inference](../redpill-federated-inference/) study audited.

**Verdict: ❌ Stage 0 — but note what got fixed.** The ACI chain here is genuinely sound and reproducible by a third party: the quote verifies to Intel's root, the keyset digest recomputes, the live TLS SPKI for each hostname is in the attested keyset, the Compose is measured into RTMR3 with all four images digest-pinned. The gateway also moved from the dstack **dev** OS to the **production** OS between 2026-08-13 and 2026-08-18, closing the operator root-SSH path that was the previous headline finding. Verified independently: the `is_dev: false` flag is cryptographically bound to the attested `os_image_hash`.

**The finding (G1): the legacy endpoint attests anything you name.** `/v1/attestation/report?model=<id>` is still served for pre-ACI clients. It returns a genuine TDX quote with the old Phala bindings — `report_data == addr||nonce`, keccak key derivation — all of which pass. But the quote is the *gateway's*, and the `model` parameter is ignored: `anthropic/claude-opus-5`, a model this gateway never serves in a TEE, and `does/not-exist-xyz`, which does not exist, both return the same passing attestation and the same signing address. A pre-ACI client reads that as "my model runs in a TEE." It proves only that a TDX workload answers at that hostname. Same class as the Chutes finding: a verified quote that binds neither the code nor the model.

It is technically conformant — ACI's compatibility rule constrains artifact bytes, not what a legacy surface claims. That gap is [P3](../aci-protocol/DEVPROOF-REPORT.md) in the protocol study.

**Also open:** an operator root-key input that attestation cannot rule out (G2), public logs with raw upstream error detail deliberately enabled (G3, error-path only but prompt-derived), admin-mutable routing outside the measurement (G4), and one attested identity spanning both a TEE-only host and an open one where 42 extra non-TEE models are served (G5).

**What works, and is worth saying plainly:** the receipt machinery is real. A live completion produced a receipt whose signature verifies under the attested key, whose request and response hashes match our own wire bytes, and whose cited session recomputes to its id inside its validity window — seven of seven §9.3 checks. And `provider.aci_verified: true` genuinely fails closed: 503, no forward event, signed refusal receipt. Prompts sent to the TEE-only hosts with the constraint set are in a much better position than the Stage verdict alone suggests.

**Fix:** stop accepting a `model` parameter that scopes nothing, or retire the legacy endpoint on a published date. Turn off `request_outcome=debug` while `public_logs: true`. Surface the per-host serving policy in the attestation report so a client can see it before sending, not after.

**Ask them:** does the production dstack 0.5.9 image ship sshd? The prod/dev distinction is bound and real, but I could not reproduce this guide's earlier claim that the production image installs no sshd — both published archives carry the same `openssh` strings. That answer decides whether the root-key input (G2) is a live path or dead code.

---

*Their own [conformance gap register](https://github.com/Dstack-TEE/private-ai-gateway/blob/main/docs/reviews/aci-spec-conformance-gaps.md) already lists the skipped custody policy, the unreproduced build, and the evidence-less Chutes sessions — including why the Chutes fix was tried and reverted. Those are documented, not hidden, and this report treats them as such. Full detail in `DEVPROOF-REPORT.md`; both findings reproduce with `verify/probe_gateway.py`.*
