# TrustedRouter — DevProof Summary

**What:** An attested LLM router. Your TLS connection terminates inside a GCP Confidential Space (Intel TDX) enclave, which decrypts your prompt and forwards it to upstream providers. First GCP Confidential Space study in the guide; verified live at commit `648ea31`, enclave code read directly.

**Verdict: ~Stage 1, one fixable finding.** The attestation chain is clean and the surface is small: nothing stores prompts, and every upstream URL is hardcoded in the measured binary, so the control plane can't redirect your prompt. That leaves the entire confidentiality claim resting on one question — **is the enclave really the endpoint decrypting your traffic?**

**The finding (G6): not guaranteed today.** To share one cert across replicas, the enclave caches the TLS *private key* in a GCS bucket the operator can read (the KMS key isn't bound to the enclave image). With that key, the operator can run a proxy that presents the genuine cert and relays a genuine attestation from the real enclave — every client check passes while they read plaintext in the middle. It's the one gap that a client verifying attestation every session still can't catch, and it means "only the enclave decrypts" rests on a GCP IAM setting: not attested, unprovable to a third party, changeable by the operator. A trust-me, not a proof.

**Fix:** there's no fully clean one without an external key authority they don't have (one shared public hostname needs a shared cert, so the key has to live *somewhere*). The practical improvement is to gate that KMS key on the enclave image digest: the operator still *could* rewrite the key policy to read it, but only via an audit-logged change instead of today's silent decrypt-by-ownership. Removing operator trust entirely would need a dstack/Phala-style external KMS — a real architectural change.

**Ask them:** is the ACME-cache KMS key gated on the enclave image digest, or can the project owner decrypt it? That single answer decides the verdict.

---

*Everything else is hygiene, not a leak: the GCP image digest is authenticated but not independently rebuildable, the GCP release files are published unsigned, and the one private repo (`quill`) isn't in the attested image. Worth raising with them; none of it exposes prompts. Full detail in `DEVPROOF-REPORT.md`.*
