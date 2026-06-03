# TODO — Confidential AI / Lunal

## Open threads
- [ ] **attestation-go parity** — does the Go verifier (`attestation-go`) repeat the optional-binding / no-measurement posture, or enforce more? (not yet read)
- [ ] **kettle deep-dive** — is the published `ghcr.io/lunal-dev/attestation-api` image actually built via `kettle`? Is its measurement published anywhere a user can pin (would close F6)?
- [ ] **C8s CDS** — the whitepaper's Certificate Distribution Service + signed allow-list + NRI image-policy enforcer are in **no public repo examined**. Confirm whether C8s is shipped, in a private repo, or aspirational. This determines whether F1 is "library gap" or "product never built the design."
- [ ] **Full Confidential Agents API** — scrape `confidential.ai/docs/confidential-agents-api` end-to-end (POST /v1/instances flow); confirm whether any provisioning step pins a measurement.
- [ ] **Live product path** — `api.confidential.ai` needs a bearer token (401). With a key, check whether the *authenticated* responses carry a fresh, nonce-bound attestation (vs the static demo header on llama-3b.lunal.dev).

## Possible deliverables (not started)
- [ ] Issues / disclosure draft: propose (1) `expected_measurements` in `VerifyParams` + fail-closed, (2) enforce-by-default verify mode, (3) per-request nonce binding + client-side GPU (NRAS) verification, (4) WASM through `verify_evidence`.
- [ ] Add to LEARNINGS.md: the "verification toolkit vs verification policy" anti-pattern (lib returns facts, callers gate on `signature_valid`).
