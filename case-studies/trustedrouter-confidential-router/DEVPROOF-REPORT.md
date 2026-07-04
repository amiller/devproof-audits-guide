# TrustedRouter (Quill Cloud) — DevProof Report

**Date:** 2026-07-03 · **Platform:** GCP Confidential Space (Intel TDX) · **Attested workload:** `Lore-Hex/quill-cloud-proxy` @ `648ea31` (`sha256:fc1bf8ff…e2593`)
**Live:** trust page `trust.trustedrouter.com` · attestation `api.trustedrouter.com/attestation` · checks reproduced by `verify/verify-attestation.py`

**DevProof question:** can the operator rug users — read, redirect, or alter prompts, or run different code — without it showing up in attestation? All repos cloned; the Go enclave read directly at `648ea31`.

**Verdict: ~Stage 1.** The chain is clean and the operator surface is small — routing is hardcoded, nothing is stored, the control plane is metadata-only. One residual (**G6**) lets the operator defeat the confidentiality claim in a way per-session verification cannot catch.

---

## What's proven (constrains the operator)

| Property | Verified |
|---|---|
| Attestation is authentic | JWT RS256 verifies against Google JWKS (`signer@confidentialspace-sign`); `hwmodel=GCP_INTEL_TDX`, `swname=CONFIDENTIAL_SPACE`, `dbgstat=disabled-since-boot`, TCB `UpToDate` |
| Bound to *this* connection | `eat_nonce[0]` == SHA-256(served leaf DER), checked against the live cert — a MITM with a different cert can't replay a valid token |
| Running code == published source | Token `image_digest` == `gcp-release.json` == `image-digest-gcp.txt`, byte-exact, pinned to commit `648ea31` |
| No hidden config | Operator `env_override` is echoed verbatim into the signed token; secret *values* stay in Secret Manager, released only to the attested image |
| Routing can't be redirected | Every upstream URL is a hardcoded `case` in `directBaseURL` in the measured binary; `default→""` hard-errors. The control plane picks a provider *label*, never a URL |
| No prompt/output storage | No request/response body is written anywhere; BYOK secrets in-memory only, 2-min TTL |
| Control plane is metadata-only | `authorize`/`settle` send key-hash + token counts, never content — enforced by a regression test |

**Trust boundary:** only `quill-cloud-proxy` (the Go enclave) is measured. The Python control plane `quill-router` runs outside the TEE and is **not** attested — its source shows intent, not what the operator actually runs. (Relevant to G5.)

---

## Residual operator surface

### G6 — Shared TLS private key is readable by the operator *(the finding)*
The nonce binds whichever cert is served; "TLS terminates in the enclave" assumes the private key never leaves. It does. To share one cert across replicas, the enclave writes the cert **+ private key** to `gs://quill-acme-cache` under CMEK `acme-cache-envelope`, which the code's own comment says is **not** image-bound (*"a future hardening step… locked to the workload's image digest, the way the device keys are"*).

So the operator — who owns the GCP project — can read that key, run a proxy presenting the **genuine** cert, and relay a **genuine** attestation minted by the real enclave. Every client check passes while the proxy reads and alters plaintext. **This is the one gap a verify-every-session client can't catch:** nothing binds the TLS *session* to the enclave, only the cert, and the cert is shared and exportable.

It's structural, not a config slip: "only the enclave decrypts" reduces to a GCP IAM setting — not attested, unprovable to a third party (you'd have to prove the operator *lacks* decrypt), and operator-mutable. With no external key authority, the operator *is* the KMS admin, so IAM gating is self-referential. Image-gating the key would at least make a bypass an audit-logged IAM change instead of a silent read; fully removing the trust needs an external KMS (architectural).

*Caveat: the GCP IAM isn't public (infra repo is AWS-only), so I can't confirm it's exploited today — only that nothing in the code prevents it.*

### G5 — Unattested control plane can inject a content webhook *(minor)*
The `authorize` response can carry a broadcast destination `{IncludeContent:true, Endpoint:<any URL>}`; with content included, the enclave POSTs prompt+completion there. By design it's per-workspace user config (`storage_broadcast.py`), but because the control plane is unattested, a malicious operator could inject a destination the user never set, and the enclave can't tell the difference. Low weight — dominated by G6, and only bites if content-broadcast is exposed to users.

---

## Not devproof surface
- **`quill` repo is private (404) but not in the attested image** — the Dockerfile is `COPY .` of `quill-cloud-proxy/enclave-go` + `FROM scratch`, no dependency on it. A backdoor there can't reach the enclave; it's client-SDK code, and the shipped verifiers (`trusted-router-js/-py`) are public. Ruled out.
- **Automatic upgrades, no notice period** — mooted: no persistent state + per-session verification means a silent upgrade shows as a new digest on the next request, *provided* the client pins a digest tied to reviewed source, not the operator-auto-committed trust page.
- **Reproducible build / cosign coverage / second-nonce docs** — provenance hygiene. The digest is authenticated and session-checkable; the GCP image isn't independently rebuildable and the GCP release files are unsigned (cosign runs only on the AWS path) — none of it affects operator access. Optional hardening.
- **The router sees plaintext by design** — the enclave decrypts and forwards to upstream providers, who see the prompt. Inherent; the chain proves *which gateway* decrypts, not that upstreams don't retain.

*First GCP Confidential Space study in the guide; trust is anchored to Google + a Git-committed trust page, with no on-chain KMS/registry — which is exactly why G6 has no fully-clean fix.*
