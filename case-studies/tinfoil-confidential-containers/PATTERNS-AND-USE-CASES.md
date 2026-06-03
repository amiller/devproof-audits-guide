# Notable patterns & use cases — Tinfoil Containers

**Companion to:** [`DEVPROOF-REPORT.md`](DEVPROOF-REPORT.md), [`UPDATES-VS-DSTACK.md`](UPDATES-VS-DSTACK.md), [`ARCHITECTURE-VS-DSTACK.md`](ARCHITECTURE-VS-DSTACK.md)
**Date:** 2026-04-30
**Sources:** docs.tinfoil.sh (full crawl via [`llms.txt`](https://docs.tinfoil.sh/llms.txt) index), [`tinfoilsh/encrypted-http-body-protocol`](https://github.com/tinfoilsh/encrypted-http-body-protocol).

A read of every Tinfoil docs page surfaced a handful of design patterns and use cases worth discussing on their own — some good ideas other TEE platforms could borrow, some interesting tensions, and a couple of explicit gaps.

---

## 1. EHBP — application-layer body encryption that survives proxies

The single most interesting protocol in Tinfoil's stack is the [Encrypted HTTP Body Protocol](https://github.com/tinfoilsh/encrypted-http-body-protocol). It's HPKE (RFC 9180) over X25519 + HKDF-SHA256 + AES-256-GCM, applied to HTTP message bodies *inside* the TLS payload:

```
Request:                                   Response:
  POST /v1/chat/completions HTTP/2           HTTP/2 200 OK
  Authorization: Bearer ...                  Content-Type: application/json
  Ehbp-Encapsulated-Key: <32B hex>           Ehbp-Response-Nonce: <32B hex>
  Content-Type: application/octet-stream

  <HPKE-encrypted body>                      <AES-256-GCM-encrypted body, key
                                              derived from request encap_key
                                              and response_nonce via HKDF>
```

Public key discovery is at the standard `/.well-known/hpke-keys` (RFC 9458 / OHTTP keys format), `application/ohttp-keys` content type. The enclave's HPKE pubkey is the same one bound to `report_data[32:64]` in the SEV report — so the client knows it's encrypting to the attested enclave, not to whoever terminates TLS.

**Why this matters.** TLS terminates wherever the cert was issued for; if you put a CDN, a load balancer, or your own backend in front of an enclave, that intermediary sees plaintext. EHBP HPKE-encrypts the body to the enclave's pubkey *first*, then ships it as opaque bytes through TLS. The intermediary sees URL + headers (for routing + auth) but the body is sealed end-to-end to the enclave. From the EHBP repo README:

> "Proxies can inspect and route upon request metadata without seeing the body."

This is exactly what enables Tinfoil's [proxy-server pattern](https://docs.tinfoil.sh/guides/proxy-server) — keep your `TINFOIL_API_KEY` server-side, let your backend forward EHBP-encrypted bodies the enclave can decrypt, and the API key never enters the browser.

**What EHBP doesn't claim.** From the spec README:
- HTTP metadata (URL, headers, method) is in the clear.
- No protection against traffic analysis (timing, payload size).
- The reference server supports plaintext fallback "for testing" — a downgrade-risk surface to be aware of.

**Generalization.** EHBP is solving a pattern that *every* TEE-on-internet platform has. dstack's `dstack-gateway` terminates TLS and forwards over WireGuard — explicitly accepting plaintext in the gateway as a trust extension. EHBP shows the alternative: keep TLS for transport but layer HPKE for end-to-end body privacy. This could plausibly be standardized as `OHTTP for TEEs` and adopted by dstack, NEAR's cloud-api, Phala's private-AI verifier, etc. None of them currently do.

---

## 2. Enclave-as-anonymizer — the web search pattern

[Tinfoil's confidential web search](https://docs.tinfoil.sh/guides/web-search) has a genuinely clever shape:

- Tinfoil hosts a CVM running a search backend that talks to Exa (a search provider with zero data retention).
- "All users share a single enclave-held API key, so Exa only sees the enclave's IP address."
- Optional in-enclave PII filtering and prompt-injection detection on Exa's results before they reach the model.

Three layers of privacy stacked: queries are encrypted to the enclave (EHBP), the enclave anonymizes via the shared API key, and Exa contractually doesn't retain anything. **Individual users are anonymized at the enclave boundary** — Exa never sees who issued the query.

This generalizes. Any external service that (a) wants to know who's calling, (b) has rate-limit semantics keyed to API keys, or (c) might log queries can be wrapped in an attested enclave that holds the API key and shares it across users. The enclave acts as a verifiable mixnet of one. Plausible adaptations:

- **External LLMs (OpenAI, Anthropic) accessed through an enclave** — the enclave holds the key; you verify what code is wrapping your prompt; the upstream provider sees only the enclave.
- **Vector search via Pinecone / Weaviate Cloud** — same shape for retrieval.
- **Email / SMS sending via Twilio** — abuse-prevention attestation: the upstream provider can prove the rate-limit-bypass risk is contained to the enclave's signed code.

The pattern is essentially "use a TEE to give the user-facing layer the verifiable property that *no individual user identity reaches the upstream service*."

---

## 3. Confidential MCP server — verifiable trust where there usually isn't any

Tinfoil hosts an MCP server at `websearch.tinfoil.sh/mcp` (source: [`tinfoilsh/confidential-websearch`](https://github.com/tinfoilsh/confidential-websearch)). The MCP server provides web-search tools to MCP clients (Claude Desktop, Cline, Cursor, etc.).

MCP servers are normally trusted-by-default — they have arbitrary local access, can read files, exfiltrate, etc. Standard MCP usage assumes you read the server's source (or trust the publisher) before wiring it up. **Putting an MCP server in a TEE inverts this**: clients can verify the server's code measurement matches a published Sigstore-signed release, without trusting the server operator at all.

This opens up a design space:

- **Verifiable MCP marketplace.** Today's MCP server lists are basically `npm`-style trust-the-publisher. An attested-MCP marketplace could let clients pin to specific code measurements.
- **Composable confidential agents.** An LLM in an enclave + a tool-calling MCP server in another enclave + cross-enclave secret sharing via TEEBridge gives you an end-to-end verifiable agent stack. We already wired the Tinfoil leg of TEEBridge in [Account-Link/tee-interop#1](https://github.com/Account-Link/tee-interop/pull/1); the missing piece is for the agent to use TEEBridge as the trust root for which MCP servers it'll call.
- **Confidential tool execution as a service.** Same shape applied to *running* tools (code execution, browser automation) inside an enclave with attested code.

---

## 4. Three caching proxies and the verification hot path

The architecture page mentions three caching proxies Tinfoil maintains:

| Proxy | What it caches | Trust extension |
|---|---|---|
| `atc.tinfoil.sh/attestation` | Per-deployment attestation bundles (SEV report, Sigstore bundle, VCEK, enclave cert) | Tinfoil sees which clients are verifying which deployments. Cache invalidation could lie. Mitigated by clients re-checking the live `/.well-known/tinfoil-attestation` endpoint (which the bundle path is layered on top of) |
| `github-proxy.tinfoil.sh` | GitHub release downloads (`tinfoil.hash`, `tinfoil-deployment.json`) and Sigstore attestation API responses | Tinfoil could serve stale or substituted Sigstore bundles. Mitigated because the bundle is signed with content cryptographically chained to the running enclave's measurement |
| `tdx-proxy.tinfoil.sh` | Intel PCS responses (TCB info, CRL, etc.) for TDX enclaves | Same shape — could serve stale collateral. Mitigated by TCB freshness checks in the verifier |

Plus presumably an AMD KDS proxy (the docs reference one but didn't name it).

**Why proxies?** Latency. Each verification fetches multiple round-trips of attestation data; doing them all over the open internet would add hundreds of ms. Tinfoil's proxies cache aggressively and serve from the same edge as the enclave hosts.

**Trade-off.** The proxies are operated by Tinfoil. A user who paranoid-wants to verify "from scratch" must override the proxy URLs (none of the SDKs document how, but the code is open). For most users, the proxies are a usability win that doesn't expand Tinfoil's adversary surface (signatures still chain back to vendor + Sigstore roots) but does add a centralization point that *could* censor or stall verification.

---

## 5. Verification Center — UX widget with a centralization wrinkle

[`verification-center.tinfoil.sh`](https://verification-center.tinfoil.sh) is an embeddable iframe component that renders "real-time enclave verification status" — green check / yellow warning / red error — inside any web page that wants to show users their TEE is healthy.

Three states: ✓ Success, ⚠ HPKE Key Mismatch, ⚠ Fingerprint Mismatch. Backed by the same underlying SDK verification.

**The wrinkle.** The iframe's *own* origin is `tinfoil.sh`. A user trusting the iframe is also trusting:
- That `verification-center.tinfoil.sh` itself isn't MITM'd
- That the iframe's JavaScript isn't substituted or compromised
- That the iframe wasn't replaced with a fake one by the embedding page

Standard iframe-trust caveats. For most web apps that show their users "private chat is verified," this is fine — but it's worth noting that the visual confirmation is itself rooted in trusting Tinfoil's own infrastructure. A purist would run their own verification client locally.

---

## 6. Path allowlisting via `shim.paths`

Small but elegant primitive. The `tinfoil-config.yml` declares which paths the public domain serves:

```yaml
shim:
  upstream-port: 8080
  paths:
    - /v1/chat/*
    - /v1/embeddings
    - /health
```

Anything outside this list returns 404 at the shim layer, before it ever reaches the container. Acts as an attack-surface reducer — your container might expose `/admin` internally, but if it's not in `paths`, no external request can reach it.

Generalizable. Could be tightened further: per-method allowlists (`POST /v1/chat/*` only), regex-based, etc. The current `*` wildcard syntax is enough for most cases.

---

## 7. Platform constraints — what Tinfoil deliberately doesn't do

The [overview](https://docs.tinfoil.sh/containers/overview) explicitly lists **what Tinfoil Containers does NOT support**:

- No persistent storage (ramdisk only)
- No built-in horizontal scaling or load balancing
- Single instance per container (one container name = one CVM)
- No inbound private networking

These are deliberate design choices that follow from the "fresh enclave per launch + TLS terminates in enclave" architecture. Worth comparing to dstack which supports all of the above (encrypted persistent disks, multi-CVM HA via shared `app_id`, gateway-terminated TLS for routing, WireGuard-based inbound mesh).

Also from [resource limits](https://docs.tinfoil.sh/containers/limits):
- 10 containers per organization
- 2 instances per repository
- CPU: 2 / 4 / 8 / 16 / 32 cores
- Memory: 8 / 16 / 32 / 64 / 128 GB

Hard caps; ask Tinfoil to raise. The two-per-repo cap is interesting: it explicitly constrains the "many copies of the same code" pattern that you'd want for HA.

---

## 8. Notable docs gaps — what's *not* there

A read of every page surfaced four omissions worth flagging:

1. **No formal threat model.** The introduction lists capabilities but never the symmetric "what we explicitly do NOT defend against" section. Things like: traffic analysis (EHBP itself admits it doesn't), side-channel attacks on shared SEV hosts, controlplane-level attacks (e.g., Tinfoil employee-driven host swap mid-deploy), the gap between "secret stored encrypted in dashboard" and "secret crosses host plaintext to enclave" (which the [secrets-and-env-vars](https://docs.tinfoil.sh/containers/secrets-and-env-vars) page does mention but the introduction doesn't) — all left to user inference.

2. **Custom domain TLS chain unspecified.** [The custom-domains page](https://docs.tinfoil.sh/containers/custom-domains) covers DNS verification (CNAME / TXT) but doesn't say whether the cert is Let's Encrypt-issued or remains the SEV-attested self-signed cert with DNS pointed at it. This matters for verifier-pinning behavior. Worth a doc fix or, if Let's Encrypt, an architectural caveat.

3. **RAG tutorial papers over state.** The [Verba+Weaviate guide](https://docs.tinfoil.sh/tutorials/verba) walks through `docker-compose up -d` for a stateful RAG pipeline without addressing how the vector DB state survives Tinfoil's "ramdisk only" constraint. In practice, the user must either run Weaviate externally (losing the privacy point) or accept that state vanishes on relaunch (rebuilding the index from source documents on every redeploy).

4. **Controlplane is closed-source.** `gh api repos/tinfoilsh/controlplane` returns 404. The orchestration layer that decides which physical host runs which CVM, holds the org's secret store, manages updates, and computes billing isn't auditable. For a security-positioned product this is the largest single gap from a transparency perspective.

---

## 9. The big picture pattern — what space is Tinfoil really exploring?

Synthesizing the design choices:

> **"Stateless enclaves with verifiable code, accessed via body-encrypted HTTP, orchestrated by a closed controlplane on Tinfoil-owned hardware."**

Each clause is a deliberate choice with tradeoffs:

- **Stateless** — no state to lose, but requires "bring your own state layer" for non-trivial apps
- **Verifiable code** — Sigstore + GitHub OIDC, repo-owner controlled
- **Body-encrypted HTTP (EHBP)** — works through arbitrary HTTP infrastructure; doesn't protect metadata
- **Closed controlplane** — fast, polished UX; centralization point that can't be replaced
- **Tinfoil-owned hardware** — quality control, no host marketplace yet

The fit is "stateless serving workloads where the developer wants user-verifiable code and minimal infrastructure friction." Inference is the canonical case. Anything stateful needs to layer something on top.

The interesting design questions Tinfoil is implicitly opening for the broader TEE ecosystem:

- **Can EHBP be the standard "TLS doesn't go far enough" protocol?** It's well-specified, has reference implementations, and solves a real cross-platform gap.
- **Is "verifiable MCP / verifiable tools" a real product space?** The websearch case study suggests yes.
- **What does "Tinfoil but on-chain" look like?** Sketched in [`ARCHITECTURE-VS-DSTACK.md`](ARCHITECTURE-VS-DSTACK.md) §6 — converges with dstack from the other direction.

---

## Use cases worth highlighting

| Use case | Why it's interesting | Where it lives |
|---|---|---|
| Confidential web search | Enclave-as-anonymizer; shared API key per enclave masks individual users from the upstream provider | `websearch.tinfoil.sh` ([source](https://github.com/tinfoilsh/confidential-websearch)) |
| Confidential MCP server | Inverts the "MCP server = trust the publisher" default; clients verify code measurement | Same `websearch.tinfoil.sh/mcp` |
| Private LLM coding (Cline + Tinfoil) | IDE assistant where the prompt never leaves an attested enclave | [docs.tinfoil.sh/tutorials/cline](https://docs.tinfoil.sh/tutorials/cline) |
| Tool calling through verified inference | Combines verifiable LLM + verifiable tool execution; both attested and bound to the same trust chain | [docs.tinfoil.sh/guides/tool-calling](https://docs.tinfoil.sh/guides/tool-calling) |
| Image / document processing | Attested vision/parsing pipelines for sensitive content | [docs.tinfoil.sh/guides/image-processing](https://docs.tinfoil.sh/guides/image-processing) |
| Private RAG (Verba + Weaviate) | Aspirational — the docs don't address state persistence; works as an in-memory index that rebuilds on each launch | [docs.tinfoil.sh/tutorials/verba](https://docs.tinfoil.sh/tutorials/verba) |
| Hermes Agent | Multi-step agent with attested inference at each step | [docs.tinfoil.sh/tutorials/hermes-agent](https://docs.tinfoil.sh/tutorials/hermes-agent) |
| Bring-your-own state via TEEBridge | Cross-CVM secret sharing on chain; combines Tinfoil's stateless serving with persistent identity | [Account-Link/tee-interop](https://github.com/Account-Link/tee-interop) |

The ones that *don't* exist yet but should, given the patterns above:

- A reusable "external-API privacy proxy in a TEE" template (the Exa pattern, generalized — TwilioProxy, AnthropicProxy, OpenAIProxy, etc.)
- A verifiable-MCP-server template for arbitrary tools
- An attested OHTTP-style relay that uses EHBP under the hood (mixnet of one, but for HTTP)
