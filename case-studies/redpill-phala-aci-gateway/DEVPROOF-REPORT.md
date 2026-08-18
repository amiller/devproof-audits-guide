# RedPill / Phala shared ACI gateway — DevProof Report

**Date:** 2026-08-18 · **Platform:** dstack on Intel TDX (`dstack-0.5.9-bd369a8c`, no GPU in this TD) · **Attested workload:** `Dstack-TEE/private-ai-gateway` @ `30296dd` (source declaration; not rebuilt)
**Live:** `tee.redpill.ai` · `inference.phala.com` · `api.redpill.ai` — one CVM, one workload keyset (`sha256:c6e808d3…`), three hostnames, each with its own SPKI in the attested keyset
**Reproduced by:** `verify/probe_gateway.py`, `verify/probe_receipts.py` (live receipts, both regimes) and `../aci-protocol/verify/aci_verify.py`; quote checked with the upstream `aci` client at `Dstack-TEE/private-ai-gateway@HEAD`

**DevProof question:** can the operator read, redirect, or substitute a prompt without it showing up in attestation? This is an aggregator, so the question splits: what the gateway itself can do, and what it can do to the upstream hop.

**Verdict: ❌ Stage 0.** The ACI chain on this deployment is sound and independently reproducible — quote, keyset binding, measured Compose, live TLS SPKI all check out, and the OS is now the production image. Stage 0 rests on **G1**, a live compatibility endpoint that mints a passing attestation for models this gateway never serves in a TEE, plus an operator surface (**G2**, **G3**) that attestation cannot rule out.

This deployment moved to the production OS between 2026-08-13 and 2026-08-18, closing the dev-image root-SSH path that [PR #12](https://github.com/amiller/awesome-private-inference/pull/12) documented. That correction is reflected below.

---

## What's proven (constrains the operator)

| Property | Verified |
|---|---|
| Genuine TDX, fresh | `aci verify` → quote verifies to Intel root via `dcap-qvl` + Phala PCCS, TCB `UpToDate`, `report_data` = SHA-256 of the §3.2 statement over our own nonce |
| Keyset is the identity | `workload_keyset_digest` recomputes from the served keyset's JCS form; the quote binds that digest — no key appears beside the quote unbound |
| Bound to *this* connection | Live TLS SPKI for each hostname is listed in the attested keyset (`22ad6f73…` / `8bafb8e6…` / `c68585e7…`) |
| Production OS, bound | RTMR3 `os-image-hash` = `bd369a8c…`; resolved independently against `download.dstack.org` (`os_image_hash == sha256(sha256sum.txt)`, `metadata.json` listed in it) → dstack **0.5.9, `is_dev: false`**. `aci verify --require-production-os` passes |
| Code measured | Compose hash `73fa4608…` measured into RTMR3; all four container images pinned by digest, including `dstacktee/dstack-verifier:0.5.11@sha256:06a20b77…` |
| Control plane is metadata-only | `consult_pre` sends `{apiKeyHash?, model?, provider?, tee?}` and nothing else (`src/middleware/control.rs`); fails closed on any non-200, bad JSON, timeout or transport error |
| Upstream hop is recorded | 237 attested sessions published; every non-Chutes record fetched in full recomputes its own id and its `evidence.data` hashes to `evidence.digest` |
| Receipts are real | A live completion on `tee.redpill.ai` produced a receipt whose ed25519 signature verifies under the attested `receipt_signing_keys` entry (`dstack-kms-receipt-ed25519-v1`), whose `request.received` and `response.returned` hashes match the exact bytes on our wire, and whose cited session recomputes to its id with `served_at` inside the validity window. All seven §9.3 checks pass |
| Required verification fails closed | With `provider.aci_verified: true` on the open host, a `claude-opus-5` request returned **HTTP 503** with `result: failed`, `required: true`, **no `request.forwarded` event** — the prompt was not forwarded, and the refusal itself carries a signed receipt |

**Trust boundary:** only this gateway TD is measured. The model CVMs it forwards to are separate workloads, verified by the gateway and published as sessions — their claims are the gateway's assertions about someone else, upgraded to independently checked only if you do the §9.2 deep audit yourself. The control plane (authorization, catalog, route selection) runs **outside** the TD.

---

## Residual operator surface

### G1 — The legacy endpoint attests anything you name *(the finding)*

`GET /v1/attestation/report?model=<id>&nonce=<hex>` is still served, for pre-ACI clients. It returns the old Phala shape — `signing_address`, `signing_public_key`, `intel_quote`, `nvidia_payload` — and it passes every check a pre-ACI client performs: genuine TDX quote, `report_data == addr.ljust(32) || nonce`, `keccak(pubkey)[-20:] == signing_address`. All three hold live.

The `model` parameter is ignored. The quote is the **gateway's**, and `signing_address` is identical for every model name:

```
tee.redpill.ai  anthropic/claude-opus-5  -> 200, valid quote, 0x79a5061e…
tee.redpill.ai  does/not-exist-xyz       -> 200, valid quote, 0x79a5061e…
api.redpill.ai  openai/gpt-5-nano        -> 200, valid quote, 0x79a5061e…
```

A pre-ACI client — the population this endpoint exists to serve — reads that as "the model I asked for runs in a TEE." What it actually proves is that a TDX workload exists at that hostname. This is the same class as the Chutes finding ([chutesai/chutes#75](https://github.com/chutesai/chutes/issues/75)): a verified quote that is not bound to the code or the model.

The second legacy surface doesn't rescue it. `GET /v1/signature/{chat_id}` — the per-chat signature a pre-ACI client would pair with the report — signs this:

```
text = "<sha256(request bytes)>:<sha256(response bytes)>"
```

Two hashes, no model. Their own [related-work note](https://github.com/Dstack-TEE/private-ai-gateway/blob/main/spec/related-work.md) describes the ancestor convention this endpoint implements as `model:sha256(request):sha256(response)` — so the compatibility surface is *weaker than the convention it exists to be compatible with*. A legacy client written against the documented three-part form either mis-parses it or silently drops the model check.

What the signature does bind is real: the exact request bytes (transitively, the model the client *asked* for) and the exact response bytes, under the gateway's attested key. What nothing in the legacy world binds is which upstream actually served — the gap `upstream.verified` closes on the ACI side.

It is *technically conformant*. ACI Appendix B permits compatibility surfaces provided they don't alter ACI artifacts and use their own quotes rather than repurposing the §3.2 statement — and this one complies on both counts (its `report_data` is the legacy layout, and an ACI verifier pointed at it fails closed on the §3.2 check; the signature response even embeds the modern receipt). The rule constrains bytes, not the semantics a legacy client reads off them. See the [protocol study](../aci-protocol/DEVPROOF-REPORT.md), **P3**.

**Fix:** stop accepting a `model` parameter that no longer scopes anything, and return a document that a pre-ACI client cannot mistake for a per-model attestation — or retire the endpoint on a published date.

### G2 — Operator root-key input, on an OS whose SSH surface I could not rule out

`allowed_envs` still includes `DSTACK_ROOT_PUBLIC_KEY`, and the measured pre-launch script still writes it to `/home/root/.ssh/authorized_keys` (it evaluates `DSTACK_ROOT_PASSWORD` first, same script). Attestation shows the *capability*, never whether a key was supplied — so it cannot rule out operator access to the TD.

On the previous dev image this was straightforwardly disqualifying. On the production image it should be inert, and this registry's earlier RedPill audit asserted that the prod dstack image "installs no sshd and runs `disable_login()`." **I could not reproduce that claim**: the published `dstack-0.5.9` and `dstack-dev-0.5.9` archives carry the same `openssh` strings in their initramfs, at the same counts. The prod/dev distinction here rests on the bound `is_dev` metadata flag, which is real and cryptographically anchored, not on a demonstrated absence of sshd.

**Ask them:** does the production 0.5.9 image ship sshd, and does the pre-launch script's `authorized_keys` write reach anything on it? That answer decides whether G2 is a live path or dead code.

### G3 — Public logs with raw error detail enabled

The measured config sets `public_logs: true` and `RUST_LOG=info,request_outcome=debug`. The attested source is explicit about what that combination means (`src/middleware/completion.rs:153`):

> Upstream error bodies can echo request content (validation errors quoting input, signed URLs), and this gateway's confidentiality model treats logs as operator-visible — so raw detail is opt-in via the tracing filter.

Opt-in, and this deployment opts in. `detail_snippet` caps it at 240 characters. The code's default is the safe one; the deployment overrides it. Error-path only, not every prompt — but it is prompt-derived content on an operator-visible surface, in a system whose claim is that prompts are visible only inside verified workloads.

### G4 — Routing is admin-mutable outside the measurement

The measured upstream seed is `[]`. Live routes live in `upstreams.json` on the `pal-state` volume and are replaced wholesale through `PUT /v1/admin/upstreams`, guarded by a bearer `admin_token` injected as a dstack encrypted secret (`src/http/app/util.rs:118` — the route 404s when no token is configured, so it cannot be reached unauthenticated). `tee_only_domains` constrains *which regime* applies per hostname (G5), and clients can pin `aci_session_ids` (§5.3), but the effective routing policy is not itself measured. Receipts expose the choice after the fact.

Worth stating precisely, because it is the honest limit: the admin API cannot make an unverified upstream *look* verified — sessions and receipts are produced by measured code. It decides which verified upstream you get, and on a non-TEE-only host, whether you get a verified one at all.

### G5 — One attested identity spans two serving regimes

`tee_only_domains` is `["tee.redpill.ai", "inference.phala.com"]`. `api.redpill.ai` is served by the same TD, same keyset, own attested SPKI — and is **not** TEE-only, so attested serving is not forced there: 67 models versus 25, the extra 42 including `anthropic/claude-opus-5`, `openai/o3`, `google/gemini-2.5-pro`.

The value *is* attested — it sits in the `gateway-config` block inlined in the measured Compose — but it is not a typed field in the report and `aci verify` does not appraise it. So a client can verify this gateway completely, on the host where nothing is enforced, and get 6/6 with no signal. The protocol-level half is **P1**.

Demonstrated with live receipts rather than inferred from the catalog. Sending `anthropic/claude-opus-5` to `api.redpill.ai`:

```
HTTP 200   X-ACI-Keyset-Digest = sha256:c6e808d3…   (the same attested keyset)
upstream.verified: result=failed  required=false  session_id=None
```

The prompt was served by Anthropic's API, and the receipt says so — afterward. The receipt is still signed by the attested key and still verifies every hash: a client checking the signature but not reading `upstream.verified.required` sees an entirely green chain over an unattested hop.

The mitigation works when used. The same request with `provider.aci_verified: true` is refused 503 with no `request.forwarded` event. So this is not a missing guard, it is an opt-in one on a host that shares its attested identity with two hosts where the guard is automatic.

---

## Not devproof surface

- **Dev OS image (resolved).** Fixed between 08-13 and 08-18; `--require-production-os` now passes. Kept here because the fix is only visible by re-checking — the registry has no automated row on this deployment (see `awesome-private-inference` [#12](https://github.com/amiller/awesome-private-inference/pull/12)).
- **Chutes sessions carry no §8.2 evidence.** All 74 rejected in the live audit, reproduced independently. It is #4 on their own [conformance gap register](https://github.com/Dstack-TEE/private-ai-gateway/blob/main/docs/reviews/aci-spec-conformance-gaps.md), was closed in #142, and was deliberately reverted in #145 — the commit running now — because fleet-wide nonce-bound evidence mints a new session id per verification round and the log grows without bound relative to the live set, OOMing on startup replay. Known, documented, with the shape of a real fix stated. Not a hidden gap.
- **Custody policy skipped by the public client — but the evidence is complete and checkable.** Their register, #1, and everyone (this guide included) has been repeating "custody skipped" as if nothing could be done. Reading the verifier (`src/aci/verifier/dstack.rs:227-278`), the published chain is fully appraisable: `signature_chain[0]` signs `"<purpose>:<compressed kms_public_key>"` and recovers the **app** key; `signature_chain[1]` signs `"dstack-kms-issued:" || app_id || app_pubkey` and recovers the **KMS root**; `app_id` is read from the RTMR3-verified event log, so it is attestation-bound, not self-asserted. The one missing input is a KMS root you have decided to trust — k256 recovery always yields *some* root, so the check is entirely the allowlist comparison. Note the asymmetry: the gateway's own upstream verifier **refuses to start** with an empty root list (`EmptyKmsRootPolicy`, `src/aci/verifier/aci_service.rs:75`), so it holds its upstreams to a custody standard no public client currently applies to it. The fix is small: publish the dstack KMS root(s) and ship them as a default policy in the CLI.
- **Provenance not rebuilt.** Their register, #2. Note the mechanism though: the launcher clones and builds the gateway from `PRIVATE_AI_GATEWAY_REPO_COMMIT` at boot, so unlike the other three services the gateway binary is bound by a git commit, not an image digest. The commit is measured; the build is not reproduced by anyone.
- **NEAR upstream TCB is stale.** All 15 NEAR-gateway sessions read `tcb_up_to_date: refuted` (`hardware_proven`). Correctly reported by the adapter — an upstream posture problem, not a gateway one.
- **`node-exporter` with `pid: host` and `/:/host:ro`.** Same TD, port 9100, basic-auth with a bcrypt hash injected as a secret. Metrics only, off the prompt path.
- **Every request is rewritten before forwarding.** `request.forwarded.body_hash` differed from `request.received.body_hash` on all four live requests, on both hosts. Expected for an aggregator (it consumes the §5.3 `provider` block, normalizes the model id — the receipt shows `anthropic/claude-opus-5` arriving and `claude-opus-5` going out). Correctly disclosed by the protocol, and the protocol-level limit — a rewrite is a boolean, never an explanation — is [P6](../aci-protocol/DEVPROOF-REPORT.md).

---

*The interesting thing about this deployment is that the honest surface and the misleading one are the same workload. `/v1/aci/attestation` tells you exactly what it proves, in a protocol that names its own limits; `/v1/attestation/report` tells a legacy client something stronger than the truth, from the same quote, on the same TD. Compatibility is where an attestation story goes to lose its scope.*
