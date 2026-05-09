# NEAR AI Private Inference — Revisit Audit (2026-05-02)

**Audited:** 2026-05-02 (live probe)
**Trigger:** NEAR AI engineering reported the `MODEL_DISCOVERY_SERVER_URL` gap was
fixed after the Apr 2026 follow-up. Re-running from scratch against today's
production system.
**Public surface:** `https://cloud-api.near.ai/`,
`https://*.completions.near.ai/`, `https://private.near.ai/` (chat-api
front-end, audited separately under `near-private-chat/`)
**Core question:** Has the operator-controlled-routing gap been closed, and
what — if anything — remains between a TDX/GPU-attested backend and an
operator-shaped logging path?

> Predecessor: `case-studies/near-ai-private-inference/DEVPROOF-REPORT.md`
> (server-side audit 2026-03-25 + client-side E2EE 2026-04-19). This file
> revisits the same surface against today's production state.

---

## Prior experiments (timeline)

| Date | Commit | Artifact |
|---|---|---|
| 2026-02-12 | `a3f7b47`, `361ba68` | Initial DEVPROOF report against prod tag of Jan 9–10, 2026 (chat-api compose `4555c4e7…`, cloud-api `2e480d3e…`). Identified `MODEL_DISCOVERY_SERVER_URL` in `allowed_envs` with no reference-value check on the discovery response. |
| 2026-03-25 | `6216e72` | Added a NEAR-AI private-inference case study capturing the inner-boundary gap (issue [nearai/cloud-api#224](https://github.com/nearai/cloud-api/issues/224), opened 2025-12-03). |
| 2026-04-04 | `483ac61` | Cross-referenced Phala's `private-ai-verifier` (which uses `verify_signature=False` for NRAS / Intel JWTs). |
| 2026-04-19 | `d02839e`, `7ba42de` | E2EE client verification guide; reorganized findings by repo. |
| 2026-04-20 | `81a0cab` | Live findings re-run against production tag `prod-20260402-003658` (cloud-api commit `2cb48d2c54da`). Confirmed: PR #513 (Mar 26) had removed the discovery server, but the new `inference_url` path still did **no** cryptographic backend verification — `_has_valid_attestation` was set true on parseable JSON, fingerprint was extracted as TOFU. |
| 2026-04-21 | `b67a9c9`, `6591e2e` (`awesome-private-inference`) | Scaffold + verifier path fix; canonical NEAR-AI re-verify recipe lives at `providers/near-ai.md` and `verifiers/near_ai.py`. |
| 2026-04-26 | snapshot `2026-04-26.json` (awesome-private-inference) | Daily snapshot for `openai/gpt-oss-120b` and `zai-org/GLM-5.1-FP8`: `tdx_verified=true`, `report_data_binds_key=true`, `key_derives_to_address=true`, `compose_hash_committed=true`, `backend_attested=false`. |

---

## What changed upstream since April

NEAR's response was concentrated in three merged PRs (all on `nearai/cloud-api`):

| PR | Merged | Title | Effect |
|---|---|---|---|
| [#485](https://github.com/nearai/cloud-api/pull/485) | 2026-03-13 | feat: add `inference_url` column to models | Backend address moved from a discovery-server response into a DB column on the `models` table. |
| [#513](https://github.com/nearai/cloud-api/pull/513) | 2026-03-26 | feat: route inference via model `inference_url`, remove discovery server | Discovery-server fetch loop and consumer code deleted. `MODEL_DISCOVERY_SERVER_URL` is no longer read anywhere; `MODEL_DISCOVERY_API_KEY` survives only as a fallback name for `INFERENCE_API_KEY`. |
| [#552](https://github.com/nearai/cloud-api/pull/552) | 2026-04-27 | Inline backend verification: zero fingerprint-mismatch failures | Replaces the eager pre-created `bucket` clients with **lazily-filled buckets that verify each backend before serving**: connect → `GET /v1/attestation/report` → `AttestationVerifier::verify_attestation_report` (TDX quote via `dcap-qvl`, RTMR3 event-log replay, GPU NRAS, optional `ALLOWED_IMAGE_HASHES` allowlist) → pin SPKI fingerprint into a shared `FingerprintState` → serve. |
| [#558](https://github.com/nearai/cloud-api/pull/558) | 2026-05-01 | fix: semaphore-bound inline verification + graceful fallback on failure | Bounds concurrent verifications (`INLINE_VERIFY_CONCURRENCY=4` default). Adds a `fallback_client` that takes over when retries exhaust, but the fallback shares the same `FingerprintState` and refuses to serve until at least one fingerprint is pinned, so it does not bypass attestation — it tolerates control-plane churn after one good verification. |

These four PRs together close the original "operator can rewrite the discovery
URL → operator can pick any backend" objection. There is no operator-mutable
env var, anywhere in the running compose, that changes which CVMs cloud-api
will route a request to.

---

## Today's deployment

Probed 2026-05-02, ~13:20 UTC, no auth:

```bash
$ curl -s https://private.near.ai/v1/attestation/report > /tmp/att.json
$ jq '.chat_api_gateway_attestation.info  | {app_id, compose_hash, instance_id}' /tmp/att.json
{
  "app_id":      "f723e96ab11772f0166e5e4749e49a2113f63b0c",
  "compose_hash":"ab2f90d6f0af8999f0ab643a86f22fde50e6c17023292e791c8bdf9df97d7b4a",
  "instance_id": "904c63f78ea8dccdb3391853cf43e4ff06a353d9"
}
$ jq '.cloud_api_gateway_attestation.info | {app_id, compose_hash, instance_id}' /tmp/att.json
{
  "app_id":      "f550fdfb4eb8ad787c1bcd423f091cbb4a4431ae",
  "compose_hash":"2e84b7214760b9b3f9db5b137beedb4cecdf7ef1e846699fcd3331f998a7f3a3",
  "instance_id": "0d5b1cdfcc3bdd4bbc41b0a92a236f4d284e48b4"
}
```

| Service | App ID (Base address) | Compose hash | Container digest |
|---|---|---|---|
| dstack-ingress | `0x000b2d32de3ed13d7e15b735997e7580ed6dea69` | `2df8a9cc20…` (unchanged since Jan 2026) | `nearaidev/dstack-ingress-vpc@sha256:49385aaf…` |
| chat-api | `0xf723e96ab11772f0166e5e4749e49a2113f63b0c` | `ab2f90d6f0…` (new since Apr 2026) | `nearaidev/private-chat@sha256:d7ef0558…` |
| cloud-api | `0xf550fdfb4eb8ad787c1bcd423f091cbb4a4431ae` | `2e84b72147…` (new since Apr 2026) | `nearaidev/cloud-api@sha256:22763fe4…` |
| Postgres | `0xc5f76292a3df94d50056b08e57fc30fe1081ad40` | (referenced via `POSTGRES_PRIMARY_APP_ID`) | n/a |
| VPC server | `0xe78c12915ad57900317b97bd16f59ae13f86f148` | (Tailscale VPC root) | n/a |
| OS image | (all CVMs) | `da9a3d5cc196a1a76d953fb27069be428ddf60a1ce10b0534c3cf968d3053fde` | dstack 0.5.4 |

`runner=docker-compose`, `kms_enabled=true`, `key_provider=null` (so the
KMS chain is the dstack registry on Base, not a TPM/local), `public_logs=false`,
`public_sysinfo=true`.

---

## Re-run of the original checks

### 1. TLS termination is still in TEE — but `/evidences/quote.json` is empty (regression)

```bash
$ curl -sI https://private.near.ai/evidences/quote.json | grep -E 'HTTP|content-length|last-modified'
HTTP/2 200
last-modified: Sat, 02 May 2026 04:49:28 GMT
content-length: 0
```

The dstack-ingress CVM regenerates the evidence bundle each time the Let's
Encrypt cert renews; it ran today at 04:49 UTC and produced a 0-byte
`quote.json`. `sha256sum.txt` and `cert-private.near.ai.pem` are well-formed
and the cert fingerprint matches the live TLS handshake:

```bash
$ diff <(openssl x509 -in evidence-cert.pem -noout -fingerprint -sha256) \
       <(echo | openssl s_client -connect private.near.ai:443 -servername private.near.ai 2>/dev/null \
           | openssl x509 -noout -fingerprint -sha256)
# (no output — fingerprints identical)
```

But there is no quote to compare them against, so for the duration of this
broken evidence cycle the dstack-ingress TLS-binding leg is **not
re-verifiable**. The compose hash `2df8a9cc…` is the same as Jan 2026, so this
is an operational regression (probably in the `generate-evidences.sh` cert-renew
hook), not a code change. (The `chat-api` and `cloud-api` gateways' own
TDX quotes embed report_data on every `/v1/attestation/report` call and are
unaffected.)

### 2. chat-api → cloud-api routing — still hardcoded ✅

```bash
$ jq -r '.chat_api_gateway_attestation.info.tcb_info.app_compose' /tmp/att.json \
    | jq -r '.docker_compose_file' | grep OPENAI_BASE_URL
      - OPENAI_BASE_URL=https://cloud-api.near.ai/v1
$ jq -r '.chat_api_gateway_attestation.info.tcb_info.app_compose' /tmp/att.json \
    | jq '.allowed_envs[]' | grep -i openai
# (no output — not runtime-mutable)
```

### 3. cloud-api → backend routing — operator-mutable env var path is gone ✅, but…

`MODEL_DISCOVERY_SERVER_URL` still appears in `cloud-api`'s `allowed_envs` and is
still passed into the container's environment in the running compose:

```yaml
- MODEL_DISCOVERY_SERVER_URL=${MODEL_DISCOVERY_SERVER_URL}
- MODEL_DISCOVERY_API_KEY=${MODEL_DISCOVERY_API_KEY}
- MODEL_DISCOVERY_REFRESH_INTERVAL=60
- MODEL_DISCOVERY_TIMEOUT=5
```

…**but the binary no longer reads any of these**. `crates/config/src/types.rs`
in `nearai/cloud-api@HEAD` does:

```rust
inference_api_key: env::var("INFERENCE_API_KEY")
    .or_else(|_| env::var("MODEL_DISCOVERY_API_KEY"))
    .ok(),
```

— the only surviving mention. There is no `MODEL_DISCOVERY_SERVER_URL` read in
the workspace. So it's vestigial: the env var is reachable, but nothing
downstream depends on it. **The original gap is genuinely closed.** Cleanup
recommendation only: drop the four env entries from compose and the two
names from `allowed_envs` so reviewers don't have to chase the dead path.

The new routing source is the `inference_url` column on the `models` table
(`crates/database/src/migrations/sql/V0048__add_model_inference_url.sql`),
written via the admin endpoint at `POST /v1/admin/models` (handler at
`crates/api/src/routes/admin.rs:108–217`). On every admin write that changes
`provider_type` or `inference_url`, cloud-api unregisters the affected provider
and calls `inference_provider_pool::load_inference_url_models` — which routes
through the inline-verification path before serving.

### 4. Database stores metadata only — unchanged ✅

`crates/database/src/migrations/sql/V3__add_conversations.sql` and the
corresponding model `crates/database/src/models.rs` still hold conversation
IDs, titles, and timestamps. No message-content columns were added.

### 5. AppAuth contracts on Base — verified ✅ (2026-05-09)

The two implementation contracts behind every NEAR DstackKms / DstackApp
proxy now have `exact_match` source on Sourcify, Basescan, and Blockscout:

- `DstackKms` impl: [`0x2e99ade185c125145d5defa11c6ea33ecd532e28`](https://repo.sourcify.dev/8453/0x2e99ade185c125145d5defa11c6ea33ecd532e28/)
- `DstackApp` impl: [`0x7e5192c0aa36e35e003351bffb8ebb213e7e1ba9`](https://repo.sourcify.dev/8453/0x7e5192c0aa36e35e003351bffb8ebb213e7e1ba9/)
  (shared by all 50+ active per-app proxies — `0xf550fdfb…` cloud-api,
  `0x2c0a0c96…` shared models, `0xf723e96a…` chat-api, `0x000b2d32…`
  ingress, `0xc5f76292…` postgres, `0xe78c1291…` vpc-server, etc.)

Source matches `Dstack-TEE/dstack@771f3c9e` (last contract-touching commit
before the 2025-09-24 deployment), solc 0.8.22 / optimizer enabled / runs=200
/ evmVersion=paris. Reproducible build verified: byte-for-byte identical to
deployed runtime bytecode modulo the standard OZ UUPS `__self` immutable
(impl's own address patched into 3 places at construction). Submitted to
Sourcify by the audit; auto-propagated to Blockscout, separately verified on
Basescan.

This closes the prior recommendation. Anyone reading attestation reports can
now click through to verified Solidity for `addComposeHash`, `registeredApps`,
`allowedComposeHashes`, owner/upgrade controls, and read off the access
control directly.

The `ComposeHashAdded` log set is queryable on Base (script in this folder is
`query-compose-hashes.py`).

---

## What inline verification actually checks (cloud-api HEAD)

`crates/services/src/attestation/verification.rs::verify_attestation_report`:

1. **TDX quote** — `dcap_qvl::collateral::CollateralClient::fetch_and_verify`
   against Phala's PCCS by default (`PCCS_URL` overrides). Rejects debug-mode
   TDs. Logs `tcb_status` if not `UpToDate` and only enforces `UpToDate`
   when `REQUIRE_TCB_UP_TO_DATE=1` (default off).
2. **report_data binding** — first 32 bytes are
   `SHA256(signing_address || tls_cert_fingerprint)` when fingerprint is
   present, otherwise the signing address padded; bytes 32..64 are the request
   nonce. Both must match the values reported in the JSON body.
3. **RTMR3 replay** — walks the JSON event log, recomputes the running
   hash, and compares against `td_report.rt_mr3`. Only after the log is
   verified are `os_image_hash` and `compose_hash` extracted from it.
4. **`os_image_hash` allowlist** — `ALLOWED_IMAGE_HASHES` (comma-separated env
   var). When unset, **the check is skipped** (HashSet is empty, the
   `if !is_empty()` guard short-circuits).
5. **GPU evidence** — `verify_gpu_evidence` POSTs the GPU evidence to
   `https://nras.attestation.nvidia.com/v3/attest/gpu` and (per
   `attestation/verification.rs`) returns the verdict.
6. **Fingerprint pinning** — on success, the verified
   `tls_cert_fingerprint` is added to `FingerprintState`, and the H2
   connection that did the attestation handshake is reused for the actual
   inference request, so an MITM cannot swap targets after step 5.

That is a complete TDX+GPU+TLS chain. It is materially stronger than the
"endpoint exists" check that was here in January and through April.

---

## What is still missing

### A. `compose_hash` is extracted but never checked

In `verify_attestation_report` (verification.rs:144–269), `event_log_data`
yields both `os_image_hash` and `compose_hash`. Only `os_image_hash` is run
through the allowlist; `compose_hash` is returned in `VerifiedAttestation`
and never compared against anything. There is no symmetric
`ALLOWED_COMPOSE_HASHES` env or in-process whitelist anywhere in
`crates/services/src/attestation/`.

Practical effect: a backend that boots a different docker-compose (say, one
that adds a logging proxy in front of vLLM) on the same dstack OS image will
verify successfully if the OS image hash check is itself disabled (see B).

### B. `ALLOWED_IMAGE_HASHES` is empty in production

The running cloud-api compose:

- does **not** set `ALLOWED_IMAGE_HASHES` in the env block, and
- does **not** list `ALLOWED_IMAGE_HASHES` in `allowed_envs`.

So `AttestationVerifier::from_env` builds an empty `HashSet`, and per the
guard at `verification.rs:240–253` the OS-image-hash branch is a no-op.

Combined with (A), the verification chain — though cryptographically sound on
its own terms — does not actually pin which code is running on the backend.
It pins:

- *some* TDX TD that is **non-debug** and signed by a TCB Intel will verify;
- TLS to a fingerprint embedded in that TD's report_data;
- some GPU evidence the backend chose to include, judged by NRAS.

It does not pin: which OS image, which compose, which app_id. An operator
who can stand up a TDX CVM on a TCB-current Intel host with a real H100/H200,
running any code that responds to `/v1/attestation/report`, will pass
verification.

### C. `inference_url` is operator-writable through the admin path

`POST /v1/admin/models` is gated by an admin user. Admin status comes from
two sources:

1. Static admin-domain allowlist — `AUTH_ADMIN_DOMAINS` is in `cloud-api`'s
   `allowed_envs`, so the operator (anyone with deploy rights to the
   compose-stack secrets) can change it at restart and onboard new admin
   identities through OAuth.
2. Existing rows in the `admin_access_tokens` table — but the database is
   itself just another service in the VPC; anyone who can write the
   `inference_url` column can also write `admin_access_tokens`.

So the path to "swap which CVM is the gpt-oss-120b backend" today is:

- Touch `AUTH_ADMIN_DOMAINS` (allowed_env) → log in as an admin →
  `POST /v1/admin/models` with a new `inference_url`.
- *Or:* directly UPDATE the `models` row in postgres.

Either way, the swap is bound by inline verification — but inline
verification accepts any non-debug TDX-signed TD with valid GPU evidence
(see A+B). So the operator can spin up a TDX CVM that runs a logging vLLM
shim, set its `inference_url`, and route real user traffic through it without
the gateway's verifier objecting.

### D. Issue #224 still tracks this

[`nearai/cloud-api#224`](https://github.com/nearai/cloud-api/issues/224)
("cloud-api should only add verified model nodes") opened 2025-12-03,
last comment 2026-01-12, **state: open** as of 2026-05-02. Linked to the
2026-01 gist `gist.github.com/amiller/6b547f407386d059d62c69d35e125464`. PRs
#485/#513/#552 progressed the underlying mechanics but didn't formally close
this thread — and the compose-hash leg is genuinely not done yet.

---

## Concerns summary

### Critical (closed since prior audit)
- **Operator-controlled discovery URL.** `MODEL_DISCOVERY_SERVER_URL` is no
  longer read by the binary; routing comes from a DB column gated by admin
  auth, and the inline-verification path has real TDX/GPU checks. ✅
- **AppAuth contracts on Base verified** (2026-05-09). DstackKms impl
  `0x2e99ade1…` and DstackApp impl `0x7e5192c0…` (shared by every NEAR
  per-app proxy) now have `exact_match` source on Sourcify, Basescan, and
  Blockscout. Source = `Dstack-TEE/dstack@771f3c9e`, solc 0.8.22 / opt 200.
  See §5 above. ✅

### Critical (server-side trust model)
- **Backend code is not pinned at the gateway.** cloud-api's verifier
  extracts `compose_hash` from the backend's TDX quote but doesn't compare
  it against an allowlist; `ALLOWED_COMPOSE_HASHES` is unset in production.
  A user trusting cloud-api alone has no protection: any TDX+H100 backend
  the operator points the gateway at will pass cloud-api's checks, including
  one running operator-side logging code.

  **N/A under closed-chain verification.** Clients running the attestation
  check themselves (e.g.,
  [`verifiers/near_ai_lightclient.py`](https://github.com/amiller/awesome-private-inference/blob/main/verifiers/near_ai_lightclient.py)
  or hermes-agent's strict mode) extract the compose hash from the
  attestation directly and check it against the on-chain
  `addComposeHash` set on Base. The gateway-side check being unconfigured
  doesn't affect them.

### Residual (belt-and-suspenders)
- **`kmsInfo` on `DstackKms` is empty.** All four fields (`k256Pubkey`,
  `caPubkey`, `quote`, `eventlog`) return zero-length bytes on
  `0x8fa1593fac104c1aa0c59eaa3553f7e3e162d637`. Each per-CVM attestation
  already carries `info.key_provider_info.id` (the asserted KMS pubkey),
  and the dstack source is auditable + verified, so a closed-chain client
  can pin the KMS pubkey across attestations and trust dstack's
  `quote_enabled=true` + `OsRng`-inside-TD machinery to produce a TEE-bound
  root. The on-chain `kmsInfo.quote` would be the public TEE-attested
  proof of that fact rather than a transitive trust chain — useful but not
  load-bearing for a verifying client. Phala's canonical KMS at
  `0x2f83172A…` populates these fields; NEAR's hasn't.

  **Fix path (if NEAR cares to close it):** call
  `setKmsInfo((k256Pubkey, caPubkey, quote, eventlog))` once on
  `0x8fa1593fac104c1aa0c59eaa3553f7e3e162d637` with the bootstrap output
  from the KMS TD.

### Operational regression
- **`/evidences/quote.json` is 0 bytes** as of 2026-05-02 04:49 UTC. The
  TLS-cert ↔ TDX quote binding produced by the dstack-ingress CVM is
  currently absent. Compose hash unchanged, so this is a runtime bug in the
  evidence-renew script.

### Moderate
- **Vestigial `MODEL_DISCOVERY_*` envs** in compose and `allowed_envs`. Dead
  code path; recommend removing to make the audit story cleaner.
- **`AUTH_ADMIN_DOMAINS` is in `allowed_envs`.** Combined with (A+B) this
  is the practical lever for the routing-substitution attack above.
- **Datadog agent in TEE** — unchanged from prior audits; receives
  container logs from the dstack ring.

### Verified good
- TLS cert fingerprint matches `/evidences/cert-…pem` (cert-content side of
  binding still works).
- `OPENAI_BASE_URL` for chat-api → cloud-api is hardcoded in compose, not
  in `allowed_envs`.
- Conversations table stores metadata only.
- All container images pinned by digest; OS image hash matches across both
  CVMs (`da9a3d5c…`, dstack 0.5.4).
- Cryptographic TDX/GPU verification of inference backends has been added
  (PRs #552, #558) — this is a meaningful improvement over the April state.

---

## Two-layer compose architecture (discovered after the gateway pass)

`/v1/attestation/report?model=…` returns **per-model attestation** including
`model_attestations[].info.tcb_info.app_compose` (the OUTER compose) **and**
`model_attestations[].compose_manager_attestation` (the INNER compose log).

Reading the outer compose for `zai-org/GLM-5.1-FP8` (app_id
`0x2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b`):

```
nearaidev/compose-manager@sha256:a3c6e223…   ← only meaningful service
datadog/agent@sha256:5556fb80…
certbot/dns-cloudflare@sha256:742dbd2e… (×2)
```

The **inner** compose (the YAML that actually launches `vllm-proxy-rs` and
`sglang`) is fetched by compose-manager from
[`nearai/cvm-compose-files`](https://github.com/nearai/cvm-compose-files) at
runtime. Each `compose_up` is recorded in
`compose_manager_attestation.actions[]` with
`(timestamp, action, tag, commit, file, file_sha256, services)`. The actions
list is then SHA256'd and embedded in `report_data[0:32]` of compose-manager's
own TDX quote.

The most recent entries on the GLM-5.1 CVM as of 2026-05-02:

```json
[
  {"action":"compose_up","tag":"v0.0.133","commit":"584ee87484abae8d5fbe05099a8db12be9100a4e",
   "file":"GLM-5.1.yaml","file_sha256":"bdc45935e760a5724f8e8ffee27fefb04e8652e8edba5451f6e374ad84e2293e",
   "services":["nginx","proxy-glm51"]},
  {"action":"compose_up","tag":"v0.0.134","commit":"f431d0a321046b1f12d40bdf809a4209d81f8d00",
   "file":"GLM-5.1.yaml","file_sha256":"8c22042d76f45edaf6e61e1fa957f69ab82b16080c7a4e33df7c4e96c2d86179",
   "services":["nginx"]}
]
```

`git show <commit>:GLM-5.1.yaml | sha256sum` matches each `file_sha256`
byte-for-byte. So compose-manager's log is **honest at the YAML-content
level**: it records what it actually fetched.

The inner YAML for GLM-5.1 (commit `584ee87…`):

```yaml
proxy-glm51:
  image: nearaidev/vllm-proxy-rs@sha256:6f3cb72d31f6f7623a4ac17f1caf60c57678e958dd6e77152164c5cc4bac4913
  environment:
    - MODEL_NAME=zai-org/GLM-5.1-FP8     # → KMS derivation path
    - OHTTP_ENABLED=true
    - TOKEN=${PROXY_TOKEN}
    # no DEV env

glm51:
  image: lmsysorg/sglang:dev@sha256:e1eee3f75e62827dbfa29994a260934c2bc7e5adfb047170576f1676b436b926
  command: sglang serve --model-path zai-org/GLM-5.1-FP8 --tp 8 …
```

This closes prior diligence items concretely:

- **DEV mode is off** in the inner YAML and absent from the outer
  `allowed_envs` (which contains only `BEARER_TOKEN`, `AWS_*`, `CERTBOT_*`,
  `DD_*`, `HUGGING_FACE_HUB_TOKEN`, `PROXY_TOKEN`, `ENV`, `HOST_IP`,
  `DD_HOSTNAME`, `HOSTNAME`).
- **`MODEL_NAME` is hardcoded** as the KMS derivation path.
- **`vllm-proxy-rs` image digest is pinned** in the YAML and the YAML hash is
  in the on-chain action log.

### Three call paths

| Path | URL | Where TLS terminates | Where the prompt is in plaintext |
|---|---|---|---|
| **A** | `https://cloud-api.near.ai/...` | `dstack-ingress` CVM (separate TD) | dstack-ingress → chat-api → cloud-api → inference-proxy |
| **B** | `https://glm-5-1.completions.near.ai/...` | inference-proxy CVM's nginx (same TD as the GPU) | only inside the model TD |
| **C** | E2EE headers via either path | TLS is incidental (anywhere it terminates, ciphertext is what's seen) | only inside the model TD |

`*.completions.near.ai` resolves to two SNI-passthrough LB IPs
(`160.72.54.186`, `160.72.54.254`); the per-host SAN
(`gpu26.hosts.near.ai`) on the wildcard cert confirms TLS is *not* terminated
at the LB. Path B's TLS endpoint is the model TD itself.

### Source-code audit of `nearai/compose-manager` (one-file Rust service)

- **Mutating endpoints**: `compose/up`, `compose/down`, `docker/clean`,
  `docker/restart`, `dstack-agent/{start|stop|restart}` — every mutating call
  writes a `DeploymentAction` to the in-memory `actions: RwLock<Vec<…>>`.
  No off-log mutation paths exist.
- **`file_sha256`** is computed from the *fetched* GitHub content
  (`sha2::Sha256::digest(content.as_bytes())`); operator can't fake it.
- **`min_tag_age_hours`** check (default 48h) blocks deploys of tags younger
  than that — bounds attacker speed if they push a malicious tag. Configurable
  per CVM.
- **Auth = single shared `BEARER_TOKEN`** (env var). Whoever has the token
  can deploy any tag from `cvm-compose-files`. The token is in the outer
  `allowed_envs`, so it's operator-mutable at outer-CVM restart.
- **In-memory log only.** `actions: RwLock::new(Vec::new())` at startup with
  no disk restoration. If compose-manager itself restarts, the action log is
  wiped; subsequent attestation reports `actions=[]` and
  `actions_hash=SHA256("[]")` until the next deploy. Containers from previous
  deploys may keep running. **This is a real forensic gap** — between
  compose-manager's restart and the next deploy, the attestation cannot tell
  you what's currently running.
- **GitHub source is fetched over `https://api.github.com/...` and
  `https://raw.githubusercontent.com/...`** at the requested tag. TLS
  protects the wire, but the TLS root is GitHub's; GitHub itself sees the
  request. (GitHub serving a different blob than what's in the public commit
  would require GitHub compromise.)

### Source-code audit of `nearai/inference-proxy` (`vllm-proxy-rs`)

- **DEV gate is `env_bool("DEV")`** with default false. No
  `cfg!(debug_assertions)` guard — runtime env-only. Confirmed not in NEAR's
  outer `allowed_envs` and not in any inner YAML.
- **KMS-only key derivation in production**. `SigningPair::init` calls
  `dstack_sdk::dstack_client::DstackClient::new(None).get_key("{model}/ed25519-signing-key", "signing")`
  for both ECDSA and Ed25519. If KMS is unreachable, init returns `Err` →
  proxy fails to start. **No fallback to random keys when KMS fails.** ✓
- **OHTTP key config** is HPKE-derived from the *same* Ed25519 seed via
  domain-separated `KeyConfig::derive(...)` (different from the E2EE X25519
  derivation, which uses `SHA512(seed)[..32]` clamped per RFC 7748). The
  OHTTP key config bytes are signed with Ed25519 and exposed as
  `ohttp_attestation.signature` — clients can verify the OHTTP HPKE pubkey is
  endorsed by the TDX-attested Ed25519 key.
- **`signing_address` query parameter on `/v1/attestation/report`**: if a
  client requests a specific signing address and it doesn't match, returns
  404 — prevents a man-in-the-middle from returning attestation for a
  different signing key than expected.
- **`include_tls_fingerprint=false` by default**: clients must explicitly
  opt in to bind the TLS cert fingerprint into `report_data[0:32]`.
- **Two auth paths**: static `TOKEN` (= `PROXY_TOKEN`, in outer
  `allowed_envs` — operator can rotate at restart) and `sk-` cloud API keys
  (proxied to `cloud-api/v1/check_api_key` for validation). Both are accepted
  on the per-model endpoint, so path B accepts NEAR_API_KEY directly.

### Source-code audit of `nearai/cvm-compose-files`

- **All commits unsigned**. `git tag -v <tag>` returns
  `error: no signature found`; `git log --pretty='%G?'` shows `N` for every
  commit. No GPG/SSH signing on commits or tags.
- **CI** (`.github/workflows/validate-compose.yaml`) only runs
  `docker compose -f file config` to validate syntax. **Does not** pin image
  digests or check anything against an allowlist.
- **Maintainer concentration**: 168 commits over the repo lifetime; 123 by
  Evrard-Nil Daillet (gmail), 21 across three Lloyd accounts, 4 by Henry
  Park, 4 by `nearai-bot`/PR merges. **The push-protection model relies on
  GitHub branch rules + each individual contributor's account security.**
  No on-chain or out-of-band anchor for "the legitimate set of release
  commits."
- All current YAMLs use the same `vllm-proxy-rs@sha256:6f3cb72d…` digest;
  engine images differ per model.

### Substitution-vs-evidence table (post-investigation)

| Substitution | Public evidence (retroactively auditable)? |
|---|---|
| EOA owner adds new `compose_hash` to existing DstackApp | ✅ `ComposeHashAdded` on Base |
| EOA owner UUPS-upgrades the DstackApp impl | ✅ `Upgraded(address)` on Base |
| Owner transfers ownership | ✅ `OwnershipTransferred` on Base |
| KMS contract `setKmsInfo`, `addOsImageHash`, etc. | ✅ KMS contract events on Base |
| compose-manager `compose_up`/`compose_down` of an inner YAML | ✅ in `compose_manager_attestation.actions[]` (TDX-attested) |
| New commit / backdoored YAML in `cvm-compose-files` | ✅ via public Git history + `48h` `min_tag_age` window |
| **cloud-api admin updates `models.inference_url`** (path A only) | ❌ **off-chain DB mutation, no public log** |
| **compose-manager restart wipes action log** | ❌ **between restart and next deploy, attestation can't show what's running** |
| LB at `completions.near.ai` redirects model subdomain | indirect — destination CVM's TDX quote reveals the swap (different `app_id`) |
| DNS hijack of `*.completions.near.ai` | ✅ via Certificate Transparency + DNS records |
| Inner YAML maintainer pushes backdoored YAML | ✅ via Git history; auditor must compare expected (commit, image-digest) but no anchored expectation exists |

The two ❌ rows are the substitution surfaces with no public retroactive
audit:

1. **cloud-api `models.inference_url` mutation** — only path A; path B
   bypasses cloud-api so this surface is irrelevant for users hitting
   `glm-5-1.completions.near.ai` directly.
2. **compose-manager in-memory action log** — between restart and next
   deploy, `compose_manager_attestation.actions=[]` and an external auditor
   cannot tell what is running. Mitigation would be persistence-on-disk in
   compose-manager.

### Address registry (live values, 2026-05-02)

```
DstackApp proxies on Base mainnet (chain 8453)
  dstack-ingress     0x000b2d32de3ed13d7e15b735997e7580ed6dea69
  chat-api           0xf723e96ab11772f0166e5e4749e49a2113f63b0c
  cloud-api          0xf550fdfb4eb8ad787c1bcd423f091cbb4a4431ae
  postgres           0xc5f76292a3df94d50056b08e57fc30fe1081ad40
  vpc-server         0xe78c12915ad57900317b97bd16f59ae13f86f148
  GLM-5.1 / DeepSeek-V3.1 model CVM (shared)
                     0x2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b

DstackApp UUPS implementation (shared by all six)
                     0x7e5192c0aa36e35e003351bffb8ebb213e7e1ba9
  runtime bytecode keccak256:
    0xd5fc0c77da14a89d7e4401ecaac0c01eaf3bd7d129a5fd51112486ba9bd95598
  Solidity metadata IPFS: QmYwfYtrNaz2t2XfCPzQBHrpM5xpPAKKabDMZJa2oDFbkk
  solc 0.8.22 (matches dstack/kms/auth-eth/contracts/DstackApp.sol pragma)

Owner (EOA, controls all six)
                     0x21e6b7ef11185eaa57c56ea9c74e48aac6e8ab8d
                     no contract code → externally-owned account (1/1 keypair)

DstackApp storage flags (all six)
  _upgradesDisabled  false   (owner can UUPS-upgrade impl)
  allowAnyDevice     true    (no per-device pinning)

KMS root identity (from info.key_provider_info.id)
  P-256 SubjectPublicKeyInfo:
    3059…04 228f800590a10442cba9d0e6adb2fa9f195eea9e75e23dd35990d52b59dda
              2415a63674c38adebde4ffd4d4b265bf818985933820c8053cee3ce29b5fb0fbcbc

Canonical DstackKms registry contract on Base
                     0x8fa1593fac104c1aa0c59eaa3553f7e3e162d637
  impl               0x2e99ade185c125145d5defa11c6ea33ecd532e28
  owner              0x21e6b7ef11185eaa57c56ea9c74e48aac6e8ab8d  (same EOA)
  gatewayAppId       0x90ba8bc1e9a0bee94ff5651d1f437146d0c1a60a  (dstack-gateway)

  Found by paginating Blockscout's tx history for the EOA owner; the
  selector pattern 0x8618169d (= deployAndRegisterApp(...)) appearing
  99 times against this single contract identifies it as the KMS factory.
  registeredApps(addr) returns true for all six known DstackApp proxies
  in this audit (cloud-api, chat-api, dstack-ingress, postgres, vpc-server,
  and the GLM-5.1/DeepSeek model CVM).
```

NEAR has not published any of these addresses publicly (gh code search
across `org:nearai` returned only this audit repo's own references).
Anyone independently verifying must obtain the `app_id` from the live
attestation response, then trust that response to be correct — there is no
out-of-band anchor.

---

## Reproduction

```bash
# 1. Pull both gateway attestations (no auth needed)
curl -s https://private.near.ai/v1/attestation/report > att.json
jq '.chat_api_gateway_attestation.info  | {app_id, compose_hash, instance_id}' att.json
jq '.cloud_api_gateway_attestation.info | {app_id, compose_hash, instance_id}' att.json

# 2. Confirm OPENAI_BASE_URL still hardcoded
jq -r '.chat_api_gateway_attestation.info.tcb_info.app_compose' att.json \
  | jq -r '.docker_compose_file' | grep OPENAI_BASE_URL
jq -r '.chat_api_gateway_attestation.info.tcb_info.app_compose' att.json \
  | jq '.allowed_envs[]' | grep -i openai     # (no output expected)

# 3. Confirm MODEL_DISCOVERY_* are vestigial — present in compose, absent in code
jq -r '.cloud_api_gateway_attestation.info.tcb_info.app_compose' att.json \
  | jq '.allowed_envs[]' | grep MODEL_DISCOVERY  # 2 lines
# Then in cloud-api source (HEAD):
git clone --depth 1 https://github.com/nearai/cloud-api /tmp/cloud-api
grep -rn 'MODEL_DISCOVERY_SERVER_URL' /tmp/cloud-api/crates/   # 0 hits
grep -rn 'MODEL_DISCOVERY_API_KEY'    /tmp/cloud-api/crates/   # 1 hit, only as fallback name

# 4. Confirm ALLOWED_IMAGE_HASHES unset in prod
jq -r '.cloud_api_gateway_attestation.info.tcb_info.app_compose' att.json \
  | jq -r '.docker_compose_file' | grep ALLOWED_IMAGE_HASHES   # (no output)
jq -r '.cloud_api_gateway_attestation.info.tcb_info.app_compose' att.json \
  | jq '.allowed_envs[]' | grep ALLOWED_IMAGE_HASHES           # (no output)

# 5. Confirm the verifier extracts compose_hash but never enforces it
grep -nE 'compose_hash|allowed_compose' \
  /tmp/cloud-api/crates/services/src/attestation/verification.rs
# extracted at event_log_data.compose_hash, surfaced on VerifiedAttestation,
# never compared against any allowlist.

# 6. Replicate the awesome-private-inference re-verifier
git clone https://github.com/nearai/nearai-cloud-verifier _nearai-verifier
export NEARAI_VERIFIER_PATH="$(pwd)/_nearai-verifier/py"
export NEAR_API_KEY=...
python -c "from verifiers.near_ai import verify; \
  r = verify('$NEAR_API_KEY','https://cloud-api.near.ai','openai/gpt-oss-120b'); \
  import json; print(json.dumps(r.as_dict(), indent=2, default=str))"
# Expected: tdx_verified=true, nonce_bound=true, report_data_binds_key=true,
#           key_derives_to_address=true, gpu_attested=true,
#           backend_attested=false (this is the still-open gap).

# 7. Issue / PR pointers
# https://github.com/nearai/cloud-api/issues/224  (open, opened 2025-12-03)
# https://github.com/nearai/cloud-api/pull/485    (inference_url column)
# https://github.com/nearai/cloud-api/pull/513    (remove discovery server)
# https://github.com/nearai/cloud-api/pull/552    (inline backend verification)
# https://github.com/nearai/cloud-api/pull/558    (semaphore + fallback)
```

---

## Recommended next steps for NEAR

Each ask below is framed in two layers: (1) the change itself, and (2) the
*residual consequence assuming a verifying client (e.g. `hermes-agent`'s
static-anchor mode in PR
[NousResearch/hermes-agent#12201](https://github.com/NousResearch/hermes-agent/pull/12201))
is already running the full closed-chain check from
[`VERIFIER-DESIGN.md` §5](./VERIFIER-DESIGN.md) — Blocks A+B+C+D — with a
manually-pinned anchor file*. Many gateway-side gaps moot under that model;
what's left is what an *unpinned* client (or a generic verifier) can't anchor.

### Asymmetric wins (one tx, big anchor improvement)

1. **Call `setKmsInfo((k256Pubkey, caPubkey, quote, eventlog))` on
   `DstackKms 0x8fa1593fac104c1aa0c59eaa3553f7e3e162d637`.** Phala's
   canonical KMS at `0x2f83172A…` populates all four; NEAR's returns
   zero-length bytes. The EOA owner already has authority for the call;
   it only needs to happen once with the bootstrap output of the running
   KMS instance.
   *Consequence with pinned client:* zero — hermes pins
   `info.key_provider_info.id` directly from the captured attestation.
   *Without* a pin: no on-chain way to confirm the KMS root was generated
   inside a TDX TD. "Root generated in TD with `quote_enabled=true`,
   deployer simply forgot to publish via `setKmsInfo`" and "root generated
   off-chain and imported into a `quote_enabled=false` KMS instance" are
   indistinguishable from chain state, and the KMS endpoint at
   `kms.cvm1.near.ai` is not externally reachable so the quote isn't
   published anywhere else either.

2. **Publish a signed `(model → app_id, compose_hashes, os_image_hash,
   kms_pubkey)` manifest at a stable URL.** Phala has
   `https://cloud-api.phala.network/api/v1/apps/{app_id}/attestations`;
   NEAR's `cloud-api.near.ai/v1/apps/...` is `404`. A NEAR-org key signs
   each release of the manifest.
   *Consequence with pinned client:* zero — hermes already substitutes for
   this with the ad-hoc anchor file we built. *Without* a manifest: every
   other client either has to capture+pin themselves (fragmenting the
   ecosystem) or trust the live response (no anchor at all). Externality:
   keeps the verifier-design Block B unimplementable for any client that
   doesn't already know NEAR's contract addresses out-of-band.

### Server-side enforcement (helps path A direct users without our client)

3. **Set `ALLOWED_IMAGE_HASHES`** in the cloud-api compose to the dstack OS
   image hashes the team has actually validated, and treat this as part of
   the measured config (i.e. don't list it in `allowed_envs`). Today's
   value would start as `da9a3d5cc196a1a76d953fb27069be428ddf60a1ce10b0534c3cf968d3053fde`.
   *Consequence with pinned client:* unchanged — Block B2 enforced
   client-side. Path A direct users without our client today get ~no
   enforcement on which OS image is serving them. Cheap server-side fix.

4. **Add `ALLOWED_COMPOSE_HASHES` (or a per-model whitelist) and enforce
   it in `AttestationVerifier::verify_attestation_report` symmetric to the
   image-hash check.** `verification.rs` extracts `compose_hash` from the
   RTMR3 event log and surfaces it on `VerifiedAttestation` — but never
   compares against anything. Best implementation: source the allowlist
   from the on-chain `ComposeHashAdded` / `ComposeHashRemoved` events on
   the model CVM's AppAuth contract instead of an env var, which gives
   external auditors a single place to look.
   *Consequence with pinned client:* unchanged. *Without* a pin: this is
   the single biggest server-side hole — any TCB-current TDX TD running
   anything passes.

5. **Enable `REQUIRE_TCB_UP_TO_DATE=1` in cloud-api.** Off by default;
   today only `tcb_status` is logged when not `UpToDate`.
   *Consequence with pinned client:* hermes uses `dcap_qvl` itself but
   does not currently fail-closed on `tcb_status != UpToDate` either, so
   an Intel TCB revocation tolerates both layers until someone fixes one
   of them. The gateway is the operator-controlled floor — flip it on
   there as a backstop while client-side enforcement matures.

### Governance (residual trust assumption even with pinned clients)

6. **Move ownership from a single EOA (`0x21e6b7ef11185eaa57c56ea9c74e48aac6e8ab8d`)
   to a multisig or timelock-wrapped controller.** That one keypair owns
   all six DstackApp proxies *and* `DstackKms`, with `_upgradesDisabled=false`
   on every proxy — so it can UUPS-swap any impl, `addComposeHash`,
   `addOsImageHash`, transfer ownership, etc.
   `disableUpgrades()` outright is operationally untenable (would force
   new `app_id`s on every bug fix and on every legitimate compose
   rotation, which we already observed mid-capture for GLM-5.1 on
   2026-05-05). Multisig or timelock is the operator-friendly variant:
   keeps upgrade and rotation capability, but turns single-key compromise
   into a multi-party, time-windowed event auditable in
   `OwnershipTransferred` / `Upgraded` / `ComposeHashAdded` logs.
   *Consequence with pinned client:* downgraded to "anchor-refresh
   discipline." A hostile single-key compromise can't trick a pinned
   hermes client at request time, but it can fool any future Block B
   on-chain reader, and a determined attacker who legitimately
   `addComposeHash`-es a poisoned compose under the EOA's signature could
   slip into the next anchor refresh PR if the maintainer can't tell
   apart "operator authorized" from "operator key compromised." Multisig
   reframes that question as "is this rotation consistent with NEAR's
   published process?" rather than "do we trust every transaction signed
   by one EOA?"

### Cleanup (low-stakes, makes future audits cleaner)

7. **Verify the Base AppAuth contracts** for the five live app IDs +
   `DstackKms` on Basescan.
   *Consequence with pinned client:* zero functional impact — `eth_call`
   works against the ABI regardless of source verification. Pure
   auditability concern: blocks human review and reproducibility of any
   third-party audit.

8. **Fix the dstack-ingress evidence-renew script** so `quote.json` is
   regenerated alongside `cert-…pem` / `sha256sum.txt` on Let's Encrypt
   rollover. Currently 0 bytes since 2026-05-02 04:49 UTC; compose hash
   unchanged so it's an operational regression in the renew hook.
   *Consequence with pinned client:* zero on path B/C. Path A users
   currently can't bind the live TLS cert fingerprint to a TDX quote — the
   cert-content side still works but the TDX-anchored leg is missing.

9. **Drop the `MODEL_DISCOVERY_*` env entries** from the cloud-api compose
   (pure cleanup; the binary no longer reads them — only
   `MODEL_DISCOVERY_API_KEY` survives as a fallback name for
   `INFERENCE_API_KEY`).
   *Consequence with pinned client:* zero. Removes a dead path so future
   audits don't have to chase it.

### Issue closure

10. **Close [`nearai/cloud-api#224`](https://github.com/nearai/cloud-api/issues/224)**
    once (3) and (4) ship. The original "cloud-api should only add
    verified model nodes" objection is server-side compose + image
    enforcement.

Headline ordering: **`setKmsInfo` first** (most asymmetric — one tx for
NEAR, fundamentally improves the trust story for every non-pinned client),
then **published manifest** (unblocks generic verifiers and removes the
out-of-band trust on contract addresses), then **server-side allowlists +
TCB-up-to-date**, then **governance**, then cleanup.

---

## Source code references (cloud-api `main` as of 2026-05-02)

- TDX/GPU verifier: `crates/services/src/attestation/verification.rs`
- Inline verify entry: `crates/services/src/inference_provider_pool/mod.rs::create_verified_client` (line 131)
- Admin write path for `inference_url`: `crates/api/src/routes/admin.rs:108–217`
- DB column: `crates/database/src/migrations/sql/V0048__add_model_inference_url.sql`
- Config plumbing for `MODEL_DISCOVERY_API_KEY` fallback: `crates/config/src/types.rs::ApiConfig::from_env`
