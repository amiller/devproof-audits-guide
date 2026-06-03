# Alternate Futures — DevProof inquiry (kickoff 2026-05-25)

## What the target actually is
Alternate Futures (alternatefutures.ai) is a **multi-provider DePIN PaaS** — a Vercel/Netlify/Fleek/Spheron
competitor. Static sites + serverless functions on IPFS, plus a general "deploy any service" path that
orchestrates compute across providers:
- **Akash / Spheron** — plain Ubuntu VMs + GPU leases (no TEE)
- **Phala Cloud** — TDX CVMs (`tdx.small…xlarge`) and GPU CVMs (`h200`), `computeKind: Standard | Confidential`

The "TEE GPU provider" angle is real: AF brokers Phala TDX/GPU CVMs by shelling out to the `phala` CLI
(`service-cloud-api/src/services/queue/phalaSteps.ts`, `src/services/phala/orchestrator.ts`).

## The confidentiality claims (what they market)
- `web-docs/docs/guides/functions.md`: Cloud Functions with "optional SGX". SGX provides
  "Encrypted Execution", **"Attestation — Verify code hasn't been tampered with"**, "Confidential Computing".
- `web-docs/docs/guides/index.md`: "Privacy-First Apps — Run functions with SGX encryption **where not even the
  host can see your data**."
- `web-docs/docs/guides/glossary.md`: SGX = "A vault inside the computer — **even the computer's owner can't peek
  inside** … not even the cloud provider can see your data."
- `reports/parallax-comparison/index.html`: "TEE: Intel TDX/AMD SEV-SNP (defense-in-depth, post-TEE.fail)";
  positions TEE as one layer of a "6-layer FHE/ZK/TEE/WASM stack".

## Initial findings (all from source; sources/ is gitignored)

### F1 — No attestation surface exposed to end users
GraphQL schema (`service-cloud-api/src/schema/typeDefs.ts`) has **zero** attestation fields: no `quote`,
`report_data`, `rtmr`, `compose_hash`, `measurement`, `mrenclave`, `tcb`. The only `verif*` fields are domain
DNS TXT verification. A user who deploys a "Confidential" Phala CVM gets back `{ appId, invokeUrl }` and has no
AF-provided way to obtain or verify a TDX quote / compose hash / measurement. The docs' "Attestation — verify
code hasn't been tampered with" has no corresponding API. (Phala's own 8090 endpoint / trust-center exists, but
AF neither surfaces nor documents it.)

### F2 — `sgx` / `Confidential` are operator-set booleans, no client verification
`package-cloud-sdk/src/clients/functions.ts`: `deploy({ sgx?, blake3Hash?, ... })` just sets fields on the
`triggerAFFunctionDeployment` mutation. Returned deployment carries only `id/cid/timestamps`. `blake3Hash` is
client→server (user *asserts* a hash), never server→user proven-from-a-quote. Schema: `sgx: Boolean!`,
`computeKind: 'Standard' | 'Confidential'` — pure deploy inputs. Nothing measures or attests. Mock state shows
every seeded deployment `sgx: false, blake3Hash: null`.

### F3 — AF (operator) keeps a root SSH backdoor into every CVM, incl. "Confidential" — contradicts the headline claim  [VERIFIED 2026-05-25]
`phalaSteps.ts:175`: every deploy appends `--ssh-pubkey <platform key> --dev-os` (unconditional — runs whenever
the platform pubkey file exists, which it always does in prod; `getShell` even errors telling you to generate it).
AF holds a single platform SSH private key (`~/.ssh/af_phala_ed25519`, override `PHALA_SSH_KEY_PATH`).
`orchestrator.ts:317` `getShell()` opens an interactive **root** PTY: `ssh root@<appId>-22.<gateway> -i <platform
key>` (tunneled via `openssl s_client` on :443). So AF can shell into any CVM it deployed. Directly contradicts
"even the computer's owner can't peek inside / not even the host can see your data." ERC-733 Stage-1 "no
backdoor/debug paths" fail.

**`--dev-os` semantics confirmed (Phala docs/CLI):** "SSH and SCP access require deploying with the `--dev-os`
flag." "In production images, the host CVM does not have ssh server service enabled… for development images
(`dstack-x.x.x-dev`) you can SSH into the CVM." So `--dev-os` is *precisely* the flag that enables the in-CVM
SSH server. AF runs the **development OS image** on every deployment, including the "Confidential" tier. Two
consequences:
  1. Operator (and anyone with the platform key) has root SSH into the enclave — the confidentiality claim is false.
  2. The dev OS image has a **different measurement** (OS image hash → RTMR0/MRTD) than the hardened prod image,
     so even a user who could attest would see a debug image, not a production-hardened one.

Shipped, not dead code: `getShell` backs an advertised feature — templates say "Connect via the web terminal or
CLI" / "Use `af services shell` or the web terminal to connect" (`templates/definitions/gpu-instance.ts`).
By contrast `getPhalaAttestation` (`phala cvms attestation`) has **no caller anywhere** — capability exists,
never surfaced. (And `phala cvms attestation` only works for the app *owner* = AF, never the end user.)

### F4 — Operator controls the whole compose: image, env, secrets
`src/templates/compose.ts` `generateComposeFromTemplate` emits `image: ${template.dockerImage}` (mutable tag,
operator-chosen) + operator-injected `envOverrides`. Classic config-control gap. tappd.sock is mounted "for
in-app attestation," but nothing consumes the quote on the user's behalf.

### F5 — Internal inconsistency in the TEE story
Docs market **SGX** (Intel CPU enclave, MRENCLAVE). Backend deploys **Phala TDX/SEV CVMs** (VM-level, RTMR/
compose-hash) and GPU CVMs — a different TEE entirely. Parallax report says TDX/SEV-SNP + FHE/ZK/WASM layers.
The SGX-functions marketing doesn't match the TDX-CVM implementation. Smells aspirational.

## Preliminary verdict
**Stage 0.** Strong confidentiality marketing ("vault even the owner can't peek inside", "attestation") with
(a) no user-facing attestation/verification surface and (b) an operator root-SSH channel (`--dev-os` +
platform key) into every CVM. The TEE is real infra (Phala), but AF sits in front of it as a fully-trusted
operator and exposes none of the verification.

## Repos cloned into sources/
web-docs.alternatefutures.ai, reports, web-alternatefutures.ai, package-cloud-sdk, service-cloud-api,
service-builder, swarm-runtime, infrastructure-proxy

## Open threads / where to go deeper
- Live-probe a real AF-deployed Phala CVM's 8090 endpoint — BLOCKED: no public app-id in any repo; needs an AF
  account or a published demo appId + `default_gateway_domain`. Gateway port-map is `<appId>-<port>.<gateway>`
  on :443 (e.g. `-22`=SSH, `-8090`=dstack info). Supply an appId and this becomes a one-shot curl.
- service-builder (Nixpacks): are function images reproducible / pinned by digest?
- swarm-runtime (Rust "agent runtime"): any real enclave code, or orchestration only?
- Draft AF-facing issue(s): surface attestation to users; drop `--dev-os`/SSH for Confidential tier.
