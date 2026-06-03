# Architecture comparison: Tinfoil-Containers vs dstack

**Companion to:** [`DEVPROOF-REPORT.md`](DEVPROOF-REPORT.md), [`UPDATES-VS-DSTACK.md`](UPDATES-VS-DSTACK.md)
**Date:** 2026-04-30
**Scope:** persistence, gateway / TLS termination, cross-CVM identity, registry support, centralization map, path-to-web3-grade

The [updates comparison](UPDATES-VS-DSTACK.md) covered "who controls the allowed set of versions." This file covers the remaining architectural axes: what survives across launches, who terminates TLS, how multiple CVMs share state, what the centralization footprint actually looks like, and what would have to change for Tinfoil to become "web3-grade."

---

## 1. Persistence model

| | dstack | Tinfoil-Containers |
|---|---|---|
| **Persistent disk** | Yes — `disk_size` parameter in vmm; LUKS-encrypted with KMS-derived key ([`vmm/src/main_service.rs:392-401`](https://github.com/Dstack-TEE/dstack/blob/main/vmm/src/main_service.rs#L392-L401), [`vmm/src/app.rs:49`](https://github.com/Dstack-TEE/dstack/blob/main/vmm/src/app.rs#L49)) | **No native persistent disk.** `Volumes []string` in the YAML schema is passed straight to Docker as `hostConfig.Binds` ([`containers.go:325-328`](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/containers.go#L325-L328)), but the host filesystem itself is dm-verity read-only rootfs + ephemeral writable scratch — nothing survives the CVM's lifetime |
| **Encryption key for state** | KMS-derived from `app_id`; stable across all allowed `compose_hash`es | n/a — no platform-managed encryption key |
| **State across upgrades** | Yes — `app_id` derives the same key for every allowed compose_hash, so encrypted disks survive | No — each launch is a fresh CVM with rotated HPKE/TLS keypair (empirically observed: relaunching `devproof-hello` rotated TLS pubkey from `e21fdfa9…` to `3a2667ce…`) |
| **State across crashes** | Yes — disk persists; KMS issues the same key to a re-attesting CVM with the same compose_hash | No — same as upgrades; whatever was in writable rootfs is gone |
| **`tmpfs` support** | n/a (use volume) | Yes — `Tmpfs map[string]string` per the YAML schema |
| **Read-only rootfs flag** | n/a | Yes — `read_only: true` ([`config.go:73`](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/config.go#L73)) |

The defining axis. dstack apps are stateful by design. Tinfoil-Containers are stateless by design. **An app that needs encrypted state across versions cannot be ported to Tinfoil-Containers without an external state layer.**

A stateless Tinfoil container that *wants* persistent state today has to:
- Encrypt state to a long-lived external pubkey (not the enclave's HPKE key, which rotates).
- Store the ciphertext in an external database / object store.
- On every relaunch, fetch the ciphertext, decrypt with the app's external private key, run.

The "external private key" problem is the hard part — it has to come from somewhere outside the enclave. Common patterns: KMS (Vault, AWS KMS, Phala-KMS), or peer-to-peer key sharing across attested instances (the [TinfoilAdapter we built in `tee-bridge`](https://github.com/Account-Link/tee-interop/pull/1) is exactly this pattern — Tinfoil CVMs register as bridge members and ECIES-encrypt state to each other).

---

## 2. Gateway / TLS termination

| | dstack | Tinfoil-Containers |
|---|---|---|
| **TLS termination point** | At `dstack-gateway` (a separate dstack CVM running an HTTP/TLS proxy) — see [`gateway/src/proxy/tls_terminate`](https://github.com/Dstack-TEE/dstack/tree/main/gateway/src/proxy) | **Inside the user's CVM** — the Tinfoil shim listens on the public port, terminates TLS using the SEV-attested keypair, and forwards to `shim.upstream-port` |
| **Routing layer** | WireGuard mesh between gateway and backend CVMs ([`gateway/src/config.rs:243-259`](https://github.com/Dstack-TEE/dstack/blob/main/gateway/src/config.rs#L243-L259)) | DNS-based: `<container>.<org>.containers.tinfoil.dev` resolves to the controlplane-managed IP of the CVM serving that name; one CVM per name |
| **TLS pubkey pinning** | `gateway_app_id` is reported in `BootInfo`; users pin to the gateway's measurement | `report_data[0:32] == sha256(SPKI)` of the live cert ([sister case study](../tinfoil-confidential-inference/DEVPROOF-REPORT.md)); users pin to the per-CVM measurement |
| **Plaintext exposure on the request path** | At the gateway — gateway sees decrypted requests before forwarding over WireGuard | None outside the user's CVM — TLS terminates inside the SEV boundary |
| **Multi-host HA for one app** | Yes — multiple backend CVMs sharing `app_id` behind one gateway | No — each `<container>` name maps to one CVM |
| **Custom domain support** | Via gateway config | Via `--custom-domain` flag (TLS still pinned to per-CVM SPKI) |

The TLS-terminates-in-enclave property is one of Tinfoil's stronger architectural choices: the request bytes never cross a service-operator boundary in plaintext. The trade-off is that you can't put a load balancer in front of multiple replicas of the same app — each "replica" is a distinct CVM with a distinct keypair, and clients have to choose which one to talk to.

dstack's gateway is documented as a trust extension: the gateway is itself a dstack CVM with its own measurement, but a client who reaches the gateway has effectively delegated TLS termination to a separate principal. Whether that's acceptable depends on the threat model.

---

## 3. Cross-CVM identity & HA

| | dstack | Tinfoil-Containers |
|---|---|---|
| **Native cross-CVM identity** | Yes — `app_id` is shared; KMS issues the same key to every CVM with `(app_id, allowed_compose_hash, allowed_device_id)` | No — each CVM has its own SEV measurement and HPKE keypair |
| **Native HA** | Yes — multiple CVMs share `app_id` and key, gateway load-balances | No — one CVM per container name |
| **Cross-CVM key sharing pattern** | KMS-issued (centralized) **or** [`dstack-replicatoor`](https://github.com/amiller/dstack-replicatoor) (peer-to-peer key migration via attestation handshakes, with on-chain `UpgradeOperator` contract gating which measurements can join the cluster — 48-hour timelock by default) | Bring-your-own. The `TinfoilAdapter` we [added to `tee-bridge`](https://github.com/Account-Link/tee-interop/pull/1) lets multiple Tinfoil CVMs register as bridge members and ECIES-encrypt secrets to each other; the membership registry is on-chain |
| **Identity that survives "the operator restarts everything"** | `app_id` (lives in KMS state, derivable from `app_compose` + key_provider config) | None at the platform level. The TEEBridge member registration provides one if you wire it up |

The dstack-replicatoor pattern is interesting because it's *also* an alternative to using the dstack KMS. It removes the KMS as a single point of trust by having the CVMs in the cluster verify each other's attestation directly and exchange key material — gated by an on-chain timelock contract. This is essentially the "bring-your-own KMS" pattern that Tinfoil users would adopt anyway, just done with explicit dstack-attestation primitives.

---

## 4. Registry support

| | dstack | Tinfoil-Containers |
|---|---|---|
| **Container image registries** | Anything Docker can pull (operator's host has registry credentials in the dstack VMM config) | Three explicitly: `ghcr.io`, `gcr.io`, Docker Hub. Per-org enabled — `tinfoil registry list` returned `403: private registry access is not enabled for this organization` on a fresh org without opt-in |
| **Config repo / manifest source** | `app-compose.json` is uploaded directly to `dstack-vmm` at deploy time — no external repo dependency | **GitHub-only.** The Sigstore identity policy in `tinfoil-go`'s verifier matches `^https://github\.com/<org>/<repo>/\.github/workflows/.*@refs/tags/.*` — using GitLab/Gitea/self-hosted git would require forking the verifier and Tinfoil's controlplane |
| **Image content addressing** | Operator chooses (image tag, sha256, etc.) | sha256 digest **enforced** in YAML (`image:tag@sha256:...`); the controlplane rejects releases without it. Stronger default than dstack |

The GitHub dependency is real and structural: the Sigstore signature is keyed to a GitHub Actions OIDC identity for `<repo>/.github/workflows/<workflow>@refs/tags/<tag>`. Replacing GitHub means replacing that identity policy — which lives in [`tinfoil-go/verifier/sigstore/sigstore.go:84-93`](https://github.com/tinfoilsh/tinfoil-go/blob/main/verifier/sigstore/sigstore.go#L84-L93) and our [`verifiers/tinfoil.py:_san_regex`](https://github.com/amiller/awesome-private-inference/blob/main/verifiers/tinfoil.py). Both are forkable but neither is configurable.

---

## 5. Where Tinfoil's centralization actually sits

A map of trust roots in the third-party Tinfoil-Containers product, ordered from "physically unavoidable" to "implementation choice that could be replaced":

| Layer | Trust root | Replaceable? |
|---|---|---|
| Hardware attestation | AMD KDS / Intel PCS | No — vendor-controlled root |
| Attestation transport | Sigstore Fulcio + Rekor (TUF-rooted) | Maybe — could anchor commitments on chain instead |
| Code measurement signing | GitHub Actions OIDC for `tinfoilsh/measure-image-action` | Maybe — could run the action in a TEE itself; could replace OIDC with on-chain attestation |
| Config & build manifest source | GitHub repo with tagged release | Forkable but not configurable today |
| Container images | `ghcr.io` / `gcr.io` / Docker Hub | Yes — could use IPFS / OCI distribution over content-addressable storage; doesn't change the hash |
| Deployment orchestration | `https://api.tinfoil.sh` controlplane (closed-source — `gh api repos/tinfoilsh/controlplane` returns 404) | No path today — the controlplane decides which physical SEV-SNP host runs which CVM, manages updates, holds the org's secret store |
| Hardware operator | Tinfoil's own SEV-SNP machines | No path today — would need a marketplace of attested CVM hosts |
| Update authority | Implicit: whoever can publish a Sigstore-signed release for the repo | Could be replaced with on-chain authority (see §6) |

The two unavoidable items are AMD/Intel and the hardware operator (you have to run on someone's SEV-SNP CPU). Everything in between is replaceable with tooling work, but **the controlplane being closed-source is a meaningful gap from a web3-grade perspective** — it's the orchestration layer that decides which host runs which CVM, and it can't be audited or run by third parties today.

---

## 6. Path to a "web3-grade" Tinfoil

Substituting on-chain anchors for each centralized layer above gives a sketch of what a web3-grade Tinfoil-shaped stack would need:

1. **Replace the Sigstore identity policy with an on-chain registry of allowed measurements.** Today the verifier accepts any measurement signed by a GitHub-Actions-OIDC workflow under the configured repo. A web3-grade variant would have the verifier read an on-chain `IAppAuth`-equivalent (call it `ITinfoilAppAuth`) that returns `(allowed, reason)` for a `(measurement, sigstore_bundle)` pair. Whoever can publish a signed release would still need an on-chain transaction to make it "allowed." This converges with dstack's architecture from the other direction.

2. **Move the deployment manifest off GitHub.** Anchor the `tinfoil-deployment.json` content hash on chain (not the file contents — those can stay in GitHub Releases / IPFS). An on-chain registry maps `(app_id, version) → deployment_hash`; verifiers fetch the hash from chain, the JSON from anywhere, verify the hash matches.

3. **Run `measure-image-action` in a TEE.** Today the action runs on shared GitHub Actions runners. Reproducibility helps — the public can rebuild and check — but a TEE-attested builder gives stronger guarantees that the runner wasn't compromised.

4. **Open the controlplane.** This is the hardest. The controlplane currently makes per-deployment decisions (which host, which org's secrets, when to redeploy). A web3-grade version would either (a) move these decisions on-chain (slow, expensive, transparent), (b) move them into an attested CVM whose source is public (the controlplane itself becomes a Tinfoil container), or (c) decentralize the host marketplace such that operators directly negotiate with attested SEV-SNP hosts.

5. **Decouple the host operator.** Today, Tinfoil owns the SEV-SNP machines. A marketplace of attested operators (Akash-style) would let users pick where to deploy without trusting a single host vendor. The launch attestation already proves the SEV is real; the missing piece is operator economics.

6. **Bridge the membership story.** The `TinfoilAdapter` we just added to `tee-bridge` (PR [Account-Link/tee-interop#1](https://github.com/Account-Link/tee-interop/pull/1)) already provides on-chain cross-platform secret sharing for Tinfoil CVMs. A web3-grade Tinfoil could ship this as a first-class feature: every CVM auto-registers with TEEBridge on boot, and inter-CVM state sharing is one API call away.

The most achievable step is (1) — replace the Sigstore identity policy with an on-chain registry — because it leaves the rest of Tinfoil's stack untouched and just changes what the verifier reads. Conceptually it would make Tinfoil a stateless variant of dstack: same on-chain `IAppAuth` shape, but with HPKE keys rotating per launch and no persistent disk.

The hardest step is (4) — opening the controlplane. The closed-source orchestration is where most of Tinfoil's product value sits (deployment UX, billing, monitoring, updates), and replacing it with an on-chain or attested-public alternative is a significant undertaking.

---

## Summary

The two platforms make consistent but opposite choices.

**dstack**: durable identity, persistent encrypted state, KMS-derived keys that survive upgrades, gateway-terminated TLS for HA. Designed for stateful apps with separate principals (deployer ≠ operator). Plug-in upgrade authorities (`IAppAuth`) let policy live anywhere from a single owner to a multi-step ZK-gated DAO.

**Tinfoil-Containers**: fresh enclave per launch, no persistent state at the platform level, in-enclave TLS termination, no native HA. Designed for stateless workloads where rebuild-and-redeploy is already the operating mode. Trust root for upgrades is repo write access — implicit, no separate authority. Persistence and HA are bring-your-own (e.g. via `tee-bridge` / `TEEBridge`).

The choice between them is downstream of the application's state model. Stateful apps (databases, KMS-style services, long-lived agents) want dstack. Stateless serving (inference, API gateways) wants Tinfoil. Hybrid apps want dstack as the bottom layer with Tinfoil as the public-facing serving layer.
