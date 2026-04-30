# Update mechanisms: Tinfoil-Containers vs dstack

**Companion to:** [`DEVPROOF-REPORT.md`](DEVPROOF-REPORT.md) (Tinfoil-Containers operator-side audit)
**Date:** 2026-04-30
**Sources walked:** [`tinfoilsh/cvmimage`](https://github.com/tinfoilsh/cvmimage), [`tinfoilsh/tinfoil-cli`](https://github.com/tinfoilsh/tinfoil-cli), [`Dstack-TEE/dstack`](https://github.com/Dstack-TEE/dstack) (`kms/`, `kms/auth-eth/contracts/`)

Both platforms run user-supplied code in confidential VMs and want to let operators ship updates without losing the security properties. They make opposite design choices about *who decides what version is allowed*, *whether secrets persist across upgrades*, and *what stops a downgrade*. This document maps both designs to source.

---

## Side-by-side

| Axis | dstack | Tinfoil-Containers |
|---|---|---|
| **Identity of "the app"** | `app_id` (stable address); compose_hash changes per release | `repo+tag` (GitHub release); SEV measurement changes per release |
| **What's the unit of "an allowed version"?** | `bytes32 composeHash` in the on-chain `DstackApp` contract's `allowedComposeHashes` mapping | A GitHub release tag with a Sigstore-signed `tinfoil-deployment.json` produced by the `tinfoil-build.yml` workflow |
| **Who controls the allowed set?** | `DstackApp` contract owner (any EOA / multisig the deployer wires) | GitHub repo write-permission holders (and their actions can produce a signed release) |
| **Per-version review gate?** | Explicit on-chain transaction: `addComposeHash(bytes32)` | Implicit: pushing a tag triggers a workflow that signs |
| **What stops the operator running a non-allowed version?** | KMS refuses to derive the app's secret key without an `isAppAllowed=true` from the contract | Nothing at deploy time. Verifier-side: the user pins to a measurement and refuses to talk to a different one |
| **Persistent state across upgrades** | **Yes** — `app_id` derives the same key for every allowed compose_hash; secrets persist across versions | **No** — each CVM is fresh; HPKE/TLS keypair rotates per launch; encrypted state must be re-bootstrapped from outside on every relaunch |
| **Downgrade prevention** | Contract owner can `removeComposeHash(bytes32)` — KMS then refuses to derive keys for old versions | None at the platform level. Old releases stay Sigstore-signed; `relaunch --tag old-vN` works indefinitely |
| **Auto-update** | Not built-in; each redeploy is operator-driven | `tinfoil container auto-update --on` makes the controlplane redeploy on each new release detected |
| **Operator-side notice period before a redeploy takes effect** | n/a (operator drives) | Default: explicit `tinfoil container update accept`. Auto-update bypasses this |
| **External-auditor view of "current allowed set"** | `cast call <DstackApp> "allowedComposeHashes(bytes32)" 0x…` per version | `gh api repos/<org>/<repo>/releases` + verify each release's Sigstore bundle |

---

## Source trace — dstack

The KMS asks an external authority before deriving a key for a CVM ([`kms/src/main_service/upgrade_authority.rs:71-94`](https://github.com/Dstack-TEE/dstack/blob/main/kms/src/main_service/upgrade_authority.rs#L71-L94)):

```rust
pub async fn is_app_allowed(&self, boot_info: &BootInfo, is_kms: bool) -> Result<BootResponse> {
    match self {
        AuthApi::Dev { dev } => Ok(BootResponse { is_allowed: true, ... }),
        AuthApi::Webhook { webhook } => {
            let url = url_join(&webhook.url, if is_kms { "bootAuth/kms" } else { "bootAuth/app" });
            let response = client.post(&url).json(&boot_info).send().await?;
            ...
            Ok(response.json().await?)
        }
    }
}
```

`boot_info` carries `compose_hash` and `app_id`. The webhook is typically backed by a Solidity contract bridge that calls `DstackApp.isAppAllowed()`:

```solidity
// kms/auth-eth/contracts/DstackApp.sol:130-144
function isAppAllowed(IAppAuth.AppBootInfo calldata bootInfo)
    external view override returns (bool isAllowed, string memory reason)
{
    if (!allowedComposeHashes[bootInfo.composeHash]) {
        return (false, "Compose hash not allowed");
    }
    if (!allowAnyDevice && !allowedDeviceIds[bootInfo.deviceId]) {
        return (false, "Device not allowed");
    }
    return (true, "");
}
```

Adding a new version is one transaction by the contract owner ([`DstackApp.sol:100-103`](https://github.com/Dstack-TEE/dstack/blob/main/kms/auth-eth/contracts/DstackApp.sol#L100-L103)):

```solidity
function addComposeHash(bytes32 composeHash) external onlyOwner {
    allowedComposeHashes[composeHash] = true;
    emit ComposeHashAdded(composeHash);
}
```

Removing a version is symmetric. The contract is `UUPSUpgradeable` and supports `disableUpgrades()` for one-way locking.

### Trust roots
- AMD/Intel hardware root (signs the SEV/TDX report)
- KMS trust root (a separate TEE running the dstack KMS service; identity bound to its own attestation)
- `DstackApp` contract owner (the principal that can call `addComposeHash`, `removeComposeHash`, `addDevice`, `removeDevice`)

The contract owner is normally the deployer (or their multisig). They are a *separate principal* from whoever runs the CVM — even an attacker who compromises the CVM host cannot ship a new version that derives the same key, because the KMS will refuse without an `isAppAllowed=true` from the contract.

---

## Source trace — Tinfoil-Containers

The CVM image has **no upgrade logic**. It boots into one config, derives no persistent identity, and treats every launch as fresh. cvmimage's boot script (`tinfoil/cmd/boot/`) does not contain any code that checks "is this version allowed" — it just verifies the launch measurement matches what's signed and runs the containers.

Updates happen entirely at the controlplane level. The CLI's update commands are thin wrappers over controlplane HTTP endpoints ([`tinfoil-cli/container.go:559-577`](https://github.com/tinfoilsh/tinfoil-cli/blob/main/container.go#L559-L577)):

```go
var containerUpdateAcceptCmd = &cobra.Command{
    Use:   "accept [id|name]",
    Short: "Promote a ready staged update",
    RunE: func(cmd *cobra.Command, args []string) error {
        ...
        if _, err := client.do("POST", pathf("/api/containers/%s/update/accept", c.ID),
                               nil, nil, &updated); err != nil {
            return err
        }
        return renderContainer(updated)
    },
}
```

`auto-update --on` is similarly a single API call ([`container.go:403-419`](https://github.com/tinfoilsh/tinfoil-cli/blob/main/container.go#L403)). The `containerView` struct exposes the relevant state ([`container.go:38-44`](https://github.com/tinfoilsh/tinfoil-cli/blob/main/container.go#L38-L44)):

```go
AutoUpdate         bool              `json:"auto_update"`
GroupName          *string           `json:"group_name"`
GroupOrder         int               `json:"group_order"`
DisplayOrder       int               `json:"display_order"`
UpdateTag          string            `json:"update_tag"`
UpdateStatus       string            `json:"update_status"`
```

When the controlplane detects a new release for the connected repo (presumably via the GitHub App if `github_app_connected: true`, otherwise via polling), it stages it as `update_tag` and `update_status: ready`. The operator then `accept`s. The controlplane provisions a fresh CVM with the new attested config; the old CVM is torn down (or replaced atomically via `--replace`).

The "allowed version" check, such as it is, lives in the verifier (`tinfoil-go` / `verifiers/tinfoil.py`): it pulls the latest Sigstore bundle for the repo+tag from the GitHub release assets and asserts the live attestation's measurement equals the one Sigstore signed. There is no separate authority that says "this measurement is allowed." Whoever can publish a signed Sigstore release for the repo can publish a new "allowed" version.

### Trust roots
- AMD hardware root (signs the SEV report)
- Sigstore Fulcio + Rekor (signs the deployment.json under a GitHub Actions OIDC identity)
- The repo owner (whoever can push tags + run workflows under `^https://github.com/<org>/<repo>/.github/workflows/.*@refs/tags/.*`)

The repo owner is normally the same principal as the deployer (the org that creates the Tinfoil container deploys from a repo it owns). There is no separate "contract owner" authority. The verifier-side defense against a rogue release is `pin_to_measurement` — i.e., the user records the measurement they trust and refuses to talk to anything else.

---

## Compromise scenarios

| Compromise | dstack | Tinfoil-Containers |
|---|---|---|
| **CVM host (the machine running the CVM)** | Attacker can stop the CVM but cannot derive its key (KMS refuses without correct attestation). Existing encrypted state remains encrypted | Same. Attacker can DoS but the SEV launch measurement gates everything; no key to steal at the host level |
| **Repo write access (Tinfoil) / contract owner key (dstack)** | Attacker calls `addComposeHash(bad_hash)`, deploys malicious CVM with that hash, KMS derives the same app_key → full compromise of stored secrets. Mitigation: contract owner uses a multisig + timelock | Attacker pushes a new tag, workflow signs deployment.json, operator (or auto-update) accepts → new CVM runs attacker's code. NEW HPKE keypair, so existing encrypted-in-transit prompts are not retroactively readable, but new prompts go to attacker-controlled enclave. Mitigation: verifier-side measurement pinning |
| **GitHub Actions OIDC** | n/a | Attacker who compromises GitHub Actions infrastructure for the repo could mint a Sigstore signature for arbitrary content. Mirrors the upstream tinfoil-go's trust assumption |
| **AMD VCEK / Intel PCS** | Same — vendor root of trust | Same |
| **KMS image** | Compromise of the KMS image lets attacker derive arbitrary keys; mitigated by KMS being itself a dstack CVM with its own compose_hash on chain | n/a — no separate KMS service |

The critical asymmetry: **dstack pushes the upgrade-authority check into a separate principal** (contract owner) so that compromising the CVM operator alone is insufficient to ship a malicious upgrade. **Tinfoil-Containers conflates the upgrade-authority and the operator** — whoever can publish to the repo can ship the upgrade. That's an explicit trade-off, not an oversight: Tinfoil's design assumes secrets do not persist across upgrades, so the cost of a malicious upgrade is bounded to "future prompts go to attacker" rather than "all stored secrets are now attacker-readable."

---

## When each design is appropriate

**dstack's "persistent app_id, gated upgrades" model fits:**
- Apps that need to retain encrypted state across versions (databases, key derivation services, KMS-style apps).
- Multi-tenant or shared-infrastructure deployments where the deployer and operator are different principals.
- Compliance contexts where a documented, on-chain upgrade trail matters.

**Tinfoil-Containers' "fresh enclave per launch, repo-owner upgrades" model fits:**
- Stateless inference / serving workloads where the only persistent state is the model weights (which are pinned by content hash via dm-verity in Tinfoil's managed-inference product, or by image sha256 in third-party containers).
- Single-principal deployments where the repo owner *is* the deployer and they accept the responsibility of governing their own release pipeline.
- Workloads where "rebuild and redeploy on every change" is already the operating mode (CI/CD-native).

The "fourth class" that the earlier draft of [`DEVPROOF-REPORT.md`](DEVPROOF-REPORT.md) wrongly accused Tinfoil of having would have actually invalidated the second model — an undetectable post-attestation runtime change is incompatible with "fresh enclave per launch." It turned out the model is intact: the operator surface for runtime injection is exactly what the verifier surfaces, and updates go through the repo+Sigstore pipeline.

---

## Things this comparison does NOT cover

- **Tinfoil's managed-inference path** (covered in the [sister case study](../tinfoil-confidential-inference/DEVPROOF-REPORT.md)). The internal model enclaves are deployed by Tinfoil's own CI under repos like `tinfoilsh/confidential-gpt-oss-120b` — same trust root, but the repo owner is Tinfoil rather than the user.
- **dstack's Phala-KMS variant** vs **dstack's on-chain KMS variant**. Both use the `is_app_allowed` interface above; what differs is who runs the KMS and what backs the webhook. The on-chain version (using `DstackApp.sol` directly) is the most reviewable; the Phala-KMS version delegates to a Phala-operated service whose policies are not (publicly) source-traceable.
- **The actual reproducibility of dstack compose_hash → contract entry**. The `DstackApp` contract holds the hash but doesn't say what config produced it. To audit "is this allowed_compose_hash a benign upgrade or a backdoor?" you need to find the matching `app-compose.json` somewhere outside the chain. Same friction Tinfoil avoids by anchoring to a public GitHub repo.
- **`--staging` mode in Tinfoil**. The CLI describes it as "lower-trust environment"; not probed in this audit.
