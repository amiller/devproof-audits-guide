# Chutes Confidential Inference — DevProof Audit

**Audit date:** 2026-05-25
**Target:** `chutes.ai` — serverless AI inference on Bittensor **subnet 64**, by Rayon Labs. Confidential (`-TEE`) models on Intel TDX + NVIDIA confidential-compute GPUs, E2E-encrypted with ML-KEM-768.
**Repos (HEAD at clone):** `rayonlabs/chutes` `08d79872` (SDK) · `rayonlabs/chutes-api` `77b6f355` (control plane) · `rayonlabs/chutes-miner` `7afea4b1` (operator)
**Live at probe time:** 13 models on `llm.chutes.ai`, **12 `confidential_compute: true`**; 10 published measurement configs across h200 / b200 / RTX PRO 6000.

This is a **devproof** audit: the question is whether Chutes' claims are *externally verifiable by a client without trusting Chutes*, not whether the system is "secure" in the abstract. Findings are framed as verifiability gaps suitable for public GitHub issues.

> **Exploitability validation (2026-05-25):** see [`EXPLOITABILITY-VALIDATION.md`](./EXPLOITABILITY-VALIDATION.md). After reviewing the published guest build (`chutesai/sek8s`), the severities below are reprioritized: **F1's "miner can swap the model" is withdrawn** (a measured fail-closed OPA+cosign admission controller + TEE-gated LUKS-key release contain a malicious miner — model substitution reduces to operator-trust); **F2 is overstated** (provenance is reachable via the published builder + recompute scripts); **F5 is not miner-extractable** (operator-trust). The real top priority is **V0** — the mainstream OpenAI-compatible path sends prompts **plaintext through the control plane**, so "not even we can see your data" holds only on the opt-in verified-E2E path (**F3**). The RTMR register offsets in the original §[6] were also corrected.

---

## Quick Status

| Property | Verifiable today? | Notes |
|---|:--:|---|
| TDX quote authenticity (Intel DCAP) | ✅ | standard, client-checkable |
| Debug mode disabled | ✅ | `td_attributes` bit 0 = 0, confirmed live |
| Per-request freshness | ✅ | client nonce → fresh quote, confirmed live |
| E2E key ↔ hardware binding | ✅ | `report_data[0:32] == SHA256(nonce‖e2e_pubkey)`, confirmed live |
| ML-KEM private key inside the TD | ✅ | native `aegis` lib; control plane/host see only ciphertext |
| Quote MRTD ↔ *published* golden value | ✅ | matches `/servers/tee/measurements`, confirmed live |
| **Meaning** of that golden value (image provenance) | ❌ | **F2** — no reproducible build, TOFU on Chutes' ConfigMap |
| **Which model** is served | ❌ | **F1** — model identity in no measured register |
| Verify-then-encrypt by default | ❌ | **F3** — discovery hands out keys with no quote; shipped sample skips verification |
| GPU genuineness / CC-mode / RIM offline | ❌ | **F4** — verdict only via NVIDIA NRAS cloud call |
| Rootfs key isolation | ⚠️ | **F5** — single static `LUKS_PASSPHRASE` for the whole fleet |

---

## TL;DR

The **cryptographic core is sound and genuinely hardware-rooted**: a client who does the work can prove it is talking to a real, non-debug Intel TDX enclave whose ML-KEM-768 key is hardware-bound, with per-request freshness, and that the control plane and miner host see only ciphertext. We confirmed all of this against the live API (`verify/verify_chutes.py`).

But **five gaps stop Chutes short of the "verify without trusting us" posture** it claims (`docs/tee-verification.md:5`):

1. **F1 — the served model is not attested (High).** MRTD/RTMR0/1/2 are byte-identical across two different models; nothing in the quote binds `model_name`+`revision`+container digest. Worse, the two mechanisms that *could* catch a swap — the launch-time command check and the runtime weight-digest monitor — are both **disabled on the TEE path**.
2. **F2 — golden measurements are unverifiable (High).** The TDX VM image is in none of the repos and has no published reproducible build; the golden MRTD/RTMRs are operator-injected ConfigMap constants. No `dstack-mr`-equivalent, no on-chain anchor for measurements.
3. **F3 — verify-then-encrypt is optional and the shipped sample skips it (High).** `/e2e/instances` hands out `e2e_pubkey` with **no quote**; `scripts/test_e2e_client.py` encrypts straight to it. A malicious control plane can hand out its own key and read prompts.
4. **F4 — GPU attestation has no offline verdict (Low–Medium).** Genuineness / CC-mode / RIM-measurement matching come only from a signed NVIDIA NRAS cloud response; the API exposes raw evidence, not pre-verified tokens.
5. **F5 — rootfs disk key is one static fleet-wide secret (Medium).** `LUKS_PASSPHRASE` is a single env var returned to every node on boot attestation.

F1 and F2 are the load-bearing ones: together they mean a verified Chutes quote proves "a genuine TDX+GPU box running *some* Chutes-blessed VM image," not "this specific model, on an image I can independently audit."

---

## Architecture

Two verification regimes coexist; only the second is confidential:

- **GraVal** — GPU proof-of-work (proof the miner physically holds the claimed GPUs). No confidentiality. Used by normal chutes.
- **TDX flow** — Intel TDX CVM + NVIDIA CC mode + ML-KEM-768 E2E. Used by the `-TEE` chutes. **In scope.**

```
client ──── ML-KEM-768 E2E (prompt ciphertext) ─────────────────────────┐
   │  also fetches + (should) verify the quote                          │
   ▼                                                                     ▼
chutes-api control plane  ── picks instance, hands out e2e_pubkey+nonces, relays, bills
   │  sees: routing, user↔chute↔instance, timing, token COUNTS. Never plaintext.
   ▼  (adds a transport-encryption layer around the still-E2E-encrypted blob)
miner host (permissionless, OUTSIDE the trust boundary)
   │  k8s Job; rootfs LUKS key released post-boot-attestation
   ▼
┌─ Intel TDX CVM ─────────────────────────────┐   ┌─ 8× NVIDIA GPU (CC mode) ─┐
│ aegis lib holds ML-KEM privkey (in-TD)       │   │ per-GPU NRAS evidence,    │
│ vLLM/SGLang + model weights (pulled at boot) │   │ nonce-bound to the TD     │
└──────────────────────────────────────────────┘   └───────────────────────────┘
        ▲ report_data[0:32]=SHA256(nonce‖e2e_pubkey)   report_data[32:64]=SHA256(attest-svc cert SPKI)
```

**Client flow (third-party path), all confirmed live:**
1. `GET /e2e/instances/{chute_id}` → `{instances:[{instance_id, e2e_pubkey, nonces[]}]}`. `nonces[]` are single-use **relay** tokens, *not* the attestation binding.
2. `GET /instances/{instance_id}/evidence?nonce=<64 hex>` → `{quote, gpu_evidence[], certificate}`; **client supplies the nonce**, the instance regenerates a TDX quote bound to it (`server/service.py:1098-1137`).
3. Verify: DCAP signature, debug off, `report_data[0:32]==SHA256(nonce‖e2e_pubkey)`, MRTD/RTMRs vs golden, GPU evidence via NRAS.
4. `POST /e2e/invoke` relays the ML-KEM-encrypted blob.

---

## What is externally verifiable today (the strong parts)

Run `verify/verify_chutes.py` (no payment, ~5s). Live output, two distinct models:

```
[1] report_data[0:32] == SHA256(nonce+pub)  : True   (E2E key hardware-bound)
[2] two nonces -> different report_data      : True   (per-request freshness — quote regenerated in-TD)
[3] debug mode disabled                      : True
[4] report_data[32:64] == SHA256(cert SPKI)  : True   (attestation-service TLS cert bound into quote)
[5] MRTD in published golden set             : True
```

Server-side authoritative binding: `instance/util.py:1073` — `hashlib.sha256((nonce + e2e_pubkey).encode())`. This is byte-for-byte the formula in our [redpill case study](../redpill-federated-inference/DEVPROOF-REPORT.md)'s `chutes.ts`; Redpill federates to these backends.

The ML-KEM-768 keypair is generated by the in-TD native `aegis` library and the private key never leaves it (`chutes/chutes/entrypoint/run.py:789-801`); `/e2e/invoke` only wraps/relays ciphertext and reads plaintext token *counts* for billing (`e2e/router.py:243,251,380-418`). So **confidentiality of an E2E request from the control plane and the miner host is real** — conditional on F3.

---

## Findings

### F1 — Served model identity is not attested (High)

**Claim audited:** that a `-TEE` chute named e.g. `Qwen/Qwen3-32B-TEE` is actually serving those weights.

**Finding:** nothing a client can verify binds the model. Across two different live models (`Qwen3-32B-TEE`, `gemma-4-31B-TEE`) the quote's **MRTD, RTMR0, RTMR1, RTMR2 are byte-identical** (`verify_chutes.py` check [6]; all 10 published configs share one MRTD `DDC6EFCD…`). RTMR3 varies only with the **VM-image version** (zero in configs v1.0.0–v1.2.0; `BFAC8BBE…` in v1.3.0, where initramfs extends it for LUKS — `server/service.py:200`), and that value is identical across hardware types and across models on the same config — it tracks the image/LUKS state, **not** the model. `model_name`/`revision` are never extended into any RTMR nor placed in `report_data`.

The model is loaded *outside* the measured boundary: the miner runs the chute as an ordinary k8s Job from a string image ref (`chutes-miner/.../k8s/util.py`, `chute/schemas.py:190`), weights pulled at container start via `snapshot_download(repo_id, revision)` (`chutes/chute/template/vllm.py:335-337`), vLLM launched `--model … --revision …` (`vllm.py:466-471`). The `tee=` flag (`chute/base.py:82`) only sets a DB boolean.

The two mechanisms that could catch a swap are **disabled for TEE**:
- The launch-time command check (`verify_expected_command`, compares running `--model`/`--revision` to the declared chute) is only called from the GraVal path `_validate_graval_launch_config_instance` (`instance/router.py:1719`), never from `_validate_tee_launch_config_instance` (`:1728`).
- The continuous weight-digest monitor (`watchtower.py:323-365`) explicitly excludes TEE: `LaunchConfig.env_type != "tee"  # Exclude TEE` (`watchtower.py:91`).

**Impact:** a compromised/malicious miner can load different weights or a patched inference container and still pass the published verification. Same gap family as our NEAR-AI / Redpill model-substitution findings. **Severity: High** — this is half the product claim ("you are talking to model X, privately"); the privacy half is verifiable, the identity half is not.

**Fix:** extend `SHA256(image_digest ‖ model_name ‖ revision)` into RTMR3 and publish model-keyed expected values; or re-enable the command check + weight-digest monitor on the TEE path.

### F2 — Golden measurements are not independently reproducible (High)

**Claim audited:** `docs/tee-verification.md:5` — "verify without trusting us."

**Finding:** the MRTD/RTMR values that define a "legit" Chutes enclave are **operator-asserted constants**, not derivable from published source. The TDX guest VM image (TDVF/OVMF, kernel, initrd, rootfs) is in **none** of the three repos; there is no build pipeline, no `mkosi`/Yocto/Nix recipe, no `dstack-mr`-equivalent MR-computation tool. The maintenance spec confirms the image is an external prebuilt artifact: *"The release pipeline exposes only the latest VM image"* (`chutes-api/docs/specs/server-maintenance.md:103`). The shipped Helm template carries only `PLACEHOLDER_MRTD_96_HEX_CHARS` / `PLACEHOLDER_RTMR…` (`charts/templates/tee-measurements-cm.yaml:18-30`) — real values are hand-injected into the cluster ConfigMap (`api/config/__init__.py:334-413`). The client guide never even instructs callers to compare MRTD against the golden set.

On-chain commitments do **not** help: the miner commits `SHA256(usage report)` to Bittensor `Commitments` (`chutes-miner/.../audit_exporter.py:186-213`) — billing data only, no measurements — and the validator's `set_commitment` is **commented out** (`chutes-api/audit_exporter.py:135-155`).

**Impact:** a client can confirm "a TD with MRTD `DDC6…` is running," but must take Chutes' word for what that image *is* (no operator backdoor, no prompt logging). Textbook TOFU. **Severity: High.** Contrast dstack (`meta-dstack` + `dstack-mr` + on-chain `compose_hash`/KMS registry), which the rest of this repo's cohort leans on — Chutes has none of those three legs.

**Fix:** publish the guest-image source + a reproducible build that recomputes MRTD/RTMR0-2; anchor the accepted measurement set (with version history) on-chain or in a transparency log.

### F3 — Verify-then-encrypt is optional; the shipped sample skips it (High)

**Finding:** discovery and attestation are separate endpoints. `GET /e2e/instances/{chute_id}` returns `{instance_id, e2e_pubkey, nonces}` with **no quote** (`e2e/router.py:144-151`); the `e2e_pubkey` is just a DB field set by the miner at registration (`instance/router.py:1416`). Nothing in the discovery or `/e2e/invoke` path cross-checks it against a quote. The only runnable example, `scripts/test_e2e_client.py`, does `build_e2e_blob(instance["e2e_pubkey"], …)` straight from `discover_instances()` (`:120-128`) with **no** `/evidence` call and **no** `report_data` check.

**Impact:** a client following the path of least resistance (or the sample) encrypts to whatever key the control plane serves. A malicious/compromised control plane (or a discovery-response MITM) hands out an attacker-controlled `e2e_pubkey` and reads all prompts — bypassing TDX entirely. The docs describe the secure pattern and even warn about this MITM (`docs/tee-verification.md:409-411`), but the demonstrated code contradicts it; the server cannot enforce client-side verification by construction. **Severity: High** because the failure is silent and the canonical example is the insecure variant.

**Fix:** ship a verifying client / fold the `/evidence` fetch + `report_data` check into the E2E SDK so verify-then-encrypt is the default, not an optional second call. Bind verification to the specific `instance_id`+`e2e_pubkey` the client encrypts to.

### F4 — GPU attestation has no offline verdict (Low–Medium)

**Finding:** the nonce binding is sound — each GPU's raw evidence embeds `SHA256(nonce‖e2e_pubkey)` (the same value as the TDX `report_data`), proving the 8 GPUs and the CPU TD are the same machine/session (verified live). But the security verdict (genuine GPU, CC-mode ON, VBIOS/driver RIM match, revocation) is produced entirely by **NVIDIA's hosted NRAS** service: `verify_gpu_evidence` shells out to `chutes-nvattest` (`server/util.py:623-645`) → `NvVerifier.attest()` with `Environment.REMOTE` and empty URL (`nv-attest/chutes_nvattest/verifier.py:6-13`) → POST to `nras.attestation.nvidia.com`, trusting the signed `x-nvidia-overall-att-result` JWT. The API exposes **raw** per-GPU `{certificate, evidence, arch}`, not pre-verified tokens, so an offline client can only check the cert chain + nonce embedding; CC-mode and RIM matching require a network call to NVIDIA (or trusting Chutes). This matches Redpill's documented "light mode" punt.

**Severity: Low–Medium** — a soundness-preserving limitation inherited from NVIDIA's tooling (the verdict JWT is ES384-signed and Chutes can't forge it), not a Chutes bug. **Fix:** use NVIDIA's `LOCAL` GPU verifier (bundled RIM/golden measurements) so CC-mode + measurement matching can be done client-side against the evidence already exposed.

### F5 — Rootfs LUKS key is a single static fleet-wide secret (Medium)

**Finding:** on successful boot attestation the control plane returns `key = get_luks_passphrase()` (`server/router.py:127`), which is `settings.luks_passphrase` — a single static `LUKS_PASSPHRASE` env var (`server/util.py:364-377`, `config/__init__.py:415`), identical for every VM and miner. Release is measurement-gated (a valid boot TDX quote matching golden values), but the key is neither per-node nor TD-derived nor on-chain. (Per-volume *cache* passphrases ≥v1.3.0 are random and Fernet-encrypted per node — `util.py:535-577` — closer to real KMS behavior; the rootfs key is the weak point.)

**Impact:** whoever holds `LUKS_PASSPHRASE` can decrypt any TEE node's rootfs offline, with no per-node isolation. Note rootfs confidentiality ≠ live-prompt confidentiality (prompts live in TDX-protected memory + the F3 E2E key), so impact is bounded. **Severity: Medium.** **Fix:** derive/seal the rootfs key per-TD (sealed to measurements) rather than handing out a shared static secret.

### F6 — cert binding is to the attestation-service endpoint, not the E2E path (informational)

`report_data[32:64] == SHA256(SPKI)` of the returned `certificate`, whose subject is `CN=attestation-service` (the host's internal attestation proxy at `10.43.50.50:8443`, `chutes/constants.py:4`) — confirmed live. This is meaningful for the validator's provisioning flow but is **orthogonal** to the client→enclave E2E channel, whose integrity rests entirely on `report_data[0:32]`. Also, `/instances/{id}/evidence` does **no** server-side verification — it proxies raw quote+cert (`server/service.py:1098-1114`); all checking is the client's job (see F3). Informational, but worth stating so verifier authors don't mistake `report_data[32:64]` for an E2E-key or serving-cert binding.

---

## Stage Assessment

Against the framework's prompt-path / external-verifiability rubric:

- **Confidentiality (operator can't read prompts):** reaches a strong posture **conditional on the client performing verify-then-encrypt** (F3). The ML-KEM key is in-TD and the relay sees only ciphertext. If the client uses the shipped happy path, trust silently collapses onto the control plane → fails the operator-no-access test.
- **Integrity / "right code & model":** **does not** reach the dstack cohort's posture. F1 (model not measured) and F2 (golden values not reproducible) mean the measured-boot story is not independently auditable end-to-end. A verified quote proves genuine TDX+GPU hardware running *a* Chutes-blessed image — the image's contents and the served model are trust-me.

Net: **the hardware root is real and the crypto is correct; the verifiability chain breaks at image provenance (F2) and model binding (F1), and the default client UX undercuts the confidentiality guarantee (F3).** This is a different shape from the dstack-based cases (no KMS/on-chain compose registry, no reproducible MRs) and from Tinfoil — Chutes rolls its own measurement registry and key release.

---

## Recommendations (priority order)

1. **(F3)** Make verify-then-encrypt the default: ship an E2E client that fetches `/evidence`, checks the DCAP signature + debug bit + `report_data[0:32]` binding for the exact `instance_id`+`e2e_pubkey` before encapsulating. Fix `scripts/test_e2e_client.py`.
2. **(F1)** Measure the workload: extend `SHA256(image_digest‖model‖revision)` into RTMR3 and publish model-keyed expected values, or re-enable the command check + weight-digest monitor on the TEE path.
3. **(F2)** Publish the guest-VM image source + reproducible build (a `dstack-mr`-style recomputation), and anchor the accepted measurement set with version history on-chain / in a transparency log.
4. **(F4)** Offer the NVIDIA `LOCAL` GPU verifier path so CC-mode + RIM can be checked offline.
5. **(F5)** Per-TD sealed rootfs keys instead of a shared static `LUKS_PASSPHRASE`.

---

## Reproduction

```bash
# 1. Get a Chutes API key, put it in /tmp/ck  (Bearer cpk_...)
# 2. List confidential models
curl -s -H "Authorization: Bearer $(cat /tmp/ck)" https://llm.chutes.ai/v1/models \
  | jq '.data[] | select(.confidential_compute==true) | .id'
# 3. Published golden measurements (note: 10 configs, ONE MRTD)
curl -s -H "Authorization: Bearer $(cat /tmp/ck)" https://api.chutes.ai/servers/tee/measurements | jq .
# 4. Full attestation reproducer (checks [1]-[6] above, incl. model-substitution)
python3 verify/verify_chutes.py
```

---

## Source

| Repo | HEAD | Role |
|---|---|---|
| `rayonlabs/chutes` | `08d79872` | SDK; in-TD evidence producer (`entrypoint/verify.py`, `run.py`, `aegis`) |
| `rayonlabs/chutes-api` | `77b6f355` | control plane; verification (`server/util.py`, `instance/util.py`), measurements, LUKS KMS, `watchtower.py`, `docs/tee-verification.md`, `scripts/test_e2e_client.py` |
| `rayonlabs/chutes-miner` | `7afea4b1` | operator; k8s launch, `tee_images`, `audit_exporter.py` |

Clones are in `refs/` (gitignored; re-fetch commands in `.gitignore`). The "chutes shape" cross-references [redpill-federated-inference](../redpill-federated-inference/DEVPROOF-REPORT.md).

## Prior art / cross-references

- Model-substitution gap: [near-ai-private-inference](../near-ai-private-inference/), [redpill-federated-inference](../redpill-federated-inference/).
- Reproducible-MR baseline (what F2 lacks): the dstack cohort (`dstack-mr`, `meta-dstack`, on-chain KMS/compose registry).
- Verify-then-encrypt / incomplete-easy-path (F3): mirrors the NEAR web-verifier and Darkbloom F5 patterns.
