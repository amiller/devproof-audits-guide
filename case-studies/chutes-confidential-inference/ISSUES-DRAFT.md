# Chutes — file-able issues (devproofness framing)

Draft GitHub issues for `rayonlabs/chutes-api` and `rayonlabs/chutes`. Framed as **verifiability gaps**, not exploits. Each is reproducible against the live API with only an API key. Citations are at the cloned HEADs (`chutes-api 77b6f355`, `chutes 08d79872`, `chutes-miner 7afea4b1`).

---

## Issue 1 (F3) — `test_e2e_client.py` encrypts to a discovered key without verifying attestation

**Repo:** `chutes-api` · **Severity:** High · **Type:** docs/example contradicts the security model

`docs/tee-verification.md:409-411` warns that an unverified `e2e_pubkey` is a MITM vector, but the only runnable client example skips verification:

- `scripts/test_e2e_client.py:120-128` calls `discover_instances()` then `build_e2e_blob(instance["e2e_pubkey"], …)` and ML-KEM-encapsulates to it.
- No call to `/instances/{id}/evidence` or `/chutes/{id}/evidence`, no DCAP check, no `report_data[0:32] == SHA256(nonce‖e2e_pubkey)` check anywhere in the file.
- `GET /e2e/instances/{chute_id}` returns `e2e_pubkey` with **no quote** (`api/e2e/router.py:144-151`); the key is a miner-supplied DB field (`api/instance/router.py:1416`).

**Result:** a developer copying the sample, or anyone using discover→encrypt, encrypts to whatever key the control plane serves. A malicious/compromised control plane returns its own key and reads all prompts — TDX bypassed.

**Repro:** `GET /e2e/instances/{chute_id}` → note `e2e_pubkey`; nothing ties it to a quote until you separately call `/evidence?nonce=` and check the binding.

**Ask:** fold the `/evidence` fetch + `report_data` verification into the E2E SDK so verify-then-encrypt is the default; fix the sample to verify before encapsulating, bound to the specific `instance_id`+`e2e_pubkey`.

---

## Issue 2 (F1) — Served model is not bound to the TEE attestation; substitution checks disabled on the TEE path

**Repo:** `chutes-api` + `chutes` · **Severity:** High

A verified `-TEE` quote proves genuine TDX+GPU hardware running a Chutes VM image, but nothing binds *which model* runs:

- All published configs share one MRTD; MRTD/RTMR0/1/2 are identical across different models (repro: `verify/verify_chutes.py` check [6]). `model_name`/`revision` are never extended into an RTMR nor placed in `report_data`.
- Weights are pulled at container start (`chutes/chute/template/vllm.py:335-337`), vLLM launched `--model …` (`vllm.py:466-471`); none of this is measured.
- `verify_expected_command` (compares running `--model`/`--revision` to the declared chute) is only invoked from the GraVal path `_validate_graval_launch_config_instance` (`api/instance/router.py:1719`), **not** from `_validate_tee_launch_config_instance` (`:1728`).
- The weight-digest monitor excludes TEE: `LaunchConfig.env_type != "tee"  # Exclude TEE` (`watchtower.py:91`).

**Result:** a compromised miner can serve different weights / a patched container and still pass `/servers/tee/measurements` verification.

**Ask:** extend `SHA256(image_digest‖model‖revision)` into RTMR3 and publish model-keyed expected values, or re-enable the command check + weight-digest monitor for TEE.

---

## Issue 3 (F2) — Golden MRTD/RTMR values are not independently reproducible

**Repo:** `chutes-api` · **Severity:** High

`docs/tee-verification.md:5` claims "verify without trusting us," but the meaning of the measured image rests on Chutes' assertion:

- No TDX guest-VM image source or build pipeline in any repo; the image is an external prebuilt artifact (`docs/specs/server-maintenance.md:103`).
- Golden values are hand-injected ConfigMap constants — the shipped chart has only `PLACEHOLDER_*` (`charts/templates/tee-measurements-cm.yaml:18-30`), loaded at `api/config/__init__.py:334-413`.
- The client guide never instructs callers to compare MRTD/RTMR0-2 to the golden set.
- On-chain commitments cover usage only (`chutes-miner/.../audit_exporter.py:186-213`); validator `set_commitment` is commented out (`chutes-api/audit_exporter.py:135-155`).

**Ask:** publish the guest-image source + a reproducible build that recomputes MRTD/RTMR0-2 (à la `dstack-mr`), and anchor the accepted measurement set with version history on-chain or in a transparency log.

---

## Issue 4 (F4) — GPU attestation has no offline / self-contained verdict

**Repo:** `chutes-api` · **Severity:** Low–Medium

`/instances/{id}/evidence` returns raw per-GPU `{certificate, evidence, arch}`, not pre-verified NRAS tokens. Genuineness / CC-mode / VBIOS+driver RIM matching come only from a network call to `nras.attestation.nvidia.com` (`nv-attest/chutes_nvattest/verifier.py:6-13`, `Environment.REMOTE`). An offline client can only check the cert chain + that the evidence embeds `SHA256(nonce‖e2e_pubkey)`.

**Ask:** support NVIDIA's `LOCAL` GPU verifier (bundled RIM/golden measurements) so CC-mode + measurement matching are client-verifiable against the already-exposed evidence.

---

## Issue 5 (F5) — Rootfs LUKS key is a single static fleet-wide secret

**Repo:** `chutes-api` · **Severity:** Medium

Boot attestation returns `get_luks_passphrase()` = `settings.luks_passphrase`, a single static `LUKS_PASSPHRASE` env var identical for every node (`api/server/util.py:364-377`, `api/config/__init__.py:415`, returned at `api/server/router.py:127`). Release is measurement-gated, but the key is not per-node, not TD-sealed, and not anchored.

**Ask:** derive/seal the rootfs key per-TD (sealed to measurements) instead of distributing one shared secret. (Per-volume cache passphrases ≥v1.3.0 already do this — `api/server/util.py:535-577`.)
