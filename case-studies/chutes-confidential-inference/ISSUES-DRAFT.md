# Chutes — file-able issues (devproofness framing)

Draft GitHub issues for `chutesai/chutes-api` and `chutesai/chutes`. Framed as **verifiability gaps**, not
exploits. Each is reproducible against the live API with only an API key. Citations are at the cloned HEADs
(`chutes-api 77b6f355`, `chutes 08d79872`, `chutes-miner 7afea4b1`) and `chutesai/sek8s`. Priority order;
the first two are the ones to lead with.

---

## Issue 1 (highest) — Default OpenAI path handles prompts in plaintext at the control plane

**Repo:** `chutes-api` · **Type:** claim-vs-reality / by-design

The standard `llm.chutes.ai` OpenAI-compatible path processes the prompt in plaintext at the control plane
before forwarding it: `await request.json()`, `payload["model"]` alias rewrite (`invocation/router.py:902-930`),
`payload["messages"]` iteration (`:933`), and `get_prompt_prefix_hashes(request_body)` for prefix-cache
routing (`:605`, `invocation/util.py:314-322`). "Not even we can see your data" therefore holds only on the
opt-in `/e2e/invoke` path (Issue 2), not the path most users hit.

**Ask:** make verified-E2E the default route, or scope the "we can't see your data" claim to the E2E path in
the docs and UI.

---

## Issue 2 (highest) — Chute code & model are not bound to the attestation; client can't verify which model, operator can read plaintext

**Repo:** `chutes-api` + `chutes` · **Severity:** High

A verified `-TEE` quote proves genuine TDX+GPU running a Chutes base VM image, but nothing binds *which model*
or *which application code* runs:

- All published configs share one MRTD; MRTD/RTMR0–2 are identical across different models (repro:
  `verify/verify_chutes.py` check [6]). `model_name`/`revision` are never extended into an RTMR nor placed in
  `report_data`. RTMR3 tracks only the fixed base-VM files.
- Weights are pulled at container start (`chutes/chute/template/vllm.py:335-337`), vLLM launched `--model …`
  (`vllm.py:466-471`); the served label is `--served-model-name {self.name}` (operator-set), decoupled from
  the actual weights.
- The two checks that could catch a swap are disabled on the TEE path: `verify_expected_command` is only
  called from the GraVal validator (`instance/router.py:1719` vs TEE at `:1728`), and the weight-digest
  monitor excludes TEE (`watchtower.py:91`, `env_type != "tee"  # Exclude TEE`).
- The decrypted prompt is handed to operator-authored `serve.py` (`chutes/entrypoint/run.py:1304-1314`), which
  is in no measured register — so even a perfectly verified E2E client cannot confirm the in-enclave code does
  not log/exfiltrate plaintext.

**Result:** a client cannot independently verify the served model, and a chute operator can re-point the same
named, `verified=True` endpoint at arbitrary weights or read plaintext, undetectably. (A malicious *miner*
cannot — the measured OPA+cosign admission controller + TEE-gated LUKS release contain the host.) Demonstrated
live in `OPERATOR-EXFIL-POC.md`.

**Ask:** extend `SHA256(image_digest‖model‖revision‖serve.py)` into RTMR3 and publish model-keyed expected
values; disclose the registered chute `code` (currently `code: null` even on public `-TEE` chutes); for
confidential chutes, pin egress off under a measured NetNanny.

---

## Issue 3 (High) — `test_e2e_client.py` encrypts to a discovered key without verifying attestation

**Repo:** `chutes-api` · **Severity:** High · **Type:** example contradicts the security model

`docs/tee-verification.md:409-411` warns that an unverified `e2e_pubkey` is a MITM vector, but the only
runnable client example skips verification:

- `scripts/test_e2e_client.py:120-128` calls `discover_instances()` then `build_e2e_blob(instance["e2e_pubkey"], …)`
  and ML-KEM-encapsulates to it — no `/instances/{id}/evidence` call, no DCAP check, no
  `report_data[0:32] == SHA256(nonce‖e2e_pubkey)` check.
- `GET /e2e/instances/{chute_id}` returns `e2e_pubkey` with **no quote** (`e2e/router.py:144-151`); the key is
  a miner-supplied DB field (`instance/router.py:1416`).
- The SDK ships no consumer-side verifier (only the instance-side producer `entrypoint/verify.py`).

**Result:** anyone using discover→encrypt (or the sample) encrypts to whatever key the control plane serves; a
malicious/compromised control plane returns its own key and reads all prompts — TDX bypassed.

**Ask:** fold the `/evidence` fetch + `report_data` verification into the E2E SDK so verify-then-encrypt is the
default, bound to the specific `instance_id`+`e2e_pubkey`; fix the sample.

---

## Issue 4 (provider) — Tenant images are built & signed server-side; tenant holds no key and no digest

**Repo:** `chutes-api` · **Severity:** High (provider/rental surface)

`forge` builds the tenant image and signs it with Chutes' key (`api/image/forge.py:644-676`,
`cosign sign --key {settings.cosign_key}`); the tenant signs nothing and cannot compute "their" digest. The
admission controller verifies against the baked-in `cosign.pub`, but the image identity is in no
verifier-readable measured register (RTMR3 = 0 in production). End-users cannot distinguish "the tenant's
audited image ran" from "a Chutes-modified image ran."

**Ask:** let tenants sign their own image (their key in the admission policy, or a tenant-namespaced keyless
identity), pin the tenant image digest into RTMR3, and publish the per-deployment digest.

---

## Issue 5 (lower) — Transparency & offline-verifiability quick wins

**Repo:** `chutes-api` + `sek8s` · **Severity:** Low–Medium

Cheap, high-value verifiability improvements, none of which is an exploit:

- **Publish `cosign.pub`** (currently baked into the LUKS rootfs). Chute images are cosign-signed with tlog
  upload on by default, so signatures should already be in the public Rekor log — a published key lets anyone
  enumerate Chutes' signing history. (`sek8s/.../forge` cosign config.)
- **Publish a reproducible-build demonstration** for `tdx-guest.qcow2`: the builder + `tdx-measure` recompute
  scripts are public in `sek8s`, but a bit-for-bit rebuild is not yet shown. (Converts "claims reproducible" →
  "verified reproducible.")
- **Offer NVIDIA's `LOCAL` GPU verifier** so CC-mode + RIM matching are client-checkable offline against the
  already-exposed per-GPU evidence, rather than only via a network call to NVIDIA NRAS.
- **Per-TD sealed rootfs keys** instead of the single fleet-wide static `LUKS_PASSPHRASE`
  (`api/server/util.py:364-377`); the per-volume cache passphrases (≥v1.3.0, `:535-577`) already do this.
- **Document or grant audit quota for the Jobs path** (`@chute.job`, SSH-in-TEE, quota-0): its measurement
  model is currently untestable.
