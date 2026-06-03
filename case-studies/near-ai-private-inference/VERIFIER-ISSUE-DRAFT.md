# Verifier accepts attestation as "verified" without checking anything against on-chain reference values

**Repo:** `nearai/nearai-cloud-verifier` (filing here rather than `nearai/cloud-api` because the gap is in the verifier side; #224 already tracks the cloud-api side)

## Summary

`verify_attestation()` in `py/model_verifier.py` currently returns success
when the **cryptography in the attestation is internally consistent** —
TDX quote signature, RTMR3 replay, `report_data` binding to
`signing_address`, GPU NRAS verdict. It does **not** check whether the
`compose_hash`, `app_id`, `os_image_hash`, or KMS pubkey it learned from
the attestation correspond to anything NEAR has actually authorized.

The on-chain `DstackKms` / `DstackApp` registries on Base are the
authoritative source for "is this CVM permitted to receive an app key for
this model" — but **nothing in the verifier reads them.** `show_compose()`
prints `compose_hash` and stops; the value is shown to a human and never
compared to a reference.

So today's "verified: True" output is "the cryptography is internally
consistent," not "the keypair belongs to a CVM I should trust." Anyone
who can stand up a fresh TDX TD with a registered `DstackApp` and a
self-chosen `allowedComposeHashes` produces an attestation that the
verifier accepts.

## The full closed chain (what we'd need to check)

For a verifier to genuinely answer "does this `signing_public_key`
belong to NEAR's GLM-5.1-FP8 backend?", it needs to walk:

```
Intel TDX root cert
  → intel_quote signature ✓ (today)
  → MRTD/RTMR3 → compose_hash, app_id, os_image_hash ✓ (today; values extracted)
  → DstackKms(canonical_addr).registeredApps(app_id) == true        ✗ (NOT CHECKED)
  → DstackApp(app_id).allowedComposeHashes(compose_hash) == true    ✗ (NOT CHECKED)
  → DstackKms(canonical_addr).allowedOsImages(os_image_hash) == true ✗ (NOT CHECKED)
  → DstackKms(canonical_addr).kmsInfo().k256Pubkey
       == info.key_provider_info.id                                 ✗ (NOT CHECKED)
  → (NEAR-published manifest) per_model[M].app_id == app_id         ✗ (NOT CHECKED)
  → report_data[0:32] == SHA256(signing_address || tls_fp) ✓ (today)
  → signing_public_key → ed25519_to_x25519 → E2EE recipient
```

The five `✗` rows are independently necessary:

- Without **`registeredApps`** / **`allowedComposeHashes`** / **`allowedOsImages`** checks, any TDX TD running any code under any `app_id` passes — the on-chain authorization is bypassed entirely.
- Without **`kmsInfo.k256Pubkey == info.key_provider_info.id`**, the verifier can't tell whether the booting KMS is the canonical NEAR/Phala KMS or one the operator stood up. (`info.key_provider_info.id` is a P-256 SPKI; the on-chain `kmsInfo.k256Pubkey` is the corresponding key.)
- Without **`per_model[M].app_id`**, the verifier can't tell whether the `app_id` returned in the attestation is the right `app_id` for the model `M` the client asked for. The operator can route to a different (registered, allow-listed) `app_id` and the on-chain checks all still pass — they just pass for the wrong app.

## Why this matters concretely

The operator (anyone with deploy-time access to cloud-api or the model
CVMs) can today substitute the inference backend without the verifier
catching it:

1. Deploy a new TDX TD running custom code with a backdoored
   `compose_hash` `H_b`.
2. Deploy a `DstackApp` whose owner is the operator and whose
   `allowedComposeHashes(H_b)` is true.
3. Call `DstackKms.registerApp(myApp)` (this method is `public`, by
   design — registering an app is not the substitution lever; the
   substitution lever is the *map from model name to app id*, which has
   no anchor today).
4. Update `cloud-api.models.inference_url` (admin endpoint) to point at
   the new CVM.
5. User encrypts to the new CVM's `signing_public_key` thinking it's
   GLM-5.1-FP8. Backdoored code logs prompts, exfils via Datadog
   (whose `DD_API_KEY` is in the outer compose `allowed_envs`).

Today's verifier prints "verified: True" for steps 1–5. With the missing
checks, step (5) would fail at "per_model[M].app_id != attested app_id."

## Proposed fix

Three additions, in this order:

### 1. NEAR publishes a per-model anchor file (one-time, then maintained)

Bare minimum, ~10 lines of JSON in the verifier repo:

```json
{
  "kms_contract_addr": "0x8fa1593fac104c1aa0c59eaa3553f7e3e162d637",
  "models": {
    "zai-org/GLM-5.1-FP8":      {"app_id": "0x2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b"},
    "deepseek-ai/DeepSeek-V3.1": {"app_id": "0x2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b"},
    "openai/gpt-oss-120b":       {"app_id": "0x…"}
  }
}
```

The `kms_contract_addr` is on-chain — it is the contract that emits
`AppRegistered`/`AppDeployedViaFactory` events for every DstackApp that
gates a NEAR AI model CVM. Auditors can verify it by checking
`registeredApps(<known DstackApp>)` returns true. Ideally the per-model
table would be signed at release time by a NEAR-controlled key whose
pubkey is documented separately, so users who clone the verifier can
verify the anchor file's authenticity.

### 2. Add `py/on_chain.py` with thin Base RPC readers

```python
def kms_root_pubkey(rpc, kms_addr) -> bytes: ...
def is_app_registered(rpc, kms_addr, app_id) -> bool: ...
def is_compose_allowed(rpc, app_id, compose_hash) -> bool: ...
def is_os_image_allowed(rpc, kms_addr, os_image_hash) -> bool: ...
```

Either via plain `eth_call` over an HTTP RPC (simple) or via a Helios light
client (trustless beyond Base consensus). Default to plain RPC; document
how to swap in Helios.

### 3. Wire `verify_attestation` to fail on any mismatch

Building on #23's `VerificationResult` dataclass: add fields
`compose_allowed`, `app_registered`, `os_image_allowed`,
`kms_root_matches`, `model_app_id_matches`. Each AND-ed into `.valid`.

## Optional follow-up: inner-compose closure

The above closes the *outer* compose chain (`compose-manager + datadog +
certbot`). Inside that, `compose-manager` deploys an inner YAML from
`nearai/cvm-compose-files` containing the actual `vllm-proxy-rs` and
`sglang` image digests — but that inner compose isn't in the on-chain
allow-list. compose-manager's own TDX-attested `actions[]` log
(`compose_manager_attestation` in the response payload, today unread by
the verifier) records what was deployed.

A second NEAR-published anchor (`expected_inner_images.json`) plus a
verifier extension that fetches the YAML at the action-log commit and
compares its image digests would close that leg too. This is more
involved and can follow the outer-chain PRs.

## Refs

- Existing scaffolding: PR #22 (offline tests), PR #23 (`VerificationResult` +
  model-name match enforcement) — both touch `verify_attestation` and provide
  the structural hooks the on-chain checks should plug into.
- Cloud-api side counterpart: [`nearai/cloud-api#224`](https://github.com/nearai/cloud-api/issues/224)
  ("cloud-api should only add verified model nodes"), open since 2025-12-03.
- Full design + comparison with `Phala-Network/private-ai-verifier`:
  [VERIFIER-DESIGN.md](https://github.com/amiller/devproof-audits-guide/blob/main/case-studies/near-ai-private-inference/VERIFIER-DESIGN.md)
  (companion to a 2026-05-02 audit revisit of the production system).

## Acceptance criteria for closing

- `verify_attestation` returns `VerificationResult.valid = False` for an
  attestation whose `compose_hash`, `app_id`, `os_image_hash`, or
  `key_provider_info.id` does not match an authority on Base.
- `verify_attestation` returns `False` for an attestation whose `app_id`
  does not match `anchors[model].app_id` for the requested model.
- A test fixture demonstrating the failure mode for each check is part
  of the PR.
