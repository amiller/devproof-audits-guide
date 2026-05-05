# `feat/near-ai-attestation` — what's already there, and the three missing pieces

This is the audit's actionable hand-off into the existing
`hermes-agent` work. **Most of the closed-chain verifier is already
implemented** on `feat/near-ai-attestation` (HEAD `49cd8df1`,
upstream draft PR
[NousResearch/hermes-agent#12201](https://github.com/NousResearch/hermes-agent/pull/12201)).
This doc is the delta between that branch and the closure spec in
`VERIFIER-DESIGN.md`.

## What's on the branch today (do **not** re-pitch)

| Block (per VERIFIER-DESIGN §5) | Where it lives | Status |
|---|---|---|
| **A1 — TDX quote signature** | `hermes_cli/attestation.py::_verify_near_ai_attestation` (line 198) calls vendored `model_verifier.check_tdx_quote` | ✅ |
| **A2 — RTMR3 event-log replay** | inside `check_tdx_quote` (vendored from `nearai-cloud-verifier`) | ✅ |
| **A3 — `report_data` binds (signing_addr, tls_fp, nonce)** | `check_report_data` for gateway + each `model_attestations[i]`; refuses if any binding fails | ✅ |
| **A4 — GPU NRAS** | `check_gpu` per model; refuses on `verdict != PASS` or nonce mismatch | ✅ |
| **A — Domain attestation** (TLS cert ↔ TDX) | `verify_domain_attestation` + `tls_certificate` field round-trip | ✅ |
| **A — `signing_pubkey → signing_address` derivation** | `eth_keys.PublicKey(...).to_canonical_address()` check (line 332) | ✅ |
| **A — compose-hash *consistency*** (in-quote `app_compose` SHA matches `mr_config`) | line 326 | ✅ (note: this is consistency, **not** on-chain) |
| **D — E2EE encrypt/decrypt** | `hermes_cli/e2ee_proxy.py` (crypto primitives) + `hermes_cli/e2ee_transport.py` (httpx transport with `_HDR_*`/`_PREFIX_04`/`_CONDITIONAL_DECRYPT` knobs for venice) | ✅ |
| **D — strict-vs-warn gating** | `hermes_cli/runtime_provider.py` lines 195–253 calls `_verify_attestation`; raises in strict mode (`model.attestation.strict=true`), warns otherwise | ✅ |
| **Per-model attestation cache** | `_MODEL_ATTESTATION_CACHE` in `attestation.py` (TTL bounded) | ✅ |
| **Live integration tests** | `tests/hermes_cli/test_nearai_e2ee.py` — `TestNearAILiveE2EEChat`, `TestVeniceLiveAttestation`, etc. | ✅ |

That covers all of Block A and all of Block D. The audit's three
deltas fit cleanly into the existing structure.

## Delta 1 — Block B (on-chain anchoring)

**Where it slots in:** inside `_verify_near_ai_attestation` after the
existing model-attestation loop completes successfully and before
returning `AttestationReport(valid=True, …)`.

**New module:** `hermes_cli/on_chain.py`. Thin readers backed by an
HTTP RPC URL (`BASE_RPC_URL` env, default `https://mainnet.base.org`).

```python
# hermes_cli/on_chain.py  (new file)

from dataclasses import dataclass
import os, requests

DEFAULT_RPC = "https://mainnet.base.org"

# Function selectors (keccak256 of the signature, first 4 bytes)
_SEL_KMS_INFO              = "0x…"  # kmsInfo() — returns (k256, ca, quote, eventlog)
_SEL_REGISTERED_APPS       = "0xa6c4cce9"  # registeredApps(address)
_SEL_ALLOWED_OS_IMAGE      = "0x…"  # allowedOsImages(bytes32)
_SEL_ALLOWED_COMPOSE_HASH  = "0x2f6622e5"  # allowedComposeHashes(bytes32)


def _eth_call(rpc, to, data):
    r = requests.post(rpc, json={
        "jsonrpc": "2.0", "id": 1, "method": "eth_call",
        "params": [{"to": to, "data": data}, "latest"],
    }, timeout=10)
    r.raise_for_status()
    res = r.json()
    if "error" in res:
        raise RuntimeError(f"eth_call error: {res['error']}")
    return res["result"]


def is_app_registered(rpc, kms_addr: str, app_id: str) -> bool:
    arg = app_id.removeprefix("0x").rjust(64, "0")
    out = _eth_call(rpc, kms_addr, _SEL_REGISTERED_APPS + arg)
    return int(out, 16) != 0


def is_compose_allowed(rpc, app_id: str, compose_hash: str) -> bool:
    arg = compose_hash.removeprefix("0x").rjust(64, "0")
    out = _eth_call(rpc, app_id, _SEL_ALLOWED_COMPOSE_HASH + arg)
    return int(out, 16) != 0


def is_os_image_allowed(rpc, kms_addr: str, os_image: str) -> bool:
    arg = os_image.removeprefix("0x").rjust(64, "0")
    out = _eth_call(rpc, kms_addr, _SEL_ALLOWED_OS_IMAGE + arg)
    return int(out, 16) != 0


def kms_root_pubkey(rpc, kms_addr: str) -> bytes:
    """Returns the raw secp256k1 pubkey (uncompressed, 64 bytes, no 0x04 prefix)
    from DstackKms.kmsInfo().k256Pubkey."""
    out = _eth_call(rpc, kms_addr, _SEL_KMS_INFO)
    # decode the dynamic bytes return; first word = k256_pubkey offset, etc.
    # implementation detail — see DstackKms.sol::kmsInfo()
    raise NotImplementedError("decode kmsInfo struct")
```

**Anchor file** loaded at process start:
`hermes/anchors/nearai_mainnet.json`:

```json
{
  "kms_contract_addr": "0x8fa1593fac104c1aa0c59eaa3553f7e3e162d637",
  "models": {
    "zai-org/GLM-5.1-FP8":      {"app_id": "0x2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b"},
    "deepseek-ai/DeepSeek-V3.1": {"app_id": "0x2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b"}
  }
}
```

The `kms_contract_addr` was identified on-chain via Blockscout's tx
history for the apps' owner EOA (`0x21e6b7ef…`): 99 calls with selector
`0x8618169d` (= `deployAndRegisterApp(address,bool,bool,bytes32,bytes32)`)
against `0x8fa1593fac104c1aa0c59eaa3553f7e3e162d637` identify it as the
KMS factory. `registeredApps(...)` confirms membership for every known
NEAR DstackApp.

**`attestation.py` patch** (~30 lines added to
`_verify_near_ai_attestation`, after the existing model loop completes):

```python
# Block B: on-chain anchoring
from hermes_cli.on_chain import (
    DEFAULT_RPC, is_app_registered, is_compose_allowed,
    is_os_image_allowed, kms_root_pubkey,
)
from hermes_cli.anchors import load_nearai_anchor

anchor = load_nearai_anchor()              # raises if file missing or kms_contract_addr is null
expected = anchor["models"].get(model)
if expected is None:
    return _fail(f"Model {model!r} has no anchored app_id in nearai_mainnet.json")

rpc = config.get("base_rpc_url", DEFAULT_RPC)
kms = anchor["kms_contract_addr"]

for i, m in enumerate(model_atts):
    info = m.get("info", {})
    app_id        = info.get("app_id")
    compose_hash  = info.get("compose_hash")
    os_image_hash = info.get("os_image_hash")
    kpi_id_hex    = json.loads(info.get("key_provider_info", "{}")).get("id", "")

    if app_id.lower() != expected["app_id"].lower():
        return _fail(f"Model #{i+1}: app_id {app_id} != anchored {expected['app_id']} for {model}")
    if not is_app_registered(rpc, kms, app_id):
        return _fail(f"Model #{i+1}: DstackKms.registeredApps[{app_id}] is false")
    if not is_compose_allowed(rpc, app_id, compose_hash):
        return _fail(f"Model #{i+1}: DstackApp({app_id}).allowedComposeHashes[{compose_hash}] is false")
    if not is_os_image_allowed(rpc, kms, os_image_hash):
        return _fail(f"Model #{i+1}: DstackKms.allowedOsImages[{os_image_hash}] is false")
    on_chain_kms_pub = kms_root_pubkey(rpc, kms)
    if kpi_id_hex.lower() != on_chain_kms_pub.hex().lower():
        return _fail("Model #%d: key_provider_info.id != on-chain DstackKms.kmsInfo.k256Pubkey" % (i+1))
```

Strict-vs-warn behaviour is automatic — `_fail` already returns a
report whose `.valid=False` triggers the strict-mode raise in
`runtime_provider.py:207`. **Block B respects the existing
config.strict toggle.**

## Delta 2 — Block C (inner-compose closure)

**Status: shipped on `feat/near-ai-attestation@9e93dfdfd` (2026-05-05).** The
implementation differs from the original sketch below in two ways:

1. **Cached-in-anchor variant** rather than per-request GitHub fetch. The
   anchor pins `(file, commits[], file_sha256s[])` per model directly. The
   request-time check matches `actions[-1].{commit, file_sha256}` against
   the anchor without re-fetching from GitHub. Trade-off: no per-request
   network dependency, refresh discipline moves to anchor-PR review (where
   image-digest validation happens during human review).
2. **MRTD + RTMR3 cross-binding** between the outer model attestation and
   the compose-manager attestation, instead of MRTD-only as originally
   sketched. RTMR3 equality catches the parallel-TD substitution attack
   where the operator stands up a clean second TD with the same outer
   compose to fake the action log.

Plus an unrelated discovery during capture (worth recording here even
though it's not Block C): `model_name == requested model` is now enforced.
Live observation 2026-05-05: requesting `deepseek-ai/DeepSeek-V3.1` returns
`model_name=Qwen/Qwen3.5-122B-A10B`. The cloud-api gateway silently
reroutes one model to another's backend; without this check, the user
encrypts to the wrong TD's signing key for a model they didn't ask for.

The original plan is preserved below for reference.

---

**Where it slots in:** same place, after Block B passes, inside the
model loop.

**Anchor extension:** add `expected_inner_images` per model.

```json
"zai-org/GLM-5.1-FP8": {
  "app_id": "0x2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b",
  "yaml": "GLM-5.1.yaml",
  "expected_inner_images": {
    "vllm-proxy-rs": "sha256:6f3cb72d31f6f7623a4ac17f1caf60c57678e958dd6e77152164c5cc4bac4913",
    "sglang":        "sha256:e1eee3f75e62827dbfa29994a260934c2bc7e5adfb047170576f1676b436b926"
  }
}
```

**New helper module:** `hermes_cli/inner_compose.py`. Reads
`compose_manager_attestation` from the response, fetches the YAML at
the recorded commit from
`https://raw.githubusercontent.com/nearai/cvm-compose-files/<commit>/<file>`,
hashes, parses, compares.

```python
# hermes_cli/inner_compose.py  (new file)

import hashlib, requests, re, json

GITHUB_RAW = "https://raw.githubusercontent.com/nearai/cvm-compose-files"

def find_latest_compose_up(actions, expected_filename):
    for a in reversed(actions):
        if a.get("action") == "compose_up" and a.get("file") == expected_filename:
            return a
    return None

def fetch_yaml(commit, filename):
    url = f"{GITHUB_RAW}/{commit}/{filename}"
    r = requests.get(url, timeout=15)
    r.raise_for_status()
    return r.text

_IMG_RE = re.compile(r"image:\s*([\S]+)")

def parse_image_digests(yaml_text):
    """Extract container image digests, keyed by 'service-name' inferred from image path."""
    out = {}
    for m in _IMG_RE.finditer(yaml_text):
        ref = m.group(1)
        if "@sha256:" in ref:
            name = ref.rsplit("/", 1)[-1].split("@")[0]
            digest = "sha256:" + ref.rsplit("@sha256:", 1)[1]
            out[name] = digest
    return out
```

**`attestation.py` patch** (~25 lines):

```python
# Block C: inner compose closure
cma = m.get("compose_manager_attestation")
if not cma:
    return _fail(f"Model #{i+1}: compose_manager_attestation absent — inner compose unverifiable")

# verify the inner TDX quote (same MRTD as outer); same mechanism as Block A
inner_intel = _sync_run(check_tdx_quote(cma))
if not (inner_intel and inner_intel.get("verified")):
    return _fail(f"Model #{i+1}: compose_manager_attestation TDX quote failed to verify")
if inner_intel.get("mrtd") != m_intel.get("mrtd"):
    return _fail(f"Model #{i+1}: inner MRTD != outer MRTD")

# verify actions_hash matches sha256 of actions list
actions_json = json.dumps(cma["actions"], separators=(",", ": "))  # match server formatting
if hashlib.sha256(actions_json.encode()).hexdigest() != cma["actions_hash"]:
    return _fail(f"Model #{i+1}: compose_manager_attestation actions_hash mismatch")

last_up = find_latest_compose_up(cma["actions"], expected["yaml"])
if not last_up:
    return _fail(f"Model #{i+1}: no compose_up for {expected['yaml']!r} in action log")

yaml_text = fetch_yaml(last_up["commit"], last_up["file"])
if hashlib.sha256(yaml_text.encode()).hexdigest() != last_up["file_sha256"]:
    return _fail(f"Model #{i+1}: yaml sha256 mismatch with action log")

actual = parse_image_digests(yaml_text)
for service, expected_digest in expected.get("expected_inner_images", {}).items():
    if actual.get(service) != expected_digest:
        return _fail(
            f"Model #{i+1}: image digest mismatch for {service}: "
            f"expected {expected_digest}, got {actual.get(service)}"
        )
```

The `actions_hash` recomputation needs to match the server's exact
JSON serialization — compose-manager uses `serde_json::to_string`
which produces compact JSON without trailing whitespace. May require
matching that explicitly with `json.dumps(actions, separators=(",",":"))`
(no space after colon). Verify against a captured bundle.

## Delta 3 — anchored `model → app_id` enforcement

This is the smallest piece — it's a single check inside the existing
model loop, already shown above as the first line of Block B:

```python
if app_id.lower() != expected["app_id"].lower():
    return _fail(f"Model #{i+1}: app_id {app_id} != anchored {expected['app_id']} for {model}")
```

Without the anchor file, the operator can route to a different
registered app and all on-chain checks still pass — they just pass
for the wrong app. This is the only line that closes that.

## Test plan

The branch's test pattern is well-established. Three new test files:

- `tests/hermes_cli/test_on_chain.py` — unit tests with stubbed
  `_eth_call`. Each `is_*_allowed` covered with a true and false
  fixture.
- `tests/hermes_cli/test_inner_compose.py` — fixtures recorded from
  prod (already captured at
  `case-studies/near-ai-private-inference/sources/`); positive case +
  three negative cases (wrong sha, missing service, wrong commit).
- Extend `tests/hermes_cli/test_nearai_e2ee.py::TestNearAILiveAttestation`
  with `test_block_b_on_chain` and `test_block_c_inner_compose` —
  marked `@pytest.mark.integration`, opt-in via `NEAR_API_KEY` +
  `BASE_RPC_URL` env.

## Open questions to flag in the PR description

1. `kms_contract_addr` — not yet published by NEAR. Anchor file ships
   with `null` initially; verifier refuses to operate against
   `near-ai` until the file is filled in. This is intentionally
   fail-closed, matching the existing `strict=true` mode.
2. Vendored verifier path is repo-relative
   (`../hermes-agent/refs/nearai-cloud-verifier/py`). PR-A on
   `nearai/nearai-cloud-verifier` adds an installable package; once
   that lands, the vendoring goes away and Block B becomes upstream
   too.

## What lands in the upstream PR (`#12201`) update

A single commit `feat: on-chain anchoring + inner-compose closure for
near-ai` adding:

- `hermes_cli/on_chain.py`
- `hermes_cli/inner_compose.py`
- `hermes_cli/anchors/__init__.py` + `nearai_mainnet.json`
- patches to `hermes_cli/attestation.py::_verify_near_ai_attestation`
- three test files above
- README update describing the new anchor file and the four-block
  verification chain it now implements end to end

That should be ~400 lines added, ~30 modified, with the anchor file
containing exactly the values currently in production
(`app_id 0x2c0a0c96…`, `vllm-proxy-rs sha256:6f3cb72d…`, etc.).
