# NEAR AI Cloud: Client-Side E2EE Verification

**Audited:** 2026-04-19
**Domain:** cloud-api.near.ai
**Companion to:** `DEVPROOF-REPORT.md` (server-side audit, 2026-03-25)
**Core Question:** What must an API client do to achieve actual end-to-end encryption, and do the official SDKs do it?

---

## What E2EE means here

NEAR AI model CVMs generate a SECP256K1 keypair at boot. The public key appears in the attestation report as `signing_public_key`. The corresponding Ethereum address (`keccak256(pubkey)[12:]`) is embedded in the TDX quote's `report_data[0:32]`. This binding means: if you verify the TDX quote, you know the public key belongs to hardware running specific code.

The encryption scheme is ECIES on SECP256K1:
- Client generates an ephemeral keypair per request
- Encrypts each message: `eph_pubkey(65) || nonce(12) || AES-GCM(HKDF(ECDH(eph_priv, model_pub)))`
- Sends headers: `X-Signing-Algo: ecdsa`, `X-Client-Pub-Key: <hex>`, `X-Model-Pub-Key: <hex>`
- Model CVM decrypts with its private key, encrypts response to client's ephemeral key
- Client decrypts the response

The gateway CVM and NEAR AI's infrastructure see only ciphertext at the application layer. The model private key never leaves the TDX enclave.

**This only works if the client verifies the key before using it.** A key read from JSON without attestation verification is TOFU — the gateway can substitute any key it wants.

---

## The 8-step verification chain

Each step eliminates a class of attack:

| Step | What it proves | Skipped by |
|------|---------------|------------|
| 1. Gateway TDX quote | Real TDX hardware at cloud-api.near.ai | — |
| 2. Gateway report_data | Signing address bound to TLS cert; quote is fresh | — |
| 3. TLS cert match | The TDX enclave answering attestation = the server answering HTTPS | — |
| 4. Model TDX quote | Gateway didn't substitute a fake model attestation | **nearai-cloud-verifier** |
| 5. Model report_data | Model attestation bound to this request nonce | **nearai-cloud-verifier** |
| 6. GPU attestation | Model runs on real NVIDIA H100 in CC mode | **nearai-cloud-verifier**, **private-ai-verifier** (E2EE not implemented) |
| 7. Key → address binding | `signing_public_key` derives to hardware-attested `signing_address` | **nearai-cloud-verifier** |
| 8. Compose hash | Exact container image matches what's in the report | — |

Steps 4–7 are the ones that bind the encryption key to hardware. Skipping any of them means the client cannot trust the key it encrypts to.

### Step details

**Step 2 — Gateway report_data:**
```
report_data[0:32] = SHA256(signing_address_bytes || tls_cert_fingerprint_bytes)
report_data[32:64] = raw nonce bytes
```

**Step 5 — Model report_data:**
```
report_data[0:32] = signing_address (20 bytes, right-padded to 32)
report_data[32:64] = raw nonce bytes
```

**Step 7 — Key → address binding:**
```python
from eth_keys.datatypes import PublicKey
derived = "0x" + PublicKey(bytes.fromhex(signing_public_key)).to_canonical_address().hex()
assert derived.lower() == signing_address.lower()
```

**Step 8 — Compose hash:**
```python
compose_hash = sha256(app_compose.encode()).hexdigest()
assert mr_config.lower().startswith(("01" + compose_hash).lower())
```

---

## What the official SDKs get wrong

### nearai-cloud-verifier (NEAR's own SDK)

`encrypted_chat_verifier.py::fetch_model_public_key` fetches the attestation report and reads `signing_public_key` directly from the JSON response — without running `check_tdx_quote` on the model attestation first. The encryption key is accepted on the gateway's word. A compromised or malicious gateway substitutes any key; the client encrypts to it.

The ECIES implementation in `encrypted_chat_verifier.py` is correct. The trust chain establishing the key is not.

### private-ai-verifier (third-party, Phala Network)

`NearAICloudVerifier` runs the full dstack verification chain — TDX quote, GPU, compose hash, report_data — for both gateway and model attestations. This is the correct approach for the verification side.

But it never reads `signing_public_key` from `model_attestations` and has no E2EE implementation at all. An audit based solely on this SDK establishes that the TEE is real but does nothing to protect prompt confidentiality.

Neither SDK alone is sufficient. The correct implementation combines private-ai-verifier's verification chain with nearai-cloud-verifier's ECIES crypto, using the key only after it has been hardware-verified.

---

## Live findings (April 2026)

### OutOfDate platform TCB

~80% of requests hit platforms with `OutOfDate` TCB status. Advisories: INTEL-SA-01036, -01079, -01099, -01103, -01111. These are known firmware vulnerabilities. The official verifiers accept OutOfDate as valid. The TDX quote itself verifies; the underlying firmware is unpatched.

The `DEVPROOF-REPORT.md` notes GPU attestation as "VERIFIED ✅" from the server architecture perspective. Client-side testing finds a different picture:

### NRAS returning persistent FAIL verdicts

NVIDIA NRAS (`nras.attestation.nvidia.com/v3/attest/gpu`) is returning a boolean `False` verdict — not `"PASS"` — consistently across multiple requests and retry attempts against NEAR AI's model CVMs. This is not a transient network failure; it persists across retries.

A correct client that enforces GPU attestation as mandatory (step 6) cannot complete verification against NEAR AI's fleet in its current state. Official verifiers either skip GPU attestation or treat FAIL as non-fatal, masking this.

Combined with the OutOfDate TCB finding: as of April 2026, NEAR AI's inference fleet fails a strict client-side attestation check on two independent dimensions.

---

## Reference implementation

A correct client-side implementation is available in `hermes-agent` (`feat/near-ai-attestation` branch, `hermes_cli/attestation.py` + `hermes_cli/e2ee_proxy.py`). It runs all 8 steps, treats GPU failure as a hard error, and retries on transient NRAS failures. After successful verification it starts a local HTTP proxy that transparently encrypts outgoing messages and decrypts responses:

```python
report = verify_attestation("near-ai", {"api_key": ..., "base_url": "https://cloud-api.near.ai"}, {"enabled": True})
# report.valid is True only after all 8 steps pass
proxy = E2EEProxy(report.signing_public_key, report.signing_algo, "https://cloud-api.near.ai")
# All chat/completions traffic through proxy.base_url is now E2EE
```

Tests: `tests/hermes_cli/test_nearai_e2ee.py` — 12 unit/integration tests (no live credentials needed), 2 live tests gated on `NEAR_API_KEY`.

---

## Remaining gaps (require NEAR AI to fix)

**Issue #224 — Model backends not verified server-side (open since Dec 2025)**
`cloud-api` fetches attestation from model backends but discards the result. Signing keys are read from unverified backend JSON. A malicious backend can join the pool. Client-side model attestation (step 4) mitigates this for the prompt content — the client verifies what the server doesn't — but most clients aren't doing it.

**OutOfDate platform TCB**
Known firmware vulnerabilities on ~80% of the fleet. See INTEL-SA-01036, -01079, -01099, -01103, -01111.

**NRAS persistent FAIL verdicts**
Model CVMs are failing GPU attestation at NRAS. Root cause unknown; likely a backend registration or certificate issue.

**app_id not verified on-chain**
`app_id` (`2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b`) is a Base L2 contract address but neither the official SDK nor this implementation verifies it against an on-chain contract. Pinning it would close a residual gap where deployment composition could change without on-chain record.

**Sigstore provenance not enforced**
Docker compose references images by sha256 digest. Those digests could be checked against Sigstore for build provenance. The `nearai-cloud-verifier` probes Sigstore HTTP but does not parse or validate provenance entries.
