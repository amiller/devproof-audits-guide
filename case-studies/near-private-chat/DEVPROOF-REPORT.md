# NEAR AI Private Chat - Audit Analysis

**Audited:** 2026-01-09/10
**Version:** v0.1.10
**Core Question:** Can we verify the claim that conversation data does not leak?

## Executive Summary

| Component | Verifiable? | Notes |
|-----------|-------------|-------|
| TLS termination in TEE | ✅ Yes | Cert bound to TDX quote via report_data |
| chat-api code | ✅ Yes | Compose hash in attestation |
| chat-api → cloud-api routing | ✅ Yes | OPENAI_BASE_URL hardcoded in compose |
| cloud-api → vLLM routing | ❌ No | MODEL_DISCOVERY_SERVER_URL is runtime config, NO reference value verification |
| Database contents | ✅ Metadata only | Chat messages NOT stored - only conversation IDs |
| Upgrade protection (AppAuth) | ❌ Unverifiable | Contracts on Base are not source-verified |
| Audit scope | ⚠️ 56 versions | 56 compose hashes authorized, only current analyzed |

---

## Architecture

```
                                    INTERNET
                                        │
                                        ▼
                              private.near.ai
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  dstack-ingress CVM                                                             │
│  App ID: 000b2d32de3ed13d7e15b735997e7580ed6dea69                               │
│                                                                                 │
│  - Let's Encrypt TLS termination                                                │
│  - TLS cert bound to TDX quote (report_data = SHA256(sha256sum.txt))            │
│  - Attestation: /evidences/                                                     │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
                      Tailscale VPC (encrypted mesh)
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           ▼                            ▼                            ▼
┌────────────────────────┐   ┌────────────────────────┐   ┌────────────────────────┐
│  chat-api CVM          │   │  chat-api CVM          │   │  cloud-api CVM         │
│  App: f723e96ab1177... │   │  (replica)             │   │  App: f550fdfb4eb8a... │
│                        │   │                        │   │                        │
│  OPENAI_BASE_URL=      │   │  OPENAI_BASE_URL=      │   │  MODEL_DISCOVERY_      │
│  https://cloud-api...  │   │  https://cloud-api...  │   │  SERVER_URL (runtime)  │
│  (HARDCODED)           │   │  (HARDCODED)           │   │  ↓                     │
│                        │   │                        │   │  NO VERIFICATION of    │
│  Database: metadata    │   │                        │   │  backend attestation  │
│  only (no messages)    │   │                        │   │  (trust operator)        │
└────────────────────────┘   └────────────────────────┘   └────────────────────────┘
                                                                    │
                                                                    ▼
                                                         ┌──────────────────┐
                                                         │  vLLM backends   │
                                                         │  (UNVERIFIED    │
                                                         │   trust operator)      │
                                                         └──────────────────┘
```

---

## Deployment Info

| Service | App ID | Compose Hash |
|---------|--------|--------------|
| dstack-ingress | `000b2d32de3ed13d7e15b735997e7580ed6dea69` | `2df8a9cc20f5bc20b447b4bd8dcc77ae07e17e6a109b33339e7019f36c0a7b60` |
| chat-api | `f723e96ab11772f0166e5e4749e49a2113f63b0c` | `4555c4e70fc2b380ff8b99e8b1af329830b0cd8cd8ae39e1c9b1ebcb38317267` |
| cloud-api | `f550fdfb4eb8ad787c1bcd423f091cbb4a4431ae` | `2e480d3ec16082dd37f9622e5359c1179069428250638e9d749b051177a8ed80` |

---

## Data Flow Analysis

### 1. TLS Termination (VERIFIED ✅)

TLS cert is cryptographically bound to TEE attestation.

**Verification:**
```bash
# Hash of evidence files
curl -s https://private.near.ai/evidences/sha256sum.txt | sha256sum | cut -d' ' -f1
# ff99081b96323ee7a86eec6d9988073235a39e3571d6ff24cfa739a07e8080d1

# report_data in TDX quote
wget -q -O - https://private.near.ai/evidences/quote.json | python3 -c "import sys,json; print(json.load(sys.stdin)['report_data'][:64])"
# ff99081b96323ee7a86eec6d9988073235a39e3571d6ff24cfa739a07e8080d1

# MATCH - cert is bound to TEE
```

### 2. chat-api → cloud-api Routing (VERIFIED ✅)

`OPENAI_BASE_URL=https://cloud-api.near.ai/v1` is hardcoded in compose, NOT in `allowed_envs`.

```bash
# Verify hardcoded
curl -s https://private.near.ai/v1/attestation/report | \
  jq -r '.chat_api_gateway_attestation.info.tcb_info.app_compose' | \
  jq -r '.docker_compose_file' | grep OPENAI_BASE_URL
# OPENAI_BASE_URL=https://cloud-api.near.ai/v1

# Verify NOT runtime-configurable
curl -s https://private.near.ai/v1/attestation/report | \
  jq -r '.chat_api_gateway_attestation.info.tcb_info.app_compose' | \
  jq '.allowed_envs' | grep -i openai
# (no output)
```

### 3. cloud-api → vLLM Routing (NOT VERIFIED ❌)

`MODEL_DISCOVERY_SERVER_URL` IS in cloud-api's `allowed_envs` - operator can set at runtime.

**The code does NOT verify attestation against reference values:**

```rust
// cloud-api/crates/inference_providers/src/vllm/mod.rs:144-208
async fn get_attestation_report(...) -> Result<...> {
    // Just fetches /v1/attestation/report from backend
    // Parses JSON response
    // Returns report - NO VERIFICATION of app_id, compose_hash, or TDX signature
}

// cloud-api/crates/services/src/inference_provider_pool/mod.rs:248
has_valid_attestation = true;  // Just means HTTP request succeeded!
```

**What "attestation verified" actually means:**
- ✅ Backend responded to `/v1/attestation/report` endpoint
- ❌ Does NOT verify app_id matches expected value
- ❌ Does NOT verify compose_hash matches expected value
- ❌ Does NOT verify TDX quote signature
- ❌ No reference values are checked at all

**Trust implications:**
- Operator controls which backends receive inference requests
- Any server that returns JSON from `/v1/attestation/report` is accepted
- This is effectively **no verification** - just "does endpoint exist"

#### Detailed Code Analysis: MODEL_DISCOVERY_SERVER_URL

When cloud-api needs to route inference requests to vLLM backends, it relies on a runtime-configurable environment variable `MODEL_DISCOVERY_SERVER_URL`. This URL points to a discovery service that returns a mapping of IP addresses to model names. The cloud-api then connects to these backends and forwards user conversations.

**1. Configuration Loading**

The discovery URL is loaded from environment variables at startup:

[`crates/config/src/types.rs:135-136`](https://github.com/nearai/cloud-api/blob/80e73e25/crates/config/src/types.rs#L135-L136)
```rust
discovery_server_url: env::var("MODEL_DISCOVERY_SERVER_URL")
    .map_err(|_| "MODEL_DISCOVERY_SERVER_URL not set")?,
```

**2. Discovery Fetch**

The inference provider pool fetches available backends from this URL:

[`crates/services/src/inference_provider_pool/mod.rs:166-194`](https://github.com/nearai/cloud-api/blob/80e73e25/crates/services/src/inference_provider_pool/mod.rs#L166-L194)

This performs a simple HTTP GET and parses the JSON response into IP:PORT → model mappings. There is no authentication or verification of the discovery server itself.

**3. Provider Creation**

For each discovered backend, the code creates a VLlmProvider and attempts to fetch an attestation report:

[`crates/services/src/inference_provider_pool/mod.rs:427-448`](https://github.com/nearai/cloud-api/blob/80e73e25/crates/services/src/inference_provider_pool/mod.rs#L427-L448)

**4. Attestation "Validation"**

The attestation check occurs in `fetch_signing_public_keys_for_both_algorithms`:

[`crates/services/src/inference_provider_pool/mod.rs:240-254`](https://github.com/nearai/cloud-api/blob/80e73e25/crates/services/src/inference_provider_pool/mod.rs#L240-L254)
```rust
if let Some(attestation_report) = Self::fetch_attestation_report_with_retry_for_algo(...).await {
    has_valid_attestation = true;  // Set true if HTTP request succeeded
    if let Some(signing_public_key) = attestation_report.get("signing_public_key")...
```

The variable `has_valid_attestation` is set to `true` simply because the HTTP request returned a parseable response—not because any cryptographic verification occurred.

**5. The Underlying Fetch**

The VLlmProvider's `get_attestation_report` method shows what actually happens:

[`crates/inference_providers/src/vllm/mod.rs:144-208`](https://github.com/nearai/cloud-api/blob/80e73e25/crates/inference_providers/src/vllm/mod.rs#L144-L208)

This function constructs a URL, makes an HTTP GET request, parses the JSON response, and returns it. There is no verification of:
- `app_id` against expected values
- `compose_hash` against a whitelist
- TDX quote cryptographic signature
- Any reference values whatsoever

**Security Implication**

Since `MODEL_DISCOVERY_SERVER_URL` is in cloud-api's `allowed_envs` (operator-configurable at runtime), and the code performs no verification of backend attestations against reference values, the operator has full discretion over which servers receive user conversations. Any server that returns valid-looking JSON from `/v1/attestation/report` will be accepted into the provider pool.

**Recommended Improvement**

cloud-api should verify each backend's TDX attestation report against on-chain reference values (app_id, compose_hash) before adding it to the provider pool, using cryptographic signature verification rather than trusting that an HTTP endpoint exists.

### 4. Database Storage (VERIFIED ✅ - Metadata Only)

The database stores **only conversation metadata**, NOT message content.

```sql
-- From chat-api/crates/database/src/migrations/sql/V3__add_conversations.sql
CREATE TABLE conversations (
    id VARCHAR(255) PRIMARY KEY,  -- OpenAI conversation ID
    user_id UUID NOT NULL REFERENCES users(id),
    title TEXT,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
);
```

**What's stored:**
- User accounts (email, name, avatar)
- OAuth tokens
- Session data
- Conversation IDs and timestamps

**What's NOT stored:**
- Message content
- Chat history
- Prompts or responses

---

## Upgrade Protection (AppAuth) - UNVERIFIABLE ❌

dstack uses smart contracts to control which compose hashes can boot. This prevents operators from arbitrarily changing code.

**How it should work:**
```
DstackKms.sol (on EVM chain)
├── registeredApps[appId] → is app registered?
├── allowedOsImages[hash] → is OS image allowed?
└── delegates to → DstackApp.sol (per-app)
                   └── allowedComposeHashes[hash] → can this code run?
```

**Problem:** The contracts for NEAR AI's app IDs are deployed on Base but **not source-verified**.

| App ID | Contract Status |
|--------|-----------------|
| `000b2d32de3ed13d7e15b735997e7580ed6dea69` | Unverified on Basescan |
| `f723e96ab11772f0166e5e4749e49a2113f63b0c` | Unverified on Basescan |
| `f550fdfb4eb8ad787c1bcd423f091cbb4a4431ae` | Unverified on Basescan |

**What we cannot verify:**
- Who owns the contracts (can add new compose hashes)
- What compose hashes are currently allowed
- Whether upgrades are disabled
- Whether the logic matches the reference dstack implementation

**Impact:** Without verified contracts, we cannot verify that upgrade protection exists. The operator could theoretically deploy new code.

**Recommendation:** Request NEAR team verify contract source on Basescan, or provide deployed bytecode for comparison with reference implementation at `dstack/kms/auth-eth/contracts/`.

---

## Authorized Compose Hashes - SCOPE CONCERN ⚠️

Querying `ComposeHashAdded` events on Base reveals **56 total authorized compose hashes** across the three components. None have been removed.

| Contract | Authorized Hashes | Current Hash |
|----------|-------------------|--------------|
| dstack-ingress | 3 | `0x2df8a9cc...` (most recent) |
| chat-api | 16 | `0x4555c4e7...` (most recent) |
| cloud-api | 37 | `0x2e480d3e...` (most recent) |

**Audit implications:**
- Any of these 56 compose hashes can boot and receive keys from dstack KMS
- Older versions may have different security properties (e.g., earlier versions might not have hardcoded OPENAI_BASE_URL)
- The operator could switch to any previously-authorized version at any time
- A comprehensive audit would need to verify all 56 versions, not just the current one

**Query script:** `01-attestation-and-reference-values/query-compose-hashes.py`

**Full list of active compose hashes:**

<details>
<summary>dstack-ingress (3 hashes)</summary>

1. `0x7809c5309ddd471022f68c381c5052fcece13f89cf8fc917547dc7721ed0e2ce`
2. `0x54dd7cab9c24a3f54598965f53f5673fc09c4e7060cb94db50083b20b87a652f`
3. `0x2df8a9cc20f5bc20b447b4bd8dcc77ae07e17e6a109b33339e7019f36c0a7b60` ← current
</details>

<details>
<summary>chat-api (16 hashes)</summary>

1. `0x073b1124d0e6be63c8a73e394210956e89ff68b0d999b1dde5940ea5f7112ca4`
2. `0xe6623320adf1b62e779fe04b715ff5b45304f12029d379977e3db52009c07ea7`
3. `0xd58ecebaa5f0c44556df3469b4251ca254201446a11484e957144f8c79b7c542`
4. `0x56befcad1c77523840f4a977b9dc27051241dcd0bb77d90fffbb50ec56169e6c`
5. `0x63921b68ea69b6947d7720aa07b58797c6117a4f1d7d9f8ecf3dd8dea132901e`
6. `0xfa5e3ed11dac365fdced36c884943033a3581b57eef68806d119c1cfaf933faf`
7. `0xa16a0f70378142f12eb2d4ce72d4ce5c8603187f6f93b429921fd8c2931f401d`
8. `0xf5b95e79e4733044a3d941bde8a380ee1df2dfba00f60da68690e61efd4e904e`
9. `0x2547b46a02a2d36aec714fd64677538b8a0550ccddd280d7af24de261de7366f`
10. `0x271bd9f0a19876cbbb69605829e9b8e0a86a71bf52e6c63c8bfcdbafd7335888`
11. `0xb5b75614ba4b8f5622b9827a06cf143dcaf58937980b2acd217531f8ba6a55c2`
12. `0xe650272ac54b4943767314f455bee32c4b018c2aaeb57d6251dacf4d6acb1c8c`
13. `0x481c43bb22b3e0198c4caea19d97187bd212e27c836f4445c9ab1817c8d858b3`
14. `0x477faa093d4d1ecc4d0cd10d16b3b32d4050e3eb1d855e7dd015132aee12b381`
15. `0xb6b711e560498a49c938eb2463339fa86d162d5b64e8ae954a6f7a42c37be259`
16. `0x4555c4e70fc2b380ff8b99e8b1af329830b0cd8cd8ae39e1c9b1ebcb38317267` ← current
</details>

<details>
<summary>cloud-api (37 hashes)</summary>

1. `0x65f9a647c48bbb0ee0c0f128e6e43a575347ca049f7a10be5c75d6469945a039`
2. `0x572d0a16a551fb9a1d51d726ba53e313ff688407adae2cef032ac0ff81e6ff9f`
3. `0x6be966b710d5da2dc1e3431cb5d1c8cdf08c0631182e6659709a99823bd38b8d`
4. `0x922f0793fd39abd09ebcc3edd1a007a50938cc6a406bc9982e96ad22aa9ab82d`
5. `0x9ed1d3a128608d336863cd5554380825c366d872fe2effa654a7110e7fbe56ad`
6. `0x186a48b4f9ad5c0e88a34cd1c76fb7bdb2221b757fbe8ed587d4b3f5f6332d78`
7. `0x317bb3c816f04443e3b5846aab38366cd0a6b3d453aa65e200cc7c3c47457a0f`
8. `0x5cd945cf5309856f372841bf5a55e586edca3d622bafd3477e920fa8b81e6388`
9. `0x37a5ff70953be8abf063d5f4ec781679db0dea001f7f0f57ad0c9b1bb990ed41`
10. `0x720d9893d6a6bb04a5401eab7e4100c3487160533c1d797302711abef5af2e61`
11. `0xee8121a50f04a88c24c2323b489ced3ee6005bd57176df04ab879f44c3fd455b`
12. `0xc7af89c10453f82618f0d602a7665dec3461c4bf795e52dcb9fd752316c51119`
13. `0x0a6d2e518c60302f3071e622f6eb601540c7c459c26c43416ef507263636f9ab`
14. `0x1b48c35fe740e43ddbdc43e515ff62cb63d4e409489f3cbbe986bf54bab26025`
15. `0x5a4dd6aa3c0b264d98c90212c4d6c652fe457efcf5f55f899cc506bbcf4887f4`
16. `0x2f9e65679cabd34aec917bf4586fec20ec8e9b3b4ffefd4bddc3011a218af4a6`
17. `0xde3aecc9289d14612928328f365bd3c6cf0def5aafcbed70185ab5f20af1bbe9`
18. `0x65f5896a3b0374073cac639de716871a2211f439e2d59a02d6163caf0de6d642`
19. `0xfb0f2aadba408ee2bad78b8f7c1d103d1407fb3475ab7a56380d253f6231fafb`
20. `0x656e8626bccf670413c5d38044ea0829dc54e6df063c4fec36b5ba489fdd1b46`
21. `0x083d8b6f8ac410ee860d5b6785cb9a2312f5d56311b0ad25c98742ecfe86c4f6`
22. `0xfe7cae94a910f12372bd1a589fb975523a75b913cfc9ca56fe14a71f05ba1f8d`
23. `0xbd942195f15c4d18f88648d78beda78e518f7a92cb96b3771dbe050d278002ba`
24. `0xd2469acc5e0938c0ad2c42f2691d372c53a75579b2b2c683ac16fc4b443c194e`
25. `0x17089b008f7ae557daf913354e9278736f0e1ccb44efaf82c1fb37cb46f60af4`
26. `0xdb810ac9236f0320b6784fbad4f33187c3db8094f75b948d8e05cbeaa9e9168a`
27. `0x53c2541f3e2569d851c67bf733afe927ebb926987ccef6bd72839f28081cbf9e`
28. `0x19521821029fd65f5f77a24115d73befb137220fde13419a34f3d7dafb53de51`
29. `0xd0f5a56beeccf5f0a21885c56d9499fcf9c061aa15d65fa86c3e1a586f92a15c`
30. `0x09edcd8a73a9dc7b312526675b48dbe36581f0e16edde87bc7c895849257deae`
31. `0xd4dba3581ecdbbbd1aeb325feb9836efd42b3317669e0bff484ca56ce73dedb0`
32. `0xe9d456df575773d76d6f24da83b7f375f370e21c10e3cc6bd7553bdc6fcdd724`
33. `0xdf065ffecebd5d07228da9ecc08108157e27a345f39d82335fcacc58ad7ed309`
34. `0x8535347a8b9f13f395ec06b9789af59dd86f8219ebb732bd88ba551a5c331c29`
35. `0x6b15303703afe1094811892180e8eddc3197f3da18f6f360ec49ed86648a0333`
36. `0xbdc61960fc9410e251cf160839a276b9d09d2f83b6da6a23cff2c61aa6f6d0f6`
37. `0x2e480d3ec16082dd37f9622e5359c1179069428250638e9d749b051177a8ed80` ← current
</details>

---

## Concerns Summary

### Critical Gaps
- **AppAuth contracts unverified** - Cannot confirm upgrade protection exists
- **vLLM backend routing unverified** - MODEL_DISCOVERY_SERVER_URL is runtime config with NO reference value checking
- **56 authorized compose hashes** - Operator can switch to any previous version; older versions may lack current security properties

### Moderate Concerns
- **Datadog agent in TEE** - Has access to TEE environment for telemetry

### Verified Good
- TLS termination bound to TEE attestation
- chat-api → cloud-api routing hardcoded
- No chat message content in database
- All images pinned by digest
- Source code public

---

## Source Code

| Component | Repository |
|-----------|------------|
| chat-api | https://github.com/nearai/chat-api |
| cloud-api | https://github.com/nearai/cloud-api |
| dstack-ingress-vpc | https://github.com/nearai/dstack-ingress-vpc |
| dstack-vpc | https://github.com/nearai/dstack-vpc |
| dstack (reference) | https://github.com/Dstack-TEE/dstack |

---

## Reproduction Guide

See `NEAR-PRIVATE-CHAT-REPRODUCTION.md` for verification commands.
