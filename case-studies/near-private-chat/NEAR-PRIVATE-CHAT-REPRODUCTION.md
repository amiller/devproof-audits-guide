# NEAR Private Chat - Analysis Reproduction Guide

Quick reference for re-verifying findings from the 2026-01-09/10 audit.

## Key URLs

```bash
# Attestation endpoints
https://private.near.ai/evidences/                   # dstack-ingress TLS attestation (CRITICAL)
https://private.near.ai/v1/attestation/report        # chat-api + cloud-api attestation
https://cloud-api.near.ai/v1/attestation/report      # cloud-api only

# Source repos
https://github.com/nearai/chat-api                   # Chat backend (Rust)
https://github.com/nearai/cloud-api                  # Inference gateway
https://github.com/nearai/dstack-ingress-vpc         # TLS ingress load balancer
https://github.com/nearai/dstack-vpc                 # dstack-service image source
```

## Verify TLS Attestation Binding (CRITICAL)

```bash
# 1. Fetch evidence files from ingress CVM
curl -s https://private.near.ai/evidences/sha256sum.txt
# 34401581ff612fa1a18f2f60bc23a3483a6b1420e901a09b7ea071de73135044  acme-account.json
# f76f13231a8ee26ddd54e97ad0c80be3af593340007ae3044ac6a34df129d204  cert-private.near.ai.pem

# 2. Hash the sha256sum.txt file
curl -s https://private.near.ai/evidences/sha256sum.txt | sha256sum | cut -d' ' -f1
# ff99081b96323ee7a86eec6d9988073235a39e3571d6ff24cfa739a07e8080d1

# 3. Get report_data from TDX quote
wget -q -O - https://private.near.ai/evidences/quote.json | python3 -c "import sys,json; print(json.load(sys.stdin)['report_data'][:64])"
# ff99081b96323ee7a86eec6d9988073235a39e3571d6ff24cfa739a07e8080d1

# 4. THEY MATCH! TLS cert is cryptographically bound to TEE attestation

# 5. Verify served TLS cert matches evidences cert
curl -s https://private.near.ai/evidences/cert-private.near.ai.pem > /tmp/evidences-cert.pem
echo | openssl s_client -connect private.near.ai:443 -servername private.near.ai 2>/dev/null | openssl x509 -outform PEM > /tmp/live-cert.pem
diff <(openssl x509 -in /tmp/evidences-cert.pem -noout -fingerprint -sha256) \
     <(openssl x509 -in /tmp/live-cert.pem -noout -fingerprint -sha256)
# No output = certs are identical
```

## All App IDs and Compose Hashes

```bash
# dstack-ingress CVM
curl -s https://private.near.ai/evidences/info.json | jq '{app_id, compose_hash}'
# app_id: 000b2d32de3ed13d7e15b735997e7580ed6dea69
# compose_hash: 2df8a9cc20f5bc20b447b4bd8dcc77ae07e17e6a109b33339e7019f36c0a7b60

# chat-api and cloud-api CVMs
curl -s https://private.near.ai/v1/attestation/report | jq '{
  chat_api: .chat_api_gateway_attestation.info.app_id,
  cloud_api: .cloud_api_gateway_attestation.info.app_id
}'
# chat_api: f723e96ab11772f0166e5e4749e49a2113f63b0c
# cloud_api: f550fdfb4eb8ad787c1bcd423f091cbb4a4431ae

# VPC backend nodes
curl -s https://private.near.ai/evidences/vpc.json
# {"vpc_server_app_id":"e78c12915ad57900317b97bd16f59ae13f86f148",
#  "nodes":["chat-api-prod-a5b7gnpf.dstack.internal","chat-api-prod-rv8nqfch.dstack.internal"]}
```

## Verify OPENAI_BASE_URL is Hardcoded

```bash
# Extract docker-compose from attestation
curl -s https://private.near.ai/v1/attestation/report | \
  jq -r '.chat_api_gateway_attestation.info.tcb_info.app_compose' | \
  jq -r '.docker_compose_file' | grep OPENAI_BASE_URL
# OPENAI_BASE_URL=https://cloud-api.near.ai/v1

# Verify NOT in allowed_envs
curl -s https://private.near.ai/v1/attestation/report | \
  jq -r '.chat_api_gateway_attestation.info.tcb_info.app_compose' | \
  jq '.allowed_envs' | grep -i openai
# (no output = not in allowed_envs, can't be changed at runtime)
```

## DNS Verification

```bash
dig +short private.near.ai CNAME    # → gateway.cvm1.near.ai
dig +short private.near.ai A        # → 40.160.1.150
dig +short cloud-api.near.ai CNAME  # → gateway.cvm1.near.ai (same ingress)
```

## Docker Images

```bash
# dstack-ingress
docker pull nearaidev/dstack-ingress-vpc@sha256:49385aafea3044a21fc1c4c6d14008a60e43b5507bd29e9d60dbb73cbfc9f640

# chat-api
docker pull nearaidev/private-chat@sha256:7ecf13e80ba7bf012410ede6a01aead5762f5c7bc84d3df72d7b0d747e3c834e

# dstack-service-mesh
docker pull nearaidev/dstack-service@sha256:856b55c6c3d5b9fec15fa90cbc2006819d04fdc624337899d218d52c2721b3cb

# cloud-api
docker pull nearaidev/cloud-api@sha256:db6effdef6c139e45b680be9f3c40def73847ea08ac93629fcacb6969be113b0
```

## Key Source Code References

### dstack-ingress-vpc (nearai/dstack-ingress-vpc)

**TLS cert to TDX quote binding** - `scripts/generate-evidences.sh`
```bash
# Copies TLS cert to /evidences/
# Computes sha256sum of all evidence files
# Uses hash as report_data in TDX quote request
QUOTED_HASH=$(sha256sum sha256sum.txt | awk '{print $1}')
curl -s --unix-socket /var/run/dstack.sock "http://localhost/GetQuote?report_data=${QUOTED_HASH}" > quote.json
```

**nginx TLS config** - `scripts/entrypoint.sh`
```bash
ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
```

### chat-api (nearai/chat-api)

**OPENAI_BASE_URL handling** - `crates/config/src/lib.rs`
```rust
pub struct OpenAIConfig {
    pub api_key: String,
    pub base_url: Option<String>,  // from OPENAI_BASE_URL env
}
```

**Proxy initialization** - `crates/api/src/main.rs:138-145`
```rust
let mut proxy_service = OpenAIProxy::new(vpc_credentials_service.clone());
if let Some(base_url) = config.openai.base_url.clone() {
    proxy_service = proxy_service.with_base_url(base_url);
}
// Since OPENAI_BASE_URL not in allowed_envs, uses hardcoded compose value
```

### dstack-service-mesh (nearai/dstack-vpc)

**RA-TLS auth extraction** - `service-mesh/src/server.rs`
```rust
// Extracts app_id from client cert (RA-TLS)
let app_id = get_app_id(&cert);  // from ra_tls crate
// Returns x-dstack-app-id header
```

## Architecture Summary

```
User ──TLS──▶ dstack-ingress CVM ──VPC──▶ chat-api CVMs ──▶ cloud-api CVM
              │                           │                  │
              │ Let's Encrypt             │ Attested        │ Attested
              │ ATTESTATION AT            │ via             │ via
              │ /evidences/               │ /v1/attestation │ /v1/attestation
              │                           │                  │
              │ TLS cert bound to         │ OPENAI_BASE_URL │ MODEL_DISCOVERY_
              │ TDX quote report_data     │ hardcoded       │ SERVER_URL runtime
              ▼                           ▼                  ▼
           VERIFIABLE                  VERIFIABLE         PARTIALLY VERIFIABLE
```

**Fully verifiable:**
- TLS termination in TEE (via /evidences/)
- chat-api code and config
- OPENAI_BASE_URL routing

**Not verifiable:**
- MODEL_DISCOVERY_SERVER_URL (runtime config, NO reference value verification)
- AppAuth contracts (unverified on Base)

## MODEL_DISCOVERY_SERVER_URL - NO VERIFICATION

```bash
# Check that MODEL_DISCOVERY_SERVER_URL is in allowed_envs (runtime configurable)
curl -s https://private.near.ai/v1/attestation/report | \
  jq -r '.cloud_api_gateway_attestation.info.tcb_info.app_compose' | \
  jq '.allowed_envs' | grep MODEL_DISCOVERY
# "MODEL_DISCOVERY_SERVER_URL"

# The code does NOT verify attestation against reference values!
# See cloud-api/crates/inference_providers/src/vllm/mod.rs:144-208
# get_attestation_report() just fetches JSON - no app_id/compose_hash/TDX verification
```

## Verify Database Stores Only Metadata

```bash
# Clone and check schema
git clone --depth 1 https://github.com/nearai/chat-api /tmp/chat-api
cat /tmp/chat-api/crates/database/src/migrations/sql/V3__add_conversations.sql
# Shows: conversations table has id, user_id, title, timestamps
# NO message content columns
```

## AppAuth Contract Verification (INCOMPLETE)

The app IDs are Ethereum addresses that should have DstackApp contracts on Base:

```bash
# These contracts exist but are NOT source-verified on Basescan
# dstack-ingress
echo "https://basescan.org/address/0x000b2d32de3ed13d7e15b735997e7580ed6dea69"

# chat-api
echo "https://basescan.org/address/0xf723e96ab11772f0166e5e4749e49a2113f63b0c"

# cloud-api
echo "https://basescan.org/address/0xf550fdfb4eb8ad787c1bcd423f091cbb4a4431ae"

# Reference implementation (what they SHOULD match):
# https://github.com/Dstack-TEE/dstack/tree/master/kms/auth-eth/contracts
```

**To fully verify AppAuth:** Need NEAR team to either:
1. Verify contract source on Basescan, OR
2. Provide deployed bytecode for manual comparison

## Query Authorized Compose Hashes

The contracts emit `ComposeHashAdded` and `ComposeHashRemoved` events. Query them to see all authorized versions:

```bash
# Use the provided script
python3 01-attestation-and-reference-values/query-compose-hashes.py

# Or query manually via RPC
# ComposeHashAdded topic: 0xfecb34306dd9d8b785b54d65489d06afc8822a0893ddacedff40c50a4942d0af
# ComposeHashRemoved topic: 0x755b79bd4b0eeab344d032284a99003b2ddc018b646752ac72d681593a6e8947
```

**As of 2026-01-11:** 56 compose hashes authorized (3 ingress, 16 chat-api, 37 cloud-api), none removed.
