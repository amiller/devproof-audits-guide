# Confer.to Client Analysis

## Overview

Confer.to implements private AI inference using Trusted Execution Environments (TEEs) with end-to-end encryption via the Noise protocol. This document analyzes the client-side implementation for potential reimplementation.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         BROWSER                                 │
├─────────────────────────────────────────────────────────────────┤
│  WebSocket (wss://)                                             │
│       │                                                         │
│       └── Noise XX Handshake ──► Encrypted Channel              │
│                 │                                               │
│                 └── Attestation JSON in handshake payload       │
│                                                                 │
│  Verification:                                                  │
│    1. Parse attestation from Noise payload                      │
│    2. Verify TDX quote JWT (Intel Trust Authority)              │
│    3. Check Noise pubkey matches quote report_data              │
│    4. Validate RTMR measurements                                │
│    5. Verify manifest signature (Sigstore/Rekor)                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      TEE (TDX/SEV-SNP)                          │
├─────────────────────────────────────────────────────────────────┤
│  confer-proxy (Java)                                            │
│    - Noise XX responder                                         │
│    - Sends attestation in handshake payload                     │
│    - Proxies to vLLM for inference                              │
└─────────────────────────────────────────────────────────────────┘
```

## Protocol Details

### Noise Protocol
- **Pattern**: `Noise_XX_25519_AESGCM_SHA256`
- **Transport**: WebSocket (binary frames)
- **Handshake**:
  ```
  Client (Initiator)              Server (Responder/TEE)
       │                                   │
       │ ──────── e ──────────────────►    │  Client ephemeral
       │                                   │
       │ ◄─────── e, ee, s, es ──────      │  Server ephemeral + static
       │          + attestation JSON       │  + attestation payload
       │                                   │
       │ ──────── s, se ─────────────►     │  Client static
       │                                   │
       └─────── Encrypted Channel ─────────┘
  ```

### Attestation Payload (JSON in Noise handshake)
```json
{
  "platform": "TDX",
  "attestation": "<JWT signed by Intel Trust Authority>",
  "manifest": "<JSON with imageVersion, proxyVersion, tdxMeasurements>",
  "manifestBundle": "<Sigstore bundle with signature + Rekor proof>"
}
```

### Message Framing (after handshake)
- **Protocol**: Protobuf over Noise
- **Max Noise payload**: 65519 bytes
- **Chunking**: Large messages split into `NoiseTransportFrame` chunks

```protobuf
message NoiseTransportFrame {
  optional int64  chunk_id     = 1;
  optional uint32 chunk_index  = 2;
  optional uint32 total_chunks = 3;
  optional bytes  payload      = 4;
}

message WebsocketRequest {
  optional int64  id   = 1;
  optional string verb = 2;
  optional string path = 3;
  optional bytes  body = 4;
}

message WebsocketResponse {
  optional int64 id     = 1;
  optional int32 status = 2;
  optional bytes body   = 3;
}
```

## Client Verification Steps

### 1. TDX Quote Verification
```javascript
// JWT issued by Intel Trust Authority
await jwtVerify(attestation, INTEL_TRUST_AUTHORITY_JWKS, {
  issuer: 'https://portal.trustauthority.intel.com',
  clockTolerance: '1 min'
})
```

Intel JWKS (embedded in client):
```json
{
  "keys": [{
    "alg": "PS384",
    "kty": "RSA",
    "kid": "9612356c8d9127af5730cc86520c4065917a73000d96f6b2fdb0cb4671882356cd034431be584fa83d5f17ad783e2a62",
    "n": "xlb599-KITtjfoat58AblB7ewti9XcOTGOrCQ_19PVWZlUCZqs9zZ5hDqgz38Ly...",
    "e": "AQAB"
  }]
}
```

### 2. Public Key Binding
The Noise handshake public key must match the key embedded in the TDX quote's `report_data` field (first 32 bytes).

### 3. RTMR Measurement Validation
```javascript
// Compare RTMR1 and RTMR2 from quote against manifest
const manifestRtmr1 = Buffer.from(manifest.tdxMeasurements.rtmr1, 'hex')
const manifestRtmr2 = Buffer.from(manifest.tdxMeasurements.rtmr2, 'hex')
const quoteRtmr1 = Buffer.from(claims.tdx_rtmr1, 'hex')
const quoteRtmr2 = Buffer.from(claims.tdx_rtmr2, 'hex')

// Constant-time comparison
constantTimeEquals(manifestRtmr1, quoteRtmr1)
constantTimeEquals(manifestRtmr2, quoteRtmr2)
```

### 4. Sigstore Manifest Verification
```javascript
const verifier = new SigstoreVerifier()
await verifier.loadSigstoreRoot(PRODUCTION_TRUST_ROOT)
await verifier.verifyArtifact(
  'releases@conferlabs.iam.gserviceaccount.com',  // expected identity
  'https://accounts.google.com',                   // OIDC issuer
  manifestBundle,
  manifest
)
```

Embedded Rekor public keys:
- `https://rekor.sigstore.dev`
- `https://log2025-1.rekor.sigstore.dev`

## Key Dependencies for Reimplementation

### JavaScript/TypeScript
- **Noise Protocol**: [noise-protocol](https://www.npmjs.com/package/noise-protocol) or custom implementation
- **JWT Verification**: [jose](https://www.npmjs.com/package/jose)
- **Protobuf**: [protobufjs](https://www.npmjs.com/package/protobufjs)
- **Sigstore**: [@sigstore/bundle](https://www.npmjs.com/package/@sigstore/bundle), custom verifier

### Rust
- **Noise Protocol**: [snow](https://crates.io/crates/snow)
- **JWT**: [jsonwebtoken](https://crates.io/crates/jsonwebtoken)
- **Sigstore**: [sigstore-rs](https://crates.io/crates/sigstore)

## API Endpoints (Inferred)

Based on the `WebsocketRequest` protobuf:
```
verb: "POST", "GET", etc.
path: "/v1/chat/completions" (likely OpenAI-compatible)
body: JSON request body
```

The proxy likely implements an OpenAI-compatible API internally.

## Transparency Log Queries

```bash
# Find all Confer releases
curl -s "https://rekor.sigstore.dev/api/v1/index/retrieve" \
  -H "Content-Type: application/json" \
  -d '{"email": "releases@conferlabs.iam.gserviceaccount.com"}'

# Get entry details
curl -s "https://rekor.sigstore.dev/api/v1/log/entries/<entry-id>"
```

## Current Releases in Rekor

| Date | Entry ID | Manifest Hash |
|------|----------|---------------|
| Jan 3, 2026 | `108e9186e8c5677a6f99705421ddc48cd16e0a7470f068560e534f55dbb40e8ca6e7aa6664210cb9` | `ee406d59...` |
| Dec 22, 2025 | `108e9186e8c5677a8554d075d114e6910d763e23cc3936fa6c7982ebb91d433ad08c761abfd3bc17` | `b3e4db20...` |
| Dec 21, 2025 | `108e9186e8c5677af2d37bf8085156e4337e32b67e5084f72b98a70ca10aacd76f905947a6976208` | `a7a71643...` |
| Dec 21, 2025 | `108e9186e8c5677a77018d9b5252349f0a5d90493eb27bfc5bef2cff55debda834b278eafba8d186` | `873faf93...` |

## Open Source Components

### Server-side (Public)
- [conferlabs/confer-proxy](https://github.com/conferlabs/confer-proxy) - Java proxy
- [conferlabs/confer-image](https://github.com/conferlabs/confer-image) - VM image build

### Client-side (Proprietary)
- Built with Expo/React Native Web
- Custom `@conferlabs` scoped packages (not on npm)
- Attestation verification logic embedded in bundle

## Next Steps for Custom Client

1. **Implement Noise XX initiator** over WebSocket
2. **Parse attestation payload** from handshake
3. **Verify TDX JWT** against Intel Trust Authority JWKS
4. **Extract and compare** Noise pubkey with quote report_data
5. **Validate RTMR measurements** against manifest
6. **Verify Sigstore bundle** against Rekor transparency log
7. **Implement protobuf framing** for messages
8. **Send OpenAI-compatible requests** through encrypted channel

## Discovered Endpoints

```
wss://inference.confer.to/websocket   # Noise WebSocket (TEE connection)
https://api.confer.to                  # REST API (auth/account)
```

## Questions to Investigate

- [x] What is the WebSocket endpoint URL? → `wss://inference.confer.to/websocket`
- [ ] What API format is used? (likely OpenAI-compatible)
- [ ] How does passkey encryption integrate with the Noise session?
- [ ] Are there rate limits or authentication requirements?
- [ ] What headers/auth tokens are needed to connect?
