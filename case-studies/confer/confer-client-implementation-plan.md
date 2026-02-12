# Confer.to Open Source Python Client Implementation Plan

## Goal
Build an open-source Python client that connects to Confer.to's private AI inference service using the same Noise protocol + TDX attestation verification as the official client.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Python Client                                │
├─────────────────────────────────────────────────────────────────┤
│  WebSocket Client (websockets)                                   │
│       │                                                          │
│       └── Noise XX Handshake (dissononce) ──► Encrypted Channel  │
│                 │                                                │
│                 └── Attestation Validation                       │
│                       ├── JWT verification (PyJWT + jwcrypto)    │
│                       ├── TDX claim validation                   │
│                       ├── RTMR measurement check                 │
│                       └── Sigstore bundle verification           │
│                                                                  │
│  Protobuf Messages (protobuf)                                    │
│       └── NoiseTransportFrame, WebsocketRequest/Response         │
└─────────────────────────────────────────────────────────────────┘
```

## Project Structure
```
confer-client/
├── pyproject.toml
├── confer_client/
│   ├── __init__.py
│   ├── client.py           # Main client class
│   ├── noise.py            # Noise XX handshake
│   ├── attestation.py      # TDX attestation validation
│   ├── sigstore.py         # Sigstore bundle verification
│   ├── framing.py          # Frame encode/decode/chunking
│   ├── proto/
│   │   └── noise_transport_pb2.py  # Generated protobuf
│   └── constants.py        # Embedded keys, URLs, measurements
└── tests/
    ├── test_noise.py
    ├── test_attestation.py
    └── test_client.py
```

## Dependencies
- `websockets` - WebSocket client
- `dissononce` - Noise protocol implementation
- `PyJWT` + `cryptography` - JWT verification
- `protobuf` - Message serialization
- `sigstore` - Sigstore verification

## Key Constants to Embed

### Endpoints
```python
TDX_BASE_URL = "wss://inference.confer.to/websocket"
API_BASE_URL = "https://api.confer.to"
```

### Intel Trust Authority JWKS
- Algorithm: PS384
- Key ID: `9612356c8d9127af5730cc86520c4065917a73000d96f6b2fdb0cb4671882356cd034431be584fa83d5f17ad783e2a62`
- Full key in entry.js line 1190

### Valid TDX Measurements
```python
VALID_TDX_MEASUREMENTS = [
    {
        "rtmr1": "225da8c5c388cbe4f3f3b47df36b5a83e615186cd8993bac632a9704dc2974aff3518af391c9d1d481f59796483255e9",
        "rtmr2": "d4e08948700235c2fc9bce1ed5907e8bae49bdc4f3533319365d348533facb66e85472633dc3436becfb00fa09a8eb54"
    },
    {
        "rtmr1": "c5b8e201b95e3e830eee693b7401d5c214e7662bf9874e1bad1d6cf4254b5d6aefb333b368bab99770308400e3e9255b",
        "rtmr2": "f7639dc12eaf5e7ae7a0cfe9d7d6baab4342c12c9f94fbbea5f9b7b60b824b1783112a679a294b36a1e4a529c07b3ca1"
    }
]
```

### Sigstore Identity
```python
SIGSTORE_EMAIL = "releases@conferlabs.iam.gserviceaccount.com"
SIGSTORE_ISSUER = "https://accounts.google.com"
```

### Allowed Firmware MRTD
```python
ALLOWED_MRTD = ["3c939d8afae2ed7cd153f962e5df0636f899f5f4bd8f790d77eb003d8f1e3a956e283e4e5fc1980ccd4bf00a3bb104ce"]
```

## Implementation Steps

### 1. Noise XX Handshake (`noise.py`)
- Pattern: `Noise_XX_25519_AESGCM_SHA256`
- Client initiates with ephemeral key
- Server responds with ephemeral + static + attestation JSON
- Client sends static key to complete handshake
- Extract `remote_static` for pubkey binding verification

### 2. TDX Attestation Validation (`attestation.py`)
1. Parse JSON payload: `{platform, attestation, manifest, manifestBundle}`
2. Verify JWT against Intel Trust Authority JWKS
3. Check `noise_pubkey == tdx_report_data[:32]`
4. Validate TDX claims (debug=false, valid MRTD, SEAM SVN >= 1)
5. Constant-time compare RTMR1/RTMR2 from JWT vs manifest
6. Verify manifest hash matches Sigstore bundle digest
7. Verify Sigstore bundle signature + Rekor inclusion

### 3. Sigstore Verification (`sigstore.py`)
- Extract certificate from bundle
- Verify chain against Sigstore root
- Check identity (email) and issuer
- Verify signature over artifact hash
- Verify Rekor inclusion proof

### 4. Protobuf Messages
Copy from: `confer-proxy/proto/noise_transport.proto`
```protobuf
message NoiseTransportFrame {
  optional int64 chunk_id = 1;
  optional uint32 chunk_index = 2;
  optional uint32 total_chunks = 3;
  optional bytes payload = 4;
}

message WebsocketRequest {
  optional int64 id = 1;
  optional string verb = 2;
  optional string path = 3;
  optional bytes body = 4;
}

message WebsocketResponse {
  optional int64 id = 1;
  optional int32 status = 2;
  optional bytes body = 3;
}
```

### 5. Frame Chunking (`framing.py`)
- Max Noise payload: 65519 bytes
- Split large messages into `NoiseTransportFrame` chunks
- Reassemble incoming chunked frames

### 6. Main Client (`client.py`)
```python
class ConferClient:
    async def connect(self)  # WebSocket + Noise handshake + attestation
    async def chat(self, messages, stream=True)  # Chat completions
    async def ping(self)  # Keepalive (20s interval)
    async def close()
```

API endpoint: `POST /v1/vllm/chat/completions`
Model: `Qwen/Qwen3-235B-A22B-Instruct-2507-tput`

## Key Reference Files
- Protocol analysis: `confer-client-analysis.md`
- Server Noise impl: `confer-proxy/src/main/java/org/moxie/confer/proxy/websocket/NoiseConnectionWebsocket.java`
- Protobuf schema: `confer-proxy/proto/noise_transport.proto`
- Client bundle (reference): `entry.js` (lines 1105-1130 for key code)
- Sigstore bundle example: `bundle.json`

## Verification Checklist
- [ ] Noise XX handshake completes
- [ ] Server public key extracted
- [ ] Attestation JSON parsed
- [ ] JWT signature verified
- [ ] Noise pubkey matches tdx_report_data[:32]
- [ ] RTMR1/RTMR2 match manifest
- [ ] Manifest hash matches bundle digest
- [ ] Sigstore signature verifies
- [ ] Rekor inclusion validates
- [ ] Encrypted messages work
- [ ] Chat completions stream
- [ ] 20-second ping keepalive works

## Console Log Flow (from live testing)
```
initializeSnow()
Snow WASM initialized successfully
Parsed payload keys: Array(4)
Validating TDX attestation...
Manifest: Object
Manifest Bundle: Object
RTMR measurements verified
Manifest hash verified
Using production trust root!
Got manifest verification status: true
TDX attestation validation passed
TDX attestation validation passed. Connected!
Starting ping interval...
```
