# Private Inference: Technical Overview

*Source: https://confer.to/blog/2026/01/private-inference/*

## The Core Problem

When you use an AI service, you're handing over your thoughts in plaintext. The operator stores them, trains on them, and–inevitably–will monetize them.

## Confidential Computing Solution

Confer runs inference inside a Trusted Execution Environment (TEE) where the host machine cannot access memory or execution state. Prompts arrive encrypted via Noise Pipes and responses return encrypted, keeping plaintext hidden from operators.

---

## Key Resources

### GitHub Repositories
- **Confer Proxy**: https://github.com/conferlabs/confer-proxy
- **Confer Image**: https://github.com/conferlabs/confer-image

### Transparency Log
- **Sigstore search**: https://search.sigstore.dev/?email=releases%40conferlabs.iam.gserviceaccount.com

### Technical References
- **Noise Protocol**: https://noiseprotocol.org/noise.html
- **dm-verity docs**: https://docs.kernel.org/admin-guide/device-mapper/verity.html

---

## Chain of Trust Analysis

### 1. Build Reproducibility

The image build uses:
- **Nix flakes** (`flake.nix`) to pin all build tools (mkosi, qemu, cryptsetup, etc.)
- **mkosi** with `SourceDateEpoch=0` for reproducible timestamps
- **Fixed seed** (`Seed=a24031c1-fc68-453d-80fa-00ad057a5780`) for deterministic UUIDs
- **Pinned package versions** (e.g., `nvidia-driver-580-open=580.105.08-0ubuntu1`)
- **Fixed machine-id** for reproducibility

Key config from `mkosi.conf`:
```ini
ImageVersion=0.1.3
Seed=a24031c1-fc68-453d-80fa-00ad057a5780
SourceDateEpoch=0
Distribution=ubuntu
Release=noble
```

### 2. dm-verity Filesystem Binding

The root filesystem is cryptographically bound to the attestation via dm-verity:
1. mkosi builds the image and computes a Merkle tree over all bytes
2. The root hash is embedded in the kernel command line
3. The command line is embedded in a Unified Kernel Image (UKI)
4. The UKI is measured into the TEE during boot

From `mkosi.conf`:
```ini
KernelModulesInitrdInclude=dm-verity
                          dm-mod
```

### 3. Proxy Hash Binding

The proxy JAR is verified at boot via `confer-boot` script:
```bash
EXPECTED_HASH=$(get_cmdline_param "proxy-hash")
ACTUAL_HASH="sha256:$(sha256sum "$PROXY_ZIP" | cut -d' ' -f1)"
if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
    error "Hash mismatch!"
fi
```

The proxy hash is appended to the kernel command line at release time.

### 4. Noise Protocol Key Binding

The X25519 public key is embedded in the TEE attestation report_data:
```java
protected byte[] createReportData(byte[] publicKey) {
    byte[] reportData = new byte[64];
    System.arraycopy(publicKey, 0, reportData, 0, publicKey.length);
    return reportData;
}
```

This cryptographically binds the Noise handshake key to the TEE measurement.

### 5. TDX Measurement Computation

The release workflow computes TDX measurements using `tdx-measure`:
```yaml
- name: Compute TDX measurements
  run: |
    tdx-measure tdx_metadata.json --runtime-only --direct-boot=true --json-file measurements.json
```

### 6. Sigstore Signing

Manifests are signed with cosign using Google Cloud Workload Identity:
```yaml
- name: Sign manifest with Sigstore
  run: |
    IDENTITY_TOKEN=$(gcloud auth print-identity-token --audiences=sigstore)
    cosign sign-blob --identity-token="$IDENTITY_TOKEN" --bundle manifest.bundle.json manifest.json
```

### 7. Transparency Log Entries

Found 4 signed releases in Rekor:
```
Entry: 108e9186e8c5677a6f99705421ddc48cd16e0a7470f068560e534f55dbb40e8ca6e7aa6664210cb9
Timestamp: Sat Jan 3 15:38:02 EST 2026
Hash: ee406d59464c8ba9150b53fa503f67a1696968916d19785119cde613192c5431
Signer: releases@conferlabs.iam.gserviceaccount.com (verified via Fulcio certificate)
```

---

## Client Verification Flow

When a client connects:
1. Perform Noise NK handshake (client knows expected server pubkey)
2. Server sends attestation quote containing:
   - TEE measurement (kernel + initrd + cmdline with roothash + proxy-hash)
   - Server's X25519 public key in report_data
3. Client verifies:
   - Quote signature against AMD/Intel root of trust
   - Measurements match a signed manifest from transparency log
   - Public key in report_data matches Noise handshake key
4. Establish encrypted channel with forward secrecy

---

## Reproducibility Verification Steps

### Prerequisites
- Nix >= 2.18 with flakes enabled

### Steps to Reproduce
```bash
# Clone repos
git clone https://github.com/conferlabs/confer-image
git clone https://github.com/conferlabs/confer-proxy

# Enter nix environment
cd confer-image
nix develop

# Build image (generates vmlinuz, initrd, qcow2, cmdline)
make build

# The cmdline file contains the dm-verity roothash
cat confer-image_*.cmdline

# Build proxy
cd ../confer-proxy
mvn package -Pship -DskipTests

# Compute proxy hash
sha256sum target/proxy-*.zip

# Create full cmdline with proxy hash
echo "$(cat ../confer-image/confer-image_*.cmdline) proxy-hash=sha256:<proxy-hash>"

# Compute TDX measurements (requires tdx-measure tool)
# Compare against transparency log entries
```

### Transparency Log Verification
```bash
# Query Rekor for Confer releases
curl -s "https://rekor.sigstore.dev/api/v1/index/retrieve" \
  -H "Content-Type: application/json" \
  -d '{"email": "releases@conferlabs.iam.gserviceaccount.com"}'

# Get entry details
curl -s "https://rekor.sigstore.dev/api/v1/log/entries/<entry-id>" | \
  jq -r '.[] | .body' | base64 -d | jq '.'
```

---

## Sigstore Signature Verification (Completed)

### Rekor Entry Analyzed
```
Entry ID: 108e9186e8c5677a6f99705421ddc48cd16e0a7470f068560e534f55dbb40e8ca6e7aa6664210cb9
Log Index: 789828784
Integrated Time: Sat Jan 3 15:38:02 EST 2026
```

### Certificate Details
```
Signer: releases@conferlabs.iam.gserviceaccount.com
Issuer: sigstore.dev / sigstore-intermediate (Fulcio CA)
Validity: Jan 3 20:38:01 - 20:48:01 UTC 2026 (10 min window)
```

### Signed Manifest Hash
```
Algorithm: SHA-256
Hash: ee406d59464c8ba9150b53fa503f67a1696968916d19785119cde613192c5431
```

### Inclusion Proof
```
Tree Size: 690609803
Root Hash: 48519a22318ad2ce7a0bea19b659231c260abbd488c315e8855640219909e85f
Proof: 29 intermediate Merkle tree nodes
Checkpoint: Signed by rekor.sigstore.dev
```

### What This Proves
- ✓ A manifest with the above hash was signed by the Confer release account
- ✓ The signing certificate was issued by Fulcio (Sigstore's CA)
- ✓ The signing event is permanently logged in Rekor transparency log
- ✓ The entry is cryptographically bound via Merkle inclusion proof

### Remaining Verification
To complete end-to-end verification:
1. Obtain original `manifest.json` (contains TDX measurements)
2. OR reproduce the build and compare hash to `ee406d...5431`

---

## Full Chain of Trust

```
┌─────────────────────────────────────────────────────────────┐
│                    BUILD TIME                               │
├─────────────────────────────────────────────────────────────┤
│  Nix flake pins all tools → Reproducible environment        │
│  mkosi builds image → dm-verity Merkle tree                 │
│  Roothash embedded in kernel cmdline                        │
│  Kernel + initrd + cmdline → UKI                            │
│  tdx-measure computes TDX measurements                      │
│  Manifest = {imageVersion, proxyVersion, tdxMeasurements}   │
│  cosign signs manifest → Fulcio cert + Rekor entry          │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    RUNTIME                                  │
├─────────────────────────────────────────────────────────────┤
│  TEE boots with measured kernel/initrd/cmdline              │
│  dm-verity verifies every filesystem read                   │
│  confer-boot verifies proxy.zip hash from cmdline           │
│  Proxy generates X25519 keypair                             │
│  Keypair embedded in TEE attestation report_data            │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT VERIFICATION                      │
├─────────────────────────────────────────────────────────────┤
│  Client fetches attestation quote from proxy                │
│  Verifies quote signature (AMD/Intel root of trust)         │
│  Extracts measurements from quote                           │
│  Looks up measurements in Rekor transparency log            │
│  Verifies cosign signature on matching manifest             │
│  Confirms public key in report_data matches Noise handshake │
│  Establishes encrypted channel with forward secrecy         │
└─────────────────────────────────────────────────────────────┘
```
