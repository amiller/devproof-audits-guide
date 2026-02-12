# Auditing Primus Attestor Node

Analysis from inspecting `primuslabs/attestor-node:0.1.0` Docker image.

## Image Structure

```
/app.jar              87MB Spring Boot app (JDK 24)
/opt/libs/
  libpado.so          10MB native ZK proof library
  libpado_callback_lib.so
/cipher/circuit_files/
  aes128_ks.txt       ZK circuits for AES128
  aes128_with_ks.txt
/certs/               CA certificates
```

## Auditability Assessment

| Component | Auditable? | Notes |
|-----------|------------|-------|
| Docker image structure | ✓ Yes | `docker run --entrypoint sh` and inspect |
| `application.yaml` | ✓ Yes | Plain text config |
| Shell scripts | ✓ Yes | `__cacert_entrypoint.sh` readable |
| ZK circuit files | ✓ Yes | Plain text `.txt` format |
| `app.jar` (Java bytecode) | ⚠️ Tedious | Decompilable but 87MB is impractical |
| `libpado.so` (native binary) | ✗ No | Would require reverse engineering |

## Key Findings from Config

From `application.yaml`:

```yaml
system:
  config:
    kms-provider: DSTACK_KMS
    dstack-socket-file: /var/run/dstack.sock
    base:
      rpc-url: ${BASE_RPC_URL:https://sepolia.base.org}
      task-contract-address: ${BASE_TASK_CONTRACT_ADDRESS:0x7f56cd78A2c982440Eb33Ac260550FE2Acc00b81}
    # Default is Anvil test key
    private-key: ${PRIVATE_KEY:0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}
```

- Default private key is first Anvil key (`0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`)
- Must be overridden via `PRIVATE_KEY` env var in production
- Uses dstack KMS for key management

## Open Source Status

| Component | On GitHub? | Repo |
|-----------|------------|------|
| attestor-node | No | Docker image only |
| attestor-service | No | Docker image only |
| libpado.so | No | Binary only |
| zkTLS contracts | Yes | [primus-labs/zktls-contracts](https://github.com/primus-labs/zktls-contracts) |
| zkTLS core SDK | Yes | [primus-labs/zktls-core-sdk](https://github.com/primus-labs/zktls-core-sdk) |
| Browser extension | Yes | [primus-labs/primus-extension](https://github.com/primus-labs/primus-extension) |

## Trust Gaps

1. **`libpado.so`** - Core ZK proof cryptography. Binary blob, no source published. This is where the cryptographic operations happen.

2. **Java bytecode** - Decompilable in principle, but reviewing ~87MB of decompiled Spring Boot is not practical for thorough audit.

## "Open Source" vs "Auditable"

- **"On GitHub"** is helpful but not required for auditability
- **Image inspection** (what we did) provides real audit value
- **Reproducible builds** would close the gap: source + build instructions → byte-identical artifacts

The right questions:
- ~~"Is it on GitHub?"~~
- "Can I inspect the deployed artifact?" ✓
- "Can I reproduce the deployed artifact from source?" (best, but not available here)

## Commands Used

```bash
# Pull and inspect
docker pull primuslabs/attestor-node:0.1.0
docker run --rm --entrypoint sh primuslabs/attestor-node:0.1.0 -c "ls -la /"

# Extract and examine jar
docker create --name temp primuslabs/attestor-node:0.1.0
docker cp temp:/app.jar /tmp/app.jar
docker rm temp
unzip -p /tmp/app.jar BOOT-INF/classes/application.yaml
```
