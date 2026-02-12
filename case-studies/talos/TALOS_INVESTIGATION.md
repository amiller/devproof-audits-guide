# Talos TEE/ROFL Investigation Notes

## Overview

Talos is an autonomous AI agent running in a TEE (Intel TDX) via Oasis ROFL framework, deployed on Sapphire paratime.

## Architecture

### What TEE Provides
- **Key Confidentiality**: Private keys generated inside TEE via `rofl_client.py`, never leave enclave
- **Secret Protection**: API keys (OpenAI, Twitter, GitHub) encrypted in rofl.yaml, decrypted only in TEE
- **Code Integrity**: Attestation ensures only specific code (identified by enclave IDs) can run

### What TEE Does NOT Provide
- Wise trading decisions (AI quality)
- Confidential trading signals (inputs are public: Dexscreener, Twitter, on-chain data)
- Protection against predictable behavior (algorithm is public)

### Trust Model
"Trust the code, not the operators" - Even with root access to host, operators cannot:
- Extract private keys from enclave
- Modify running code without re-attestation
- Access API keys

## On-Chain Addresses

### Talos Token (Arbitrum)
- **Contract**: `0x30a538effd91acefb1b12ce9bc0074ed18c9dfc9`
- **Supply**: ~302M T
- **Holders**: ~1,700
- **Price**: ~$0.0016
- **Market Cap**: ~$480K

### Trading Pair
- **Pair**: T/WETH on Uniswap V2
- **LP Address**: `0xdaae914e4bae2aae4f536006c353117b90fb37e3`

### ROFL App (Oasis Sapphire)
- **Mainnet App ID**: `rofl1qpykfkl6ea78cyy67d35f7fmpk3pg36vashka4v9`
- **Testnet App ID**: `rofl1qz8c57nvrru0rdtv7242rzwv269a87zh6c8auqr3`
- **Admin**: `oasis1qz2lty9v4glt5ts8ljhfpnd05dy3cwmtnyshws8q`

### Governance Safe (Oasis Sapphire)
- **Address**: `0x70739eB50e269f1f1eb27c6f8932f63389B1Cb63`
- **Purpose**: Approving ROFL deployments via multisig

### TEE-Generated Wallets
| Wallet ID | Purpose |
|-----------|---------|
| `test` | Testing (`0x1eB5305647d0998C3373696629b2fE8E21eb10B9`, empty) |
| `talos.ohm_buyer` | OHM TWAP strategy (address derived in TEE) |

## Codebase Structure

```
src/talos/
├── server/                    # PRODUCTION SERVER
│   ├── main.py               # FastAPI, registers jobs
│   ├── jobs/
│   │   ├── twap_olympus_strategy.py  # ACTIVE: ETH→OHM every 15min
│   │   └── increment_counter.py      # ACTIVE: test counter
│   └── routes/               # REST API
│
├── contracts/                 # ON-CHAIN INTEGRATIONS
│   ├── camelot_swap.py       # USED: Camelot DEX (ETH→OHM)
│   ├── ccip/                 # IMPLEMENTED: Chainlink CCIP bridging
│   ├── gmx/                  # IMPLEMENTED: GMX perpetuals
│   └── weth.py
│
├── tools/                     # EXTERNAL API INTEGRATIONS
│   ├── twitter.py            # IMPLEMENTED: post, reply, search
│   ├── twitter_client.py     # Tweepy wrapper
│   ├── github/tools.py       # IMPLEMENTED: issues, PRs, merge
│   ├── gitbook.py
│   ├── ipfs.py
│   ├── arbiscan.py
│   ├── dexscreener.py
│   └── contract_deployment.py
│
├── skills/                    # LLM-POWERED CAPABILITIES
│   ├── twitter_sentiment.py
│   ├── twitter_influence.py
│   ├── pr_review.py
│   ├── proposals.py
│   └── cryptography.py
│
├── services/
│   └── implementations/
│       ├── talos_sentiment.py
│       ├── yield_manager.py   # Sentiment → APR (not wired to production)
│       └── onchain_management.py
│
├── hypervisor/                # GUARDRAILS
│   ├── hypervisor.py         # LLM reviews actions
│   └── supervisor.py         # Rule-based approval
│
├── utils/
│   └── rofl_client.py        # TEE INTERFACE: key generation
│
└── core/
    ├── main_agent.py
    ├── agent.py
    └── job_scheduler.py
```

## What's Actually Running in Production

Based on `server/main.py`:
1. `TwapOHMJob` - Swap ETH→OHM every 15min via Camelot (mechanical, no AI)
2. `IncrementCounterJob` - Test counter
3. REST API at :8080

**NOT running in production** (implemented but not wired):
- Twitter posting/replying
- GitHub PR review/merge
- GMX trading
- LLM-based yield management
- Hypervisor action review

## Reproducible Build Process

### Dockerfile Pinning
- Base image: `python:3.12-slim@sha256:d67a7b66...`
- Debian snapshot: `20250815T025533Z`
- SOURCE_DATE_EPOCH: `1755248916`
- UV version: `0.8.11`
- Dependencies locked via `uv.lock`

### Build Command
```bash
docker buildx build \
    --builder buildkit_23 \
    --no-cache \
    --provenance false \
    --build-arg SOURCE_DATE_EPOCH="1755248916" \
    --output type=registry,name=${TARGET_IMAGE},rewrite-timestamp=true \
    .
```

### Current Image Digests

**At tag v0.1.4post1:**
```
sha256:c624242f7c02794360adeb345e5a524812eee38e6ac45db2ad8f0d808dfe2a26
```

**On current main:**
```
sha256:ed66b3a4e2e71eb9c97e2fe0c14b0d2aa8c778de09c67a5642a500a138ed6871
```

## Enclave IDs

**At tag v0.1.4post1 (mainnet):**
```
- akQLfQ9+okCPWCvidJ/0q0f8zbrKuxieHoBWDjOgqWQA...
- 1z36ioAIwPehcXNO0gTol9sKhD5rfVA5wpba+pJbu0sA...
```

**On current main (mainnet):**
```
- jypB1qfYh2YpoXQbDglIxMxHA2wqOWpH68cLAhp0CBkA...
- v6N3N67EmLtKgCGuLia6+aw/ZtgB2ZxcfHQxu3Bn+c0A...
```

## Verification Process

### To Verify a Release
```bash
# 1. Checkout tagged release
git checkout v0.1.4post1

# 2. Reproduce container image
./scripts/build_and_push_container_image.sh
# Should output matching sha256 digest

# 3. Build ROFL and verify enclave
oasis rofl build --deployment mainnet --verify
# Checks enclave ID matches rofl.yaml

# 4. Compare with on-chain policy
oasis rofl show rofl1qpykfkl6ea78cyy67d35f7fmpk3pg36vashka4v9
```

### Verification Gaps
- No CI artifact linking "tag → enclave ID → on-chain deployment"
- Enclave IDs updated multiple times since last tag
- No easy way to query on-chain enclave whitelist without Oasis node
- Main branch is 9 commits ahead of latest tag

## Key Questions

1. **Is TEE necessary for current workload?**
   - Current production is just TWAP swaps (mechanical)
   - Could be done with simple keeper or Chainlink Automation
   - TEE value is for future LLM-driven autonomous actions

2. **What does TEE add vs standard oracle?**
   - Chainlink: "Price is X" (trust nodes)
   - TEE: "I ran this code on these inputs" (trust Intel + attestation)
   - TEE enables arbitrary computation (LLMs) with attestation

3. **Can behavior be predicted?**
   - Yes - inputs are public, algorithm is public
   - TEE doesn't provide secret trading signals
   - Value is execution integrity, not decision confidentiality

## Docker Image Verification (2025-01-04)

### Image Pulled
```
ghcr.io/talos-agent/talos:latest-agent@sha256:ed66b3a4e2e71eb9c97e2fe0c14b0d2aa8c778de09c67a5642a500a138ed6871
```

### Verification Results

| Check | Result |
|-------|--------|
| Python file count | 192 in both image and repo ✅ |
| All .py file hashes | Identical ✅ |
| pyproject.toml | Identical ✅ |
| entrypoint.sh | Identical ✅ |
| server/main.py | `d0b8f4be45f1ee60549754aa372924a3` ✅ |
| rofl_client.py | `7a067f3132736e6f17d32e5e8c206857` ✅ |
| twap_olympus_strategy.py | `1d7b2d963666c0433e247e53a5c7a16e` ✅ |

### Image Config
```json
{
  "Cmd": ["python", "-m", "talos.cli.server"],
  "WorkingDir": "/app",
  "Env": [
    "PATH=/app/.venv/bin:...",
    "PYTHONPATH=/app/src"
  ],
  "ExposedPorts": {"8080/tcp": {}}
}
```

### Conclusion
**The Docker image contents match the current main branch of this repo exactly.**

All 192 Python source files have identical MD5 hashes between the image and the local repo.
The image was built from this codebase.

### Remaining Verification Gap
While we verified image ↔ repo match, the full chain is:

```
[This Repo] ──matches──> [Docker Image sha256:ed66b3a4...]
                                    ↓
                         [ROFL Build Process]
                                    ↓
                         [Enclave ID in rofl.yaml]
                                    ↓
                         [On-Chain Policy on Sapphire]
```

To complete verification, you would need to:
1. Run `oasis rofl build --verify` to confirm enclave ID
2. Query Sapphire to confirm on-chain policy matches rofl.yaml enclave IDs

## External Links
- Token: https://arbiscan.io/token/0x30a538effd91acefb1b12ce9bc0074ed18c9dfc9
- Pair: https://dexscreener.com/arbitrum/0xdaae914e4bae2aae4f536006c353117b90fb37e3
- Docs: https://docs.talos.is/
- GitHub: https://github.com/talos-agent/talos
