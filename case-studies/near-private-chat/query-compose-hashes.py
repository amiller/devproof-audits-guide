#!/usr/bin/env python3
"""Query ComposeHashAdded/Removed events from AppAuth contracts on Base."""

import requests
import sys

COMPOSE_HASH_ADDED = "0xfecb34306dd9d8b785b54d65489d06afc8822a0893ddacedff40c50a4942d0af"
COMPOSE_HASH_REMOVED = "0x755b79bd4b0eeab344d032284a99003b2ddc018b646752ac72d681593a6e8947"

CONTRACTS = [
    ("dstack-ingress", "0x000b2d32de3ed13d7e15b735997e7580ed6dea69"),
    ("chat-api", "0xf723e96ab11772f0166e5e4749e49a2113f63b0c"),
    ("cloud-api", "0xf550fdfb4eb8ad787c1bcd423f091cbb4a4431ae"),
]

RPC_URL = "https://base-mainnet.public.blastapi.io"

def get_events(addr, topic):
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getLogs",
        "params": [{"address": addr, "topics": [topic], "fromBlock": "0x0", "toBlock": "latest"}]
    }
    resp = requests.post(RPC_URL, json=payload, timeout=30)
    return resp.json().get("result", [])

def main():
    for name, addr in CONTRACTS:
        print(f"\n{'='*70}")
        print(f"{name}: {addr}")
        print(f"{'='*70}")

        added = get_events(addr, COMPOSE_HASH_ADDED)
        removed = get_events(addr, COMPOSE_HASH_REMOVED)

        added_hashes = set(log["data"] for log in added)
        removed_hashes = set(log["data"] for log in removed)
        active_hashes = added_hashes - removed_hashes

        print(f"Total added: {len(added_hashes)}, Removed: {len(removed_hashes)}, Active: {len(active_hashes)}")
        print(f"\nActive compose hashes:")

        # Get block numbers for each hash
        hash_blocks = {}
        for log in added:
            h = log["data"]
            b = int(log["blockNumber"], 16)
            if h not in hash_blocks or b > hash_blocks[h]:
                hash_blocks[h] = b

        for i, h in enumerate(sorted(active_hashes, key=lambda x: hash_blocks.get(x, 0)), 1):
            print(f"  {i}. {h}")

if __name__ == "__main__":
    main()
