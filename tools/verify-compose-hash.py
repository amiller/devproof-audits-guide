#!/usr/bin/env python3
"""
Verify dstack app compose hash from the 8090 metadata endpoint.

Usage:
    ./verify-compose-hash.py <app-id> [cluster]

Example:
    ./verify-compose-hash.py f44389ef4e953f3c53847cc86b1aedc763978e83 dstack-pha-prod9
"""

import html
import hashlib
import json
import sys
import urllib.request

CLUSTERS = {
    "dstack-pha-prod9": "dstack-pha-prod9.phala.network",
    "dstack-base-prod7": "dstack-base-prod7.phala.network",
    "dstack-prod5": "dstack-prod5.phala.network",
}

def fetch_8090_page(app_id: str, cluster: str) -> str:
    domain = CLUSTERS.get(cluster, f"{cluster}.phala.network")
    url = f"https://{app_id}-8090.{domain}/"
    req = urllib.request.Request(url, headers={'User-Agent': 'devproof-verifier/1.0'})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode('utf-8')

def extract_tcb_info(html_content: str) -> dict:
    start = html_content.find('<textarea readonly>')
    end = html_content.find('</textarea>', start)
    if start < 0 or end < 0:
        raise ValueError("Could not find tcb_info textarea in page")
    json_str = html_content[start + len('<textarea readonly>'):end]
    decoded = html.unescape(json_str)
    return json.loads(decoded)

def verify_compose_hash(tcb_info: dict) -> tuple[bool, str, str]:
    """Returns (matches, expected_hash, computed_hash)

    Note: app_compose in tcb_info is already a JSON STRING.
    Hash the raw string directly - do NOT parse and re-serialize.
    """
    expected = tcb_info.get('compose_hash', '')
    app_compose = tcb_info.get('app_compose', '')
    # Hash the raw string as-is (it's already JSON-serialized)
    computed = hashlib.sha256(app_compose.encode('utf-8')).hexdigest()
    return computed == expected, expected, computed

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    app_id = sys.argv[1]
    cluster = sys.argv[2] if len(sys.argv) > 2 else "dstack-pha-prod9"

    print(f"Fetching metadata for {app_id} on {cluster}...")

    html_content = fetch_8090_page(app_id, cluster)
    tcb_info = extract_tcb_info(html_content)

    matches, expected, computed = verify_compose_hash(tcb_info)

    print(f"\n=== Compose Hash Verification ===")
    print(f"Expected:  {expected}")
    print(f"Computed:  {computed}")
    print(f"Match:     {'✓ YES' if matches else '✗ NO'}")

    if matches:
        print(f"\n=== App Compose Summary ===")
        app_compose = json.loads(tcb_info['app_compose'])
        print(f"allowed_envs: {len(app_compose.get('allowed_envs', []))} vars")
        print(f"features: {app_compose.get('features', [])}")
        print(f"kms_enabled: {app_compose.get('kms_enabled')}")
        print(f"public_logs: {app_compose.get('public_logs')}")

        # Show docker compose images
        docker_compose = app_compose.get('docker_compose_file', '')
        images = [line.strip() for line in docker_compose.split('\n') if 'image:' in line]
        if images:
            print(f"\nImages referenced:")
            for img in images[:10]:
                print(f"  {img}")

    sys.exit(0 if matches else 1)

if __name__ == "__main__":
    main()
