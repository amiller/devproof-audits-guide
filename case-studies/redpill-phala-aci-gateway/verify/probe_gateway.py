#!/usr/bin/env python3
"""Reproduce the deployment findings on the shared RedPill/Phala ACI gateway.

Three checks, none of which need an API key:

  G1  the legacy /v1/attestation/report endpoint returns a passing pre-ACI
      attestation for any `model` string, including models this gateway does
      not serve in a TEE and models that do not exist
  G5  one attested keyset spans a TEE-only host and a host where attested
      serving is not forced — compare the catalogs
  OS  resolve the RTMR3 os-image-hash against dstack's published archive and
      read the cryptographically bound is_dev flag

Usage:  python probe_gateway.py
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import ssl
import sys
import tarfile
import urllib.request

TEE_HOSTS = ["tee.redpill.ai", "inference.phala.com"]
OPEN_HOST = "api.redpill.ai"
ARCHIVE = "https://download.dstack.org/os-images/mr_{}.tar.gz"


def get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "devproof-aci-probe/1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def get_json(url: str):
    return json.loads(get(url))


def keccak_address(pubkey_hex: str) -> str:
    from eth_keys import keys
    return keys.PublicKey(bytes.fromhex(pubkey_hex[2:])).to_checksum_address().lower()


def g1_legacy_attests_anything() -> None:
    print("G1 — legacy /v1/attestation/report, one nonce, several model names")
    nonce = os.urandom(32).hex()
    cases = [
        ("tee.redpill.ai", "phala/gpt-oss-20b"),
        ("tee.redpill.ai", "anthropic/claude-opus-5"),
        ("tee.redpill.ai", "does/not-exist-xyz"),
        ("api.redpill.ai", "openai/gpt-5-nano"),
    ]
    addrs = set()
    for host, model in cases:
        r = get_json(f"https://{host}/v1/attestation/report?model={model}&nonce={nonce}")
        addr = r["signing_address"]
        addrs.add(addr)
        rd = r["attestation"]["report_data"]
        legacy_layout = rd == (bytes.fromhex(addr[2:]).ljust(32, b"\x00") + bytes.fromhex(nonce)).hex()
        derives = keccak_address(r["signing_public_key"]) == addr.lower()
        print(f"   {host:22s} {model:26s} addr={addr[:12]}… "
              f"report_data_binds={legacy_layout} key_derives={derives} quote={bool(r['intel_quote'])}")
    print(f"   -> distinct signing addresses across all model names: {len(addrs)}"
          "  (1 means the model parameter scopes nothing)\n")


def g5_two_regimes_one_keyset() -> None:
    print("G5 — one attested keyset, two serving regimes")
    digests, catalogs = {}, {}
    for host in TEE_HOSTS + [OPEN_HOST]:
        report = get_json(f"https://{host}/v1/aci/attestation?nonce={os.urandom(32).hex()}")
        digests[host] = report["workload_keyset_digest"]
        catalogs[host] = {m["id"] for m in get_json(f"https://{host}/v1/models")["data"]}
        print(f"   {host:22s} keyset={digests[host][:24]}…  models={len(catalogs[host])}")
    same = len(set(digests.values())) == 1
    extra = catalogs[OPEN_HOST] - catalogs[TEE_HOSTS[0]]
    print(f"   -> same workload keyset on every host: {same}")
    print(f"   -> models on {OPEN_HOST} absent from the TEE-only hosts: {len(extra)}")
    print(f"      e.g. {sorted(extra)[:5]}\n")


def resolve_os_image(host: str = "tee.redpill.ai") -> None:
    print("OS — resolve the attested os-image-hash against dstack's published archive")
    report = get_json(f"https://{host}/v1/aci/attestation?nonce={os.urandom(32).hex()}")
    vm = json.loads(report["attestation"]["evidence"]["vm_config"])
    h = vm["os_image_hash"]
    tf = tarfile.open(fileobj=io.BytesIO(get(ARCHIVE.format(h), timeout=180)))
    names = tf.getnames()
    sums = tf.extractfile([n for n in names if n.endswith("sha256sum.txt")][0]).read()
    meta_bytes = tf.extractfile([n for n in names if n.endswith("metadata.json")][0]).read()
    meta = json.loads(meta_bytes)
    # The flag is bound to the attested hash: os_image_hash == sha256(sha256sum.txt),
    # and sha256sum.txt pins metadata.json — so flipping is_dev breaks the quote.
    print(f"   image label       {vm['image']}")
    print(f"   os_image_hash     {h[:32]}…")
    print(f"   hash == sha256(sha256sum.txt):        {hashlib.sha256(sums).hexdigest() == h}")
    print(f"   metadata.json listed in sha256sum.txt: {hashlib.sha256(meta_bytes).hexdigest() in sums.decode()}")
    print(f"   -> version {meta.get('version')}, is_dev={meta.get('is_dev')}\n")


def main() -> int:
    g1_legacy_attests_anything()
    g5_two_regimes_one_keyset()
    resolve_os_image()
    print("The TDX quote itself is not checked here — run:")
    print("  aci verify https://tee.redpill.ai --require-production-os")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
