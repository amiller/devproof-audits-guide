#!/usr/bin/env python3
"""Verify the MDA→SE-key binding for every hardware-trust provider in the
live darkbloom attestation feed.

Usage:
  curl -sS https://api.darkbloom.dev/v1/providers/attestation > feed.json
  python3 binding-check.py feed.json

Reports how many providers' (sha256(se_public_key_b64) == OID 1.2.840.113635.100.8.11.1)
binding holds, and lists those where it fails — a real cryptographic gap that the
coordinator computes internally as `SEKeyBound` but does not expose in the feed.
"""
import json, base64, hashlib, sys
from cryptography import x509

OID_FRESHNESS = '1.2.840.113635.100.8.11.1'

def main(path):
    d = json.load(open(path))
    holds, fails, no_chain = [], [], []
    for p in d['providers']:
        if not p.get('mda_verified'): continue
        chain = p.get('mda_cert_chain_b64') or []
        if not chain:
            no_chain.append(p['provider_id']); continue
        leaf = x509.load_der_x509_certificate(base64.b64decode(chain[0]))
        ext = next((e for e in leaf.extensions if e.oid.dotted_string == OID_FRESHNESS), None)
        if not ext: continue
        raw = bytes(ext.value.value if hasattr(ext.value,'value') else ext.value)
        # Strip OCTET-STRING wrapper if present
        if len(raw) >= 2 and raw[0] == 0x04 and raw[1] == len(raw)-2:
            raw = raw[2:]
        expected = hashlib.sha256(p['se_public_key'].encode('ascii')).digest()
        bucket = holds if raw == expected else fails
        bucket.append((p['provider_id'][:8], p.get('mda_serial',''), p['chip_name']))

    print(f'mda_verified=true with chain : {len(holds)+len(fails)}')
    print(f'  binding HOLDS              : {len(holds)}')
    print(f'  binding FAILS              : {len(fails)}')
    print(f'mda_verified=true no chain in feed : {len(no_chain)}')
    if fails:
        print('\nFailures:')
        for pid, serial, chip in fails:
            print(f'  {pid}  {serial:11s}  {chip}')

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'feed.json')
