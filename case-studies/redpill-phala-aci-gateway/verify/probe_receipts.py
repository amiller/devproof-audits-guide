#!/usr/bin/env python3
"""Exercise the ACI receipt path end to end (§7, §9.3) — needs an API key.

Sends one real completion, fetches the signed receipt, and checks every binding
the spec defines:

  §9.3(1) signature verifies over JCS(receipt minus `signature`) under the
          key_id resolved in the ATTESTED keyset's receipt_signing_keys
  §9.3(2) api_version is aci/1 and workload_keyset_digest == the established one
  §9.3(3) request.received.body_hash == sha256(the bytes we sent)
  §9.3(4) response.returned.body_hash == sha256(the bytes we received)
  §9.3(5) upstream.verified has result/required/session_id
  §9.3(6) the cited session verifies (§9.2) and served_at is inside its window

Run it against a TEE-only host and an open host to see the two regimes:
    python probe_receipts.py                       # tee.redpill.ai, a TEE model
    python probe_receipts.py --host api.redpill.ai --model anthropic/claude-opus-5

The key is read from REDPILL_API_KEY (or awesome-private-inference/.env) and is
never printed. Each run costs a few tokens.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

import requests

ENV_FILE = Path.home() / "projects/awesome-private-inference/.env"


def api_key() -> str:
    key = os.environ.get("REDPILL_API_KEY", "").strip()
    if not key and ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            if line.startswith("REDPILL_API_KEY="):
                key = line.split("=", 1)[1].strip().strip('"').strip("'")
    if not key:
        sys.exit(f"REDPILL_API_KEY not set and not found in {ENV_FILE}")
    return key


def jcs(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def check(results: list, name: str, ok: bool, note: str = "") -> None:
    results.append((name, ok, note))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="tee.redpill.ai")
    ap.add_argument("--model", default="openai/gpt-oss-20b")
    ap.add_argument("--max-tokens", type=int, default=8)
    ap.add_argument("--require", action="store_true",
                    help="set provider.aci_verified=true (§5.3): demand attested serving")
    args = ap.parse_args(argv[1:])
    base = f"https://{args.host}"
    key = api_key()
    auth = {"Authorization": f"Bearer {key}"}
    results: list[tuple[str, bool, str]] = []

    # Establish the keyset first: a receipt resolves its signing key here (§7.2).
    report = requests.get(f"{base}/v1/aci/attestation?nonce={os.urandom(32).hex()}", timeout=60).json()
    keyset = report["attestation"]["workload_keyset"]
    established_digest = report["workload_keyset_digest"]

    body = {
        "model": args.model,
        "messages": [{"role": "user", "content": "Reply with the single word: ok"}],
        "max_tokens": args.max_tokens,
        "stream": False,
    }
    if args.require:
        body["provider"] = {"aci_verified": True}
    raw_request = json.dumps(body).encode()
    resp = requests.post(f"{base}/v1/chat/completions", headers={**auth, "Content-Type": "application/json"},
                         data=raw_request, timeout=180)
    raw_response = resp.content
    print(f"POST {base}/v1/chat/completions  model={args.model}  -> HTTP {resp.status_code}")
    receipt_id = resp.headers.get("X-Receipt-Id")
    print(f"  X-ACI-Version={resp.headers.get('X-ACI-Version')}  "
          f"X-ACI-Keyset-Digest={(resp.headers.get('X-ACI-Keyset-Digest') or '')[:24]}…")
    print(f"  X-Receipt-Id={receipt_id}")
    if not receipt_id:
        print(f"  body: {raw_response[:300]!r}")
        return 1

    receipt = requests.get(f"{base}/v1/aci/receipts/{receipt_id}", headers=auth, timeout=60).json()

    # (1) signature over JCS of the document without `signature`
    doc = {k: v for k, v in receipt.items() if k != "signature"}
    entry = next((e for e in keyset["receipt_signing_keys"] if e["key_id"] == receipt.get("key_id")), None)
    sig_ok = False
    if entry and entry.get("algo") == "ed25519":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(entry["public_key"]))
        try:
            pub.verify(bytes.fromhex(receipt["signature"]), jcs(doc))
            sig_ok = True
        except InvalidSignature:
            sig_ok = False
    check(results, "§9.3(1) receipt signature verifies under the attested key", sig_ok,
          f"key_id={receipt.get('key_id')} algo={(entry or {}).get('algo')}")

    # (2) version + keyset digest
    check(results, "§9.3(2) api_version and keyset digest match the established one",
          receipt.get("api_version") == "aci/1"
          and receipt.get("workload_keyset_digest") == established_digest,
          receipt.get("workload_keyset_digest", "")[:24] + "…")

    events = {e["type"]: e for e in receipt.get("event_log", [])}

    # (3)/(4) body hashes over the exact bytes we sent and received
    check(results, "§9.3(3) request.received.body_hash == sha256(bytes we sent)",
          (events.get("request.received") or {}).get("body_hash") == "sha256:" + sha256_hex(raw_request),
          (events.get("request.received") or {}).get("body_hash", "")[:24] + "…")
    check(results, "§9.3(4) response.returned.body_hash == sha256(bytes we got)",
          (events.get("response.returned") or {}).get("body_hash") == "sha256:" + sha256_hex(raw_response),
          (events.get("response.returned") or {}).get("body_hash", "")[:24] + "…")

    fwd = events.get("request.forwarded")
    if fwd:
        rewritten = fwd.get("body_hash") != (events.get("request.received") or {}).get("body_hash")
        print(f"  service-side rewrite (§7.4): {rewritten}")

    # (5)/(6) the upstream hop
    up = events.get("upstream.verified")
    if up is None:
        check(results, "§9.3(5) receipt carries upstream.verified", False, "absent")
    else:
        print(f"  upstream.verified: result={up.get('result')} required={up.get('required')} "
              f"model_id={up.get('model_id')} session={str(up.get('session_id'))[:16]}…")
        if args.require and resp.status_code == 503:
            # §1.2 fail-closed: the constraint was set, no attested session could
            # serve, so the refusal IS the correct outcome — and it still carries
            # a signed receipt (§7.5).
            check(results, "§1.2 required verification refused the prompt (fail closed)",
                  up.get("result") == "failed" and up.get("required") is True
                  and "request.forwarded" not in events,
                  f"HTTP 503, forwarded={'request.forwarded' in events}")
        else:
            check(results, "§9.3(5) upstream.verified says result=verified, required=true",
                  up.get("result") == "verified" and up.get("required") is True,
                  f"result={up.get('result')} required={up.get('required')}")
        sid = up.get("session_id")
        if sid:
            full = requests.get(f"{base}/v1/aci/sessions/{sid}", timeout=60).json()
            recomputed = sha256_hex(jcs({k: v for k, v in full.items() if k != "session_id"}))
            check(results, "§9.2(1) cited session recomputes to its id", recomputed == sid, sid[:24] + "…")
            served = receipt.get("served_at", 0)
            check(results, "§9.3(6) served_at falls inside the session window",
                  full.get("established_at", 0) <= served <= full.get("expires_at", 0),
                  f"{full.get('established_at')} <= {served} <= {full.get('expires_at')}")
            claims = full.get("claims") or {}
            typed = {k: v.get("status") for k, v in claims.items() if k != "extra"}
            unknown = [k for k, v in typed.items() if v == "unknown"]
            refuted = [k for k, v in typed.items() if v == "refuted"]
            print(f"  cited session verifier={full.get('verifier_id')}")
            print(f"    claims: {typed}")
            print(f"    -> {len(unknown)} unknown, {len(refuted)} refuted "
                  f"(neither blocks acceptance; §9.2 step 3 is YOUR policy)")

    width = max(len(n) for n, _, _ in results)
    print()
    for name, ok, note in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name.ljust(width)}  {note}")
    return 0 if all(ok for _, ok, _ in results) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
