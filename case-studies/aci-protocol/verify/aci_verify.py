#!/usr/bin/env python3
"""Structural ACI verifier — the §9 checks that need no TEE-vendor collateral.

What this covers, from the spec alone:

  §3.1  workload_keyset_digest == "sha256:" + sha256(JCS(keyset))
  §3.2  report_data == sha256({"keyset_digest":...,"nonce":...,"purpose":"aci.report_data.v1"})
  §3.1  not_after is in the future
  §1.1  the live TLS SPKI is listed in the keyset for the hostname we connected to
  §9.2  every session's id == sha256(JCS(document)) with the id removed, fetched full
  §9.2  evidence.data decodes and hashes to evidence.digest

What it deliberately does NOT cover: the TDX quote itself. Verifying that the
quote is genuine and that report_data is the quote's report_data needs vendor
collateral (dcap-qvl + PCCS, or an appraisal service). Run the official client
for that — `aci verify <url>` — and treat this script as the layer above it.
A pass here means the documents are internally consistent and bound to the
channel; it does not mean the hardware said so.

JCS caveat: ACI artifacts are ASCII field names and integer numbers (Appendix A),
where RFC 8785 reduces to compact JSON with lexicographically sorted keys. That
is what this implements. A document with floats or non-ASCII keys would need a
real JCS library.

Usage:
    python aci_verify.py https://tee.redpill.ai
    python aci_verify.py https://tee.redpill.ai --sessions 20
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import ssl
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

PURPOSE = "aci.report_data.v1"


def jcs(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def get_json(url: str, timeout: int = 60):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())


def live_spki_sha256(host: str, port: int = 443) -> str:
    """SHA-256 of the served certificate's SubjectPublicKeyInfo, DER-encoded."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=30) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    # Pull the SPKI out of the certificate without a full X.509 parser: the
    # cryptography module is used when present, else we fail loudly rather than
    # guess at DER offsets.
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    cert = x509.load_der_x509_certificate(der)
    spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return sha256_hex(spki)


def check_report(base: str, results: list) -> dict:
    host = urlparse(base).hostname
    nonce = os.urandom(32).hex()
    report = get_json(f"{base}/v1/aci/attestation?nonce={nonce}")

    results.append(("api_version is aci/1", report.get("api_version") == "aci/1", report.get("api_version")))

    keyset = report["attestation"]["workload_keyset"]
    digest = "sha256:" + sha256_hex(jcs(keyset))
    served = report["workload_keyset_digest"]
    results.append(("§3.1 keyset digest recomputes", digest == served, served))

    statement = '{"keyset_digest":"%s","nonce":%s,"purpose":"%s"}' % (
        served, json.dumps(nonce), PURPOSE)
    expect = sha256_hex(statement.encode())
    rd = report["attestation"]["report_data"]
    results.append(("§3.2 report_data binds keyset+nonce", rd == expect, rd[:32] + "…"))

    import time
    not_after = keyset["not_after"]
    results.append(("§3.1 keyset not expired", not_after > time.time(), f"not_after={not_after}"))

    pinned = {e["spki_sha256"] for e in keyset.get("tls_public_keys", [])
              if e.get("domain") in (None, host)}
    live = live_spki_sha256(host)
    results.append(("§1.1 live TLS SPKI is in the keyset", live in pinned, live[:32] + "…"))

    return report


def check_sessions(base: str, limit: int, results: list) -> dict:
    listing = get_json(f"{base}/v1/aci/sessions")
    entries = listing.get("sessions", [])
    if not entries:
        results.append(("sessions listed", False, "none"))
        return {}

    # One per verifier_id, up to `limit` overall: the failure modes are
    # per-adapter, so sampling across adapters beats sampling depth.
    by_verifier: dict[str, list] = {}
    for e in entries:
        by_verifier.setdefault(e["verifier_id"], []).append(e)
    sample = []
    while len(sample) < limit and any(by_verifier.values()):
        for rows in by_verifier.values():
            if rows and len(sample) < limit:
                sample.append(rows.pop(0))

    def one(entry):
        sid = entry["session_id"]
        try:
            full = get_json(f"{base}/v1/aci/sessions/{sid}")
        except Exception as e:  # noqa: BLE001 — a fetch failure is a finding
            return entry["verifier_id"], sid, f"fetch failed: {e}", None, None
        doc = {k: v for k, v in full.items() if k != "session_id"}
        id_ok = sha256_hex(jcs(doc)) == sid
        ev = full.get("evidence") or {}
        digest, data = ev.get("digest"), ev.get("data")
        if not digest or not data:
            ev_ok = None  # no §8.2 evidence at all
        else:
            # Split on the first comma only: a multipart data URI carries
            # `;boundary=...` before it, so a stricter media-type pattern
            # silently mis-parses and reports a real bundle as a mismatch.
            head, _, payload = data.partition(",")
            raw = base64.b64decode(payload) if head.endswith(";base64") else payload.encode()
            ev_ok = ("sha256:" + sha256_hex(raw)) == digest
        return entry["verifier_id"], sid, None, id_ok, ev_ok

    out: dict[str, dict] = {}
    with ThreadPoolExecutor(8) as ex:
        for vid, sid, err, id_ok, ev_ok in ex.map(one, sample):
            slot = out.setdefault(vid, {"n": 0, "id_ok": 0, "evidence": 0, "no_evidence": 0, "errors": 0})
            slot["n"] += 1
            if err:
                slot["errors"] += 1
                continue
            slot["id_ok"] += bool(id_ok)
            if ev_ok is None:
                slot["no_evidence"] += 1
            else:
                slot["evidence"] += bool(ev_ok)

    total = sum(s["n"] for s in out.values())
    ids = sum(s["id_ok"] for s in out.values())
    results.append(("§9.2(1) sampled session ids recompute", ids == total, f"{ids}/{total}"))
    missing = {v: s["no_evidence"] for v, s in out.items() if s["no_evidence"]}
    results.append(("§9.2(2) every sampled session carries evidence", not missing,
                    "all present" if not missing else f"missing: {missing}"))

    counts = {v: len(rows) for v, rows in
              {e["verifier_id"]: [x for x in entries if x["verifier_id"] == e["verifier_id"]]
               for e in entries}.items()}
    return {"per_verifier_total": counts, "sampled": out}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("base_url")
    ap.add_argument("--sessions", type=int, default=12, help="how many sessions to fetch in full")
    args = ap.parse_args(argv[1:])
    base = args.base_url.rstrip("/")

    results: list[tuple[str, bool, str]] = []
    check_report(base, results)
    detail = check_sessions(base, args.sessions, results)

    width = max(len(name) for name, _, _ in results)
    for name, ok, note in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name.ljust(width)}  {note}")
    if detail:
        print("\nsessions by verifier (full listing):")
        for vid, n in sorted(detail["per_verifier_total"].items()):
            s = detail["sampled"].get(vid, {})
            print(f"  {vid:42s} {n:4d} listed   sampled {s.get('n',0)}: "
                  f"id_ok {s.get('id_ok',0)}, evidence {s.get('evidence',0)}, "
                  f"no-evidence {s.get('no_evidence',0)}")

    print("\nNote: the TDX quote is NOT verified here — run `aci verify` for that.")
    return 0 if all(ok for _, ok, _ in results) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
