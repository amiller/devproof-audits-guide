#!/usr/bin/env python3
"""Reproduce the TrustedRouter attestation-chain checks against the live endpoint.

Checks, in order:
  1. JWT signature verifies against Google's Confidential Space JWKS (token is authentic)
  2. eat_nonce[0] == SHA-256(served TLS leaf cert DER)  (bound to this connection, no MITM replay)
  3. token image_digest == published gcp-release.json / image-digest-gcp.txt (running == published)

No account access needed; everything is public. Requires `cryptography`.
"""
import base64, hashlib, json, ssl, socket, urllib.request, re, sys

HOST = "api.trustedrouter.com"
TRUST = "https://trust.trustedrouter.com/trust"
JWKS = ("https://www.googleapis.com/service_accounts/v1/metadata/jwk/"
        "signer@confidentialspace-sign.iam.gserviceaccount.com")

def b64u(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def get(u): return urllib.request.urlopen(u, timeout=30).read()

def main():
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    tok = get(f"https://{HOST}/attestation").decode().strip()
    h, p, s = tok.split(".")
    hdr, pl = json.loads(b64u(h)), json.loads(b64u(p))

    # 1. signature
    jwks = json.loads(get(JWKS))
    k = next(k for k in jwks["keys"] if k["kid"] == hdr["kid"])
    n = int.from_bytes(b64u(k["n"]), "big"); e = int.from_bytes(b64u(k["e"]), "big")
    rsa.RSAPublicNumbers(e, n).public_key().verify(
        b64u(s), f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
    assert pl["iss"] == "https://confidentialcomputing.googleapis.com"
    assert pl["hwmodel"] == "GCP_INTEL_TDX" and pl["swname"] == "CONFIDENTIAL_SPACE"
    assert pl["dbgstat"] == "disabled-since-boot"
    print(f"[1] signature VALID, kid={hdr['kid']}  iss/hw/debug OK")

    # 2. nonce <-> TLS leaf
    pem = ssl.get_server_certificate((HOST, 443))
    der = base64.b64decode(re.search(
        r"CERTIFICATE-----(.+?)-----END", pem, re.S).group(1))
    fp = hashlib.sha256(der).hexdigest()
    assert fp in pl["eat_nonce"], f"cert fp {fp} not in nonce {pl['eat_nonce']}"
    subj = x509.load_der_x509_certificate(der).subject.rfc4514_string()
    print(f"[2] eat_nonce[0] == SHA-256(leaf DER) OK  ({subj})")

    # 3. running == published
    attested = pl["submods"]["container"]["image_digest"]
    published = get(f"{TRUST}/image-digest-gcp.txt").decode().strip()
    rel = json.loads(get(f"{TRUST}/gcp-release.json"))
    assert attested == published == rel["image_digest"], "digest mismatch"
    print(f"[3] running digest == published == release.json OK  ({attested[:23]}…)")
    print(f"    commit={rel['commit']}  repo={rel['source_repo']}")
    print("\nCHAIN CLEAN. Residual: digest is authenticated but not reproducible from source (see G1).")

if __name__ == "__main__":
    try:
        main()
    except Exception as ex:
        print("FAIL:", ex); sys.exit(1)
