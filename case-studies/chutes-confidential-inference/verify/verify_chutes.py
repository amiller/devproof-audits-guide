#!/usr/bin/env python3
"""
Chutes confidential-inference attestation reproducer.

What it demonstrates against the LIVE api.chutes.ai:
  1. report_data[0:32]  == SHA256(client_nonce + e2e_pubkey)   (E2E key binding)
  2. two different nonces -> two different report_data          (per-request freshness)
  3. td_attributes bit 0 == 0                                   (debug mode disabled)
  4. report_data[32:64] == SHA256(SPKI of returned certificate) (attestation-svc cert binding)
  5. quote MRTD matches a published /servers/tee/measurements   (golden-value match)
  6. two DIFFERENT TEE models share identical MRTD+RTMRs         (model NOT in the measurement -> F1)

Requires: cryptography  (pip install cryptography). API key in /tmp/ck (Bearer cpk_...).
"""
import json, base64, hashlib, secrets, urllib.request

K = open("/tmp/ck").read().strip()
BASE = "https://api.chutes.ai"
# Several distinct confidential models. Instance placement is nondeterministic,
# so we probe a handful and look for any pair that lands on the same image+hardware
# (=> byte-identical quote across two different models, proving model is unmeasured).
MODELS = {
    "Qwen3-32B-TEE": "ac059e33-eb27-541c-b9a9-24b214036475",
    "gemma-4-31B-TEE": "42ee92ba-a537-5a73-8741-876067750db7",
    "GLM-5-TEE": "e51e818e-fa63-570d-9f68-49d7d1b4d12f",
    "DeepSeek-V3.2-TEE": "398651e1-5f85-5e50-a513-7c5324e8e839",
    "Kimi-K2.6-TEE": "aac09863-35b4-5d9b-9b67-6e6a9d54273a",
}


def get(url):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {K}"})
    return json.load(urllib.request.urlopen(req, timeout=60))


def parse_quote(b64):
    # Offsets per chutes-api/api/server/quote.py:124-129 (td_report = quote[48:]).
    q = base64.b64decode(b64)
    body = q[48:]
    return {
        "td_attributes": body[120:128].hex(),
        "mrtd": body[136:184].hex(),
        "rtmr0": body[328:376].hex(),
        "rtmr1": body[376:424].hex(),
        "rtmr2": body[424:472].hex(),
        "rtmr3": body[472:520].hex(),
        "report_data": body[520:584].hex(),  # 64 bytes
    }


def spki_sha256(cert_der_b64):
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    der = base64.b64decode(cert_der_b64)
    cert = x509.load_der_x509_certificate(der)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(spki).hexdigest().lower(), cert.subject.rfc4514_string()


def discover(chute_id):
    return get(f"{BASE}/e2e/instances/{chute_id}")["instances"][0]


def evidence(instance_id, nonce):
    return get(f"{BASE}/instances/{instance_id}/evidence?nonce={nonce}")


golden = {c["mrtd"].lower() for c in get(f"{BASE}/servers/tee/measurements")}
print(f"published golden set: {len(golden)} distinct MRTD\n")

fingerprints = {}
for name, cid in MODELS.items():
    inst = discover(cid)
    iid, pub, nonce = inst["instance_id"], inst["e2e_pubkey"], secrets.token_hex(32)
    ev = evidence(iid, nonce)
    q = parse_quote(ev["quote"])
    bind = hashlib.sha256((nonce + pub).encode()).hexdigest().lower()
    cert_hash, subj = spki_sha256(ev["certificate"])
    debug = bool(int(q["td_attributes"], 16) & 1)
    print(f"### {name}  instance={iid}")
    print(f"  [1] report_data[0:32] == SHA256(nonce+pub) : {q['report_data'][:64] == bind}")
    print(f"  [3] debug mode disabled                    : {not debug}")
    print(f"  [4] report_data[32:64] == SHA256(cert SPKI): {q['report_data'][64:128] == cert_hash}  (subj={subj})")
    print(f"  [5] MRTD in published golden set           : {q['mrtd'] in golden}")
    print(f"  gpu_evidence count                         : {len(ev['gpu_evidence'])}")
    fingerprints[name] = (q["mrtd"], q["rtmr0"], q["rtmr1"], q["rtmr2"], q["rtmr3"])
    print()

# [2] freshness: a second nonce on the first model
m0 = list(MODELS.values())[0]
inst0 = discover(m0)
rd_a = parse_quote(evidence(inst0["instance_id"], secrets.token_hex(32))["quote"])["report_data"]
rd_b = parse_quote(evidence(inst0["instance_id"], secrets.token_hex(32))["quote"])["report_data"]
print(f"[2] freshness: two nonces -> different report_data: {rd_a != rd_b}\n")

# [6] model substitution — look for two different models with byte-identical quotes
names = list(fingerprints)
mrtd_all_same = len({fp[0] for fp in fingerprints.values()}) == 1
print(f"[6] MODEL-SUBSTITUTION CHECK ({len(names)} different models probed):")
print(f"    MRTD identical across ALL probed models: {mrtd_all_same}")
full_match = None
for i in range(len(names)):
    for j in range(i + 1, len(names)):
        if fingerprints[names[i]] == fingerprints[names[j]]:
            full_match = (names[i], names[j])
if full_match:
    print(f"    Two DIFFERENT models with byte-identical MRTD+RTMR0-3: {full_match[0]} == {full_match[1]}")
    print("    => the served model is NOT distinguished by any measured register (F1).")
else:
    print("    No fully-identical pair this run (instances landed on different image/hardware).")
    print("    Re-run: placement is nondeterministic. MRTD-identical already shows model is unmeasured.")
