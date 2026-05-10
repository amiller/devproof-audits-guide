# Darkbloom (d-inference) — Case Study

Audit of [Layr-Labs/d-inference](https://github.com/Layr-Labs/d-inference), product brand **Darkbloom** by Eigen Labs. The framework's first **edge-TEE** case (Apple Secure Enclave + Hardened Runtime + SIP, no app-level memory encryption) and first **two-tier hybrid TEE** case (Intel TDX coordinator + Apple-attested macOS provider).

**Audit date:** 2026-05-10
**Repo HEAD:** `cf4c0ef`
**Provider release audited:** v0.4.7 (registered 2026-04-26 to `api.darkbloom.dev`)
**Live network at probe time:** 65 providers across M1 → M5 silicon

## TL;DR

Apple's vouching is real and externally verifiable. Provider source provenance is unusually clean. **But six gaps prevent the project from reaching the same external-verifiability posture as the dstack/Tinfoil cohort:**

1. **F1** — MDA→SE binding silently fails for **13/30 (43%)** hardware-trust providers in the live network. Coordinator computes the binding but doesn't gate routing on it.
2. **F2** — SE-signed AttestationBlob not in the public feed. Security-state fields (sip, binary_hash, encryption pubkey) are coordinator-asserted to outside auditors.
3. **F3** — No public coordinator attestation endpoint. Paper claims Intel TDX; no quote, no image hash, no Sigstore predicate exposed.
4. **F4** — Release registry has no public history; admin DELETE is silent; silent ADDs are a CT-analogous MITM vector.
5. **F5a/b** — Web verifier stops at "genuine Apple device" (NEAR-pattern incomplete easy path); the Python SDK referenced in docs doesn't exist on PyPI / GitHub. Realistic Python users get zero attestation enforcement.
6. **F6** — Three project docs disagree about who sees plaintext.

Five of those six are findable from the research paper alone — see the *Concordance with the research paper* section in `DEVPROOF-REPORT.md`.

## File guide

| File | Purpose |
|---|---|
| `DEVPROOF-REPORT.md` | **Canonical audit report.** Quick Status, architecture diagrams, stage assessment, six findings, paper concordance, reproduction steps. Start here. |
| `CHAIN-OF-TRUST.md` | Deep dive on cert-chain verification with the actual openssl/Python results from the live network (17/30 binding holds, 13/30 fails). |
| `RECON.md` | Initial recon notes. Useful for understanding how we arrived at the architectural framing; superseded by the report for findings. |
| `ISSUES-DRAFT.md` | Six file-able GitHub issues (F1–F6) with reproduce steps and code citations. Frame is devproofness/verifiability, not security. |
| `repo/` | Full clone of `Layr-Labs/d-inference` at `cf4c0ef`. |
| `verify/` | Reproducer artifacts. |

## Reproducing the audit (no payment, no account, ~30s)

```bash
# 1. Live attestation feed
curl -sS https://api.darkbloom.dev/v1/providers/attestation > /tmp/feed.json

# 2. Run the binding check
python3 verify/binding-check.py /tmp/feed.json
# Today: holds 17, fails 13

# 3. Latest release manifest + bundle hash check (no Mac required)
curl -sS https://api.darkbloom.dev/v1/releases/latest | jq .
curl -fsSL <url-from-step-3> -o bundle.tar.gz
sha256sum bundle.tar.gz                 # matches bundle_hash
tar -xzf bundle.tar.gz -C /tmp/bundle
sha256sum /tmp/bundle/bin/darkbloom     # matches binary_hash

# 4. Confirm coordinator publishes nothing about itself
curl -sS -o /dev/null -w '%{http_code}\n' https://api.darkbloom.dev/v1/coordinator/attestation
# 404
```

## Vendor channel

Eigen Labs' stated channel for actual security exploits is `security@eigenlabs.org` (per `repo/README.md`). The findings here are framed as **devproofness/verifiability gaps** — they're the right shape for GitHub Issues filed publicly. See `ISSUES-DRAFT.md` for the exact text.
