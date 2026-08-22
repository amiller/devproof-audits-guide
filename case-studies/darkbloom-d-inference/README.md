# Darkbloom (d-inference) — Case Study

Audit of [Layr-Labs/d-inference](https://github.com/Layr-Labs/d-inference), product brand **Darkbloom** by Eigen Labs. The framework's first **edge-TEE** case (Apple Secure Enclave + Hardened Runtime + SIP, no app-level memory encryption) and first **two-tier hybrid TEE** case (a confidential-VM coordinator + Apple-attested macOS providers).

**Latest pass:** 2026-08-22 — paid-product relaunch, repo HEAD `232911ca`, 251 commits since the June review.
**Earlier passes:** 2026-06-07 (`069a6c3`), 2026-05-10 (`cf4c0ef`).

## TL;DR (2026-08-22)

**Darkbloom built the control the June report said was missing.** Provider code identity is no longer a self-reported hash: v0.6.0 added an **APNs code-identity challenge** — the coordinator pushes `E_K(nonce)` to the provider's Apple push token, which only a binary carrying Darkbloom's Team ID, App ID and Apple-signed push profile can receive, and the provider answers with a Secure-Enclave signature. Self-reported `binaryHash` is explicitly demoted to telemetry in their own threat model. That is real engineering against a real finding.

Four things stand between that mechanism and the guarantee the product sells:

1. **N1 — the proof isn't bound to the device it vouches for.** Posture (MDM/MDA), key possession (SE), and code identity (APNs token) are three independent legs pivoting on a **self-asserted serial number**; none ties to the machine that decrypts the prompt. One clean enrolled Mac can vouch for inference running elsewhere. `/ws/provider` requires no authentication.
2. **N2 — enforcement is an operator env var defaulting to grace.** Unset `APNS_ENFORCE_AFTER` ⇒ un-attested providers route normally. Headless Macs *structurally cannot* attest; the documented routable pool was ≈67/176. One aggregate boolean in `/v1/stats` is the only external witness.
3. **N3 — the coordinator TEE leg regressed.** June: Intel TDX on EigenCloud with a public 35-entry image-digest history (the one link marked ✓ verified). Today: a self-run GCE VM that GCP reports as **AMD SEV, not SEV-SNP**, `--maintenance-policy=MIGRATE`, **nothing published**, and the boot-time confidential-compute assertion their own runbook calls a blocker is not implemented.
4. **N4 — the paid UI contradicts the code.** The console's verification panel asserts four guarantees — including *"Not even Darkbloom servers can read them"* and a binary-hash check that is default-off — while the Terms and Privacy Policy in the same repo state the truth. The web verifier can also verify the *wrong* provider (`providers[0]` fallback).

Prior findings: **F1, F2, F3, F4, F5, F6 — five open, one fixed**; the June §1 "no code identity" finding is superseded by N1 (a real anchor now exists; it is unbound rather than absent).

## File guide

| File | Purpose |
|---|---|
| `DEVPROOF-REPORT.md` | **Canonical current report (2026-08-22, HEAD `232911ca`).** N1–N4, F1–F6 status, credit section, recommendations. Start here. |
| `DEVPROOF-REPORT-2026-06-07.md` | Prior canonical report (HEAD `069a6c3`) — the "no remote code identity" headline the APNs work responds to. |
| `DEVPROOF-REPORT-2026-05-10.md` | Original audit (HEAD `cf4c0ef`) — architecture diagrams, stage assessment, paper concordance. |
| `FOLLOWUP-REPORT.md` | 2026-06-07 multi-agent re-examination of F1–F6 (examiner + adversarial skeptic per finding). |
| `CHAIN-OF-TRUST.md` | Deep cert-chain walk with live openssl/Python results from the 2026-05 network. |
| `RECON.md` | Initial recon notes (2026-05-10). Superseded by the reports for findings. |
| `ISSUES-DRAFT.md` | File-able GitHub issues — F1–F6, plus the **2026-08-22 addendum** (N1–N4). |
| `verify/` | Reproducer artifacts: `binding-check.py` (MDA→SE binding), `enforcement-check.sh` (is the code-identity gate on?), captured cert chains. |

## Reproducing (no payment, no account)

Source-only — this is what the 2026-08-22 pass is built on:

```bash
git clone https://github.com/Layr-Labs/d-inference && cd d-inference
git checkout 232911ca690b78cbd3c8f65668d69f75a8f6bef0
grep -rin "codesign\|cdhash\|teamid" --include=*.go coordinator/   # → nothing: the only code anchor is the APNs channel
sed -n '1016,1021p' coordinator/registry/registry.go               # → grace is the default
sed -n '27p' docs/operations/coordinator-deploy.md                 # → "Do not claim SEV-SNP for this VM."
```

Live (blocked by egress policy during the 2026-08-22 pass — run these yourself):

```bash
verify/enforcement-check.sh                       # is the code-identity gate enforced? what coverage?
curl -sS https://api.darkbloom.dev/v1/providers/attestation > /tmp/feed.json
python3 verify/binding-check.py /tmp/feed.json    # MDA→SE binding (F1)
jq '.providers[0] | keys' /tmp/feed.json          # does the feed carry code_attested / se_key_bound yet?
```

## Vendor channel

Eigen Labs' stated channel for exploits is `security@eigenlabs.org`. **N1 should go there first** — it is an exploitable identity-binding gap, not a documentation issue, and it has a cheap fix (bind the APNs token to the MDM-enrolled device). N2–N4 and F1–F6 are devproofness/verifiability gaps and are the right shape for public GitHub issues; see `ISSUES-DRAFT.md`.
