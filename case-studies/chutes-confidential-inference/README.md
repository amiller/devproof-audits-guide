# Chutes Confidential Inference — Case Study

Audit of [chutes.ai](https://chutes.ai) confidential (`-TEE`) inference — serverless AI on **Bittensor subnet 64** (Rayon Labs), Intel TDX + NVIDIA confidential-compute GPUs, ML-KEM-768 E2E encryption. The framework's first **Bittensor-subnet** case and first **non-dstack custom TDX stack** (own attestation service, own measurement registry, own LUKS key release).

**Audit date:** 2026-05-25
**Repos:** `rayonlabs/chutes` `08d79872` · `rayonlabs/chutes-api` `77b6f355` · `rayonlabs/chutes-miner` `7afea4b1`
**Live:** 12 `confidential_compute` models, 10 measurement configs (h200 / b200 / RTX PRO 6000).

## TL;DR

The crypto core is sound and hardware-rooted — confirmed live: per-request freshness, `report_data[0:32]==SHA256(nonce‖e2e_pubkey)`, debug off, ML-KEM key in-TD, relay sees only ciphertext, MRTD matches the published golden set. **But five gaps keep it short of "verify without trusting us":**

1. **F1 (High)** — served model is in no measured register; the launch-command check and weight-digest monitor are both disabled on the TEE path. Model substitution passes attestation.
2. **F2 (High)** — golden MRTD/RTMRs are operator-asserted ConfigMap constants; the VM image has no published reproducible build and no on-chain anchor. TOFU.
3. **F3 (High)** — `/e2e/instances` hands out `e2e_pubkey` with no quote; the shipped `test_e2e_client.py` encrypts to it without verifying → silent control-plane MITM.
4. **F4 (Low–Med)** — GPU genuineness / CC-mode / RIM verdict only via NVIDIA NRAS cloud call; no offline path.
5. **F5 (Med)** — rootfs LUKS key is one static fleet-wide `LUKS_PASSPHRASE`.

## File guide

| File | Purpose |
|---|---|
| `DEVPROOF-REPORT.md` | **Canonical report.** Quick Status, architecture, what's verifiable, F1–F6, stage assessment, recommendations, reproduction. Start here. |
| `RECON.md` | Initial recon notes (framework-vs-service distinction, flow map, live snapshot). Superseded by the report for findings. |
| `verify/verify_chutes.py` | Live reproducer — six checks incl. model-substitution. ~5s, needs an API key in `/tmp/ck`. |
| `ISSUES-DRAFT.md` | File-able GitHub issues (F1–F5) framed as verifiability gaps. |
| `refs/` | Untracked clones of the three repos (re-fetch commands in `.gitignore`). |

## Reproduce (no payment, ~5s)

```bash
# API key in /tmp/ck (Bearer cpk_...)
curl -s -H "Authorization: Bearer $(cat /tmp/ck)" https://api.chutes.ai/servers/tee/measurements | jq 'length'   # 10 configs, 1 MRTD
python3 verify/verify_chutes.py     # [1]-[6]: binding, freshness, debug, cert, golden-match, model-substitution
```

## Vendor channel

Findings are framed as **devproofness/verifiability gaps** suitable for public issues on the `rayonlabs/chutes-api` / `rayonlabs/chutes` repos (see `ISSUES-DRAFT.md`), not exploits. F3 (default-insecure example client) and F1 (model not measured) are the ones to lead with.
