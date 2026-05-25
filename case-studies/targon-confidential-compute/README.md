# Targon (SN4 / Manifold Labs) — confidential GPU rental

DevProof audit of Bittensor subnet 4's "Confidential Decentralized AI Cloud" (Intel TDX + NVIDIA CC,
AMD SEV-SNP). Now a **GPU-rental auction marketplace**, not a managed inference API (the old inference
hub `targon-hub-api` is deleted upstream).

- **[DEVPROOF-REPORT.md](DEVPROOF-REPORT.md)** — the audit. Headline: every attestation verdict is a
  `{valid:bool}` from Manifold's closed `tower.targon.com` (F1); the renter is never in the attestation
  loop and there's no E2E channel (F2); image/agent/golden-values are closed and non-reproducible (F4).
- **[RECON.md](RECON.md)** — code-trace, the closed `tvm/install` binary teardown, and credit items.

Source clones live in `refs/` (gitignored; re-fetch command in `.gitignore`).
Compare: [chutes-confidential-inference](../chutes-confidential-inference/) is the mirror image
(client-verifiable quote + ML-KEM E2E, but TOFU golden values).
