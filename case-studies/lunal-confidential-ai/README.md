# Confidential AI / Lunal / PrivateClaw

Audit of **Confidential AI** (confidential.ai, GitHub `lunal-dev`) — a SEV-SNP-on-Azure confidential **agent** (OpenClaw) + private-inference product, federating to Redpill (TDX+H100) on failover. First SEV-SNP-centric case study in this guide.

## Files
- **[DEVPROOF-REPORT.md](DEVPROOF-REPORT.md)** — the audit. Verdict **Stage 0**: crypto core sound, but nothing enforces *which code* runs (no measurement allow-list) or *binds* the attestation to the session.
- **[RECON.md](RECON.md)** — initial source recon + finding map (F1–F6).
- **verify/** — live-probe transcript (`live-probe-2026-05-25.md`) + decoded HCLA blob.
- **[TODO.md](TODO.md)** — remaining threads.
- `refs/` — cloned source (gitignored; re-fetch per `.gitignore`).

## Headline
`attestation-rs` is a verification **toolkit that reports facts and punts pass/fail to the caller**; every consumer gates on `signature_valid` alone (**F1** no measurement enforcement, **F2** unbound report_data, **F3** weak WASM verifier, **F4** unconditional JWT, **F5** product soft-passes). The live demo serves a **static, Aug-2025-expired, HMAC-signed GPU token it never checks** (**L1–L3**). The **C8s whitepaper** describes the allow-list/CDS enforcement that is missing from all shipped code.
