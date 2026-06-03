# TEE-Signed Usage Reports

## Problem

TEE attestation proves *what code runs*. Reproducible builds prove *code matches source*. Source review proves *the code is safe*. But none of this proves **users actually interacted with the attested code**.

For apps where users directly connect to the TEE endpoint (e.g., an HTTPS API with certificate transparency), the TLS chain provides some binding. But many TEE apps have **indirect user interaction** — users scan a QR code, click a link, or interact through an operator-controlled frontend. In these cases:

- The operator could run the real TEE app alongside a plaintext clone
- Route some/all users to the clone
- Capture sensitive data (session cookies, credentials) in the clear
- The TEE attestation remains valid — it's just not the thing users are talking to

This is the **parallel deployment attack**. It's hard to prove a negative ("we never ran a non-TEE version").

## Motivation: TokScope Xordi

TokScope captures TikTok session cookies inside a TEE. Users scan a QR code in a browser window. The user has no way to verify that browser is inside the attested enclave vs. a plain server. The TEE's 8090 attestation port isn't exposed to end users, and even if it were, QR-code-scanning users wouldn't check it.

The operator's incentive to cheat: TikTok session cookies are valuable. A plaintext version could silently harvest them.

The operator's disincentive to cheat (currently): reputation only. No cryptographic mechanism.

## Proposed Solution: TEE-Signed Heartbeats

The enclave itself periodically signs and publishes usage reports. These create a **cryptographic paper trail** that:

1. **The operator cannot forge** — signed by the TEE-derived key, verifiable against the attestation
2. **The operator cannot suppress** — missed heartbeats are visible gaps
3. **Creates economic misalignment with cheating** — publicly committed user counts mean more potential witnesses

### What Gets Signed

A periodic report containing:

```json
{
  "app_id": "f44389ef...",
  "compose_hash": "a9e4ac8a...",
  "period_start": "2026-02-10T00:00:00Z",
  "period_end": "2026-02-11T00:00:00Z",
  "session_count": 847,
  "unique_users": 312,
  "report_sequence": 42,
  "prev_report_hash": "sha256:..."
}
```

Key properties:
- **`compose_hash`** binds the report to a specific code version
- **`report_sequence` + `prev_report_hash`** creates a hash chain — can't insert or remove reports retroactively
- **Counts are aggregated** — no PII, just totals
- **Signed by TEE-derived key** — verifiable against the TDX quote

### What This Proves

- The TEE processed at least N sessions during period T
- No gaps in the reporting chain (missing heartbeats = suspicious)
- The operator publicly committed to serving N users through the attested code

### What This Doesn't Prove

- That the operator isn't *also* running a parallel non-TEE service
- That the reported counts are an upper bound (the TEE could under-report if the code were malicious — but the code is auditable)
- That specific users were served by the TEE

### Why It Still Helps

The parallel deployment attack becomes economically irrational at scale:

- If you claim 10k WAU through signed reports, those are 10k potential witnesses
- Diverting users to a non-TEE clone means your signed counts drop (visible) or your clone's users could notice anomalies
- The more you advertise growth, the more exposure you have if you're cheating
- It's the same logic as public company audited financials — doesn't make fraud impossible, but raises the cost dramatically

## Design Space

### Publication Mechanism

| Option | Trust Level | Complexity |
|--------|------------|------------|
| **Operator-hosted dashboard** | Low — operator controls visibility | Trivial |
| **Push to public append-only log** | Medium — third party holds the log | Low |
| **On-chain commitments** | High — tamper-evident, permissionless | Medium |
| **IPFS + on-chain hash** | High — data availability + tamper evidence | Medium |

On-chain is the natural fit since dstack already integrates with Base KMS. A heartbeat contract that accepts signed reports and rejects gaps in the sequence would be minimal.

### Frequency

- **Daily** seems right for most apps — enough granularity without overhead
- **Per-session** would be ideal but creates gas costs and privacy concerns
- **Weekly** is too coarse — a week of parallel deployment goes unnoticed

### Integration with dstack

This could be a generic dstack middleware / sidecar rather than app-specific:

```yaml
services:
  my-app:
    image: ghcr.io/org/app@sha256:...

  heartbeat:
    image: ghcr.io/aspect-build/dstack-heartbeat@sha256:...
    environment:
      - REPORT_INTERVAL=86400
      - PUBLISH_TO=base:0x1234...
```

The heartbeat sidecar:
1. Shares the TEE's derived signing key
2. Monitors the app's request logs (or receives counter increments via localhost)
3. Periodically signs and publishes a report

This keeps it out of application code and makes it reusable across dstack apps.

## Relation to ERC-733 Stages

This mechanism fits between Stage 1 (reproducible builds) and Stage 2 (on-chain governance):

- **Stage 0**: No transparency — operator can do anything
- **Stage 1**: Code is verifiable — attestation + reproducible builds
- **Stage 1.5 (this)**: Usage is verifiable — TEE-signed heartbeats prove the attested code is actually serving users
- **Stage 2**: Upgrades are verifiable — on-chain governance of compose hash changes

For apps with indirect user interaction (no direct TLS to TEE), Stage 1 alone is insufficient. You need 1.5 to close the parallel deployment gap.

## Open Questions

1. **Counter manipulation**: The TEE code is auditable, but could a malicious version inflate/deflate counts? Mitigated by source review, but worth noting.
2. **Privacy**: Even aggregate counts leak information (usage patterns, growth rate). Is this acceptable for all apps?
3. **Downtime vs. suppression**: How do you distinguish "app was down for maintenance" from "operator suppressed reports"? Maybe require signed downtime notices.
4. **Cost**: On-chain publication has gas costs. Who pays — the operator? A subsidy from the protocol?
5. **Bootstrapping**: First heartbeat needs to be anchored to the attestation. The initial report should include the full TDX quote.
