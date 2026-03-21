# TEE Trust Report

Note: Final report must be in English.

## One-Glance Card

One-glance verdict: SAFE / PARTIAL / NOT SAFE + key reason

| Dimension | Status | Signal | Evidence |
| --- | --- | --- | --- |
| Operator gap (can operator exfiltrate?) | PASS / FAIL / PARTIAL | GREEN / RED / YELLOW | allowed_envs, ${VAR} URLs |
| Attestation integrity | PASS / FAIL / PARTIAL | GREEN / RED / YELLOW | TDX quote + compose_hash match |
| TLS binding | PASS / FAIL / PARTIAL | GREEN / RED / YELLOW | certFingerprint vs attestation |
| Build reproducibility | PASS / FAIL / PARTIAL | GREEN / RED / YELLOW | digest pin + SOURCE_DATE_EPOCH |
| Upgrade transparency | PASS / FAIL / PARTIAL | GREEN / RED / YELLOW | Base KMS / timelock / history |

Signal key: GREEN=closed, YELLOW=partial/unknown, RED=attackable

## Summary

| Item | Result | Notes |
| --- | --- | --- |
| Verdict | SAFE / PARTIAL / NOT SAFE | One sentence |
| Stage | Unproven / Stage 0 / Stage 1 candidate | Why |
| Score | 0-100 | Weighted score |
| Initial triage | PASS / WARN / FAIL | Fast red-flag layer |
| Strong proof | PASS / WARN / FAIL | Quote / binding / reproducibility / traceability |
| Website | PASS / WARN / FAIL | TLS and live evidence |
| Repo | PASS / WARN / FAIL | Auditability and reproducibility |

## Critical Blockers

- Blocker 1
- Blocker 2

## Evidence

### Attestation

- endpoint:
- compose hash:
- compose-hash algorithm:
- measurement binding:
- quote verifier:
- repo-to-live link:

### TLS

- certificate issuer:
- certificate fingerprint:
- boundary model:
- binding evidence:

### Deployment Traceability

- repo remote:
- repo commit:
- app id:
- deployed digest / compose hash:
- evidence grade:

### Operator Gap

- configurable URLs:
- `allowed_envs`:
- mutable image refs:

### Upgrade Transparency

- AppAuth or registry evidence:
- timelock evidence:

## Recommended Next Step

- the single highest-leverage change needed to move closer to Stage 1
