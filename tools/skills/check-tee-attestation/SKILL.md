---
name: check-tee-attestation
description: Assess whether a GitHub repository and deployed website are safe to trust under the dstack DevProof model. Use when the user gives a repo, website, app ID, or attestation endpoint and asks whether a TEE app is safe, how strong its attestation and TLS binding are, whether the operator can still rug users, what DevProof stage it reaches, or what evidence is still missing.
---

# Check TEE Attestation

## Overview

Audit TEE applications from the auditor perspective. Focus on operator gap, attestation integrity, TLS binding, reproducibility, and upgrade transparency. The final report must be in English.

## Quick Start

1. Normalize inputs.
Accept GitHub URLs or local repo paths. Prefer live URLs; if only a custom domain is given, resolve `_dstack-app-address` to find the 8090 endpoint.

2. Run the checker.

```bash
python scripts/check_tee_attestation.py --repo /path/to/repo --url https://target.example
```

Useful variants:

```bash
python scripts/check_tee_attestation.py --repo https://github.com/org/repo --url https://app.example
python scripts/check_tee_attestation.py --repo /path/to/repo --url https://app.example --attestation-url https://app.example/v1/attestation/report
python scripts/check_tee_attestation.py --repo /path/to/repo --url https://<app-id>-443.dstack-pha-prod9.phala.network --format markdown
python scripts/check_tee_attestation.py --repo /path/to/repo --url https://app.example --evidence-dir evidences/
```

3. Read the result as an auditor.
The script gives a verdict, score, stage estimate, blockers, and evidence. Treat `Stage 1 candidate` as evidence-supported, not as a substitute for full manual review.

4. Follow up with manual checks when the live target matters.
Use [references/live-checks.md](./references/live-checks.md) and [references/plan-tee.md](./references/plan-tee.md).

## Workflow (7 Phases)

1. Threat model and trust claims.
2. Attestation evidence collection (8090, Trust Center, Cloud API).
3. Quote verification (dcap-qvl/manual parsing; compose_hash vs mr_config_id).
4. TLS binding check (passthrough vs gateway; certFingerprint).
5. Code audit for operator gap (allowed_envs, ${VAR} URLs, image pinning, KMS).
6. Cross-reference deployed compose vs source.
7. Evidence archiving for audit history.

## Output Requirements

- Final report must be in English.
- Include both:
  - Formal audit sections (Executive Summary, Key Questions, Findings, Evidence).
  - One-glance card (matrix + red/yellow/green signal).

## Reporting

Always report:

- Verdict: SAFE / PARTIAL / NOT SAFE
- Stage: Unproven / Stage 0 / Stage 1 candidate
- Score: weighted trust score
- Critical blockers: concrete reasons the app falls short
- Evidence: repo paths, endpoints, compose hash, TLS facts
- Next step: shortest path to upgrade the trust model

Use [references/report-template.md](./references/report-template.md) for the full output structure.

## Interpreting Results

### Strong result

Call the app safe under the DevProof model only when all of these are true:

- Live attestation evidence is reachable and coherent.
- The website's TLS endpoint is cryptographically bound to attested code, or the trust boundary is clearly limited to an attested gateway.
- The repo is auditable and the deployment can be connected back to the reviewed source.
- Reproducibility evidence exists.
- Operator-controlled URLs, secrets, and image indirection do not remain as rug vectors.
- Upgrades are visible and ideally timelocked.

### Weak result

Call the app `Stage 0` when you see real TEE evidence but any of the Stage 1 properties fail.

Common reasons:

- `allowed_envs` includes URLs, secrets, or image selectors
- image refs use `${VAR}` indirection
- no reproducible build evidence
- instant owner-controlled upgrades
- website TLS exists but cannot be tied back to attestation

### Inconclusive result

If the script cannot reach the website or the repo is not actually present, say the result is inconclusive instead of inventing certainty.

## References

- [references/devproof-stages.md](./references/devproof-stages.md): condensed Stage 0 vs Stage 1 decision model
- [references/live-checks.md](./references/live-checks.md): live endpoint heuristics, 8090 tricks, TLS binding checks
- [references/case-studies.md](./references/case-studies.md): patterns from real audits and which examples to compare against
- [references/report-template.md](./references/report-template.md): reusable output structure

## Scripts

- `scripts/check_tee_attestation.py`: combined repo plus live website checker with markdown, text, and JSON output
- `scripts/run_regression_cases.py`: local regression runner for the bundled sample cases
- `scripts/live_regression_cases.json`: optional live-network sample set for real deployment regression
