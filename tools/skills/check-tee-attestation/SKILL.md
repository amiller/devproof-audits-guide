---
name: check-tee-attestation
description: Assess whether a GitHub repository and deployed website are safe to trust under the dstack DevProof model. Use when the user gives a repo, website, app ID, or attestation endpoint and asks whether a TEE app is safe, how strong its attestation and TLS binding are, whether the operator can still rug users, what DevProof stage it reaches, or what evidence is still missing.
---

# Check TEE Attestation

## Overview

Evaluate a TEE application from the user or auditor perspective, not the operator perspective. Decide whether the deployment is merely security-looking or actually approaches DevProof by checking live attestation evidence, TLS binding, repo auditability, reproducibility, operator-controlled configuration, and upgrade transparency.

## Quick Start

1. Normalize the target.
If the user gives a GitHub URL, clone it before running checks.
If the user gives a website, also ask for or discover an attestation endpoint, app ID, or dstack 8090 endpoint when possible.

2. Run the bundled checker.

```bash
python scripts/check_tee_attestation.py --repo /path/to/repo --url https://target.example
```

Useful variants:

```bash
python scripts/check_tee_attestation.py --repo https://github.com/org/repo --url https://app.example
python scripts/check_tee_attestation.py --repo /path/to/repo --url https://app.example --attestation-url https://app.example/v1/attestation/report
python scripts/check_tee_attestation.py --repo /path/to/repo --url https://<app-id>-443.dstack-pha-prod9.phala.network --format json
```

3. Read the result as an auditor, not a scanner operator.
The script gives a verdict, score, stage estimate, blockers, and evidence. Treat `Stage 1 candidate` as evidence-supported, not as a substitute for full manual review.

4. Follow up with manual checks when the live target matters.
Use [references/live-checks.md](./references/live-checks.md) for 8090 endpoint handling, attestation endpoint discovery, TLS fingerprint matching, and dstack-specific website patterns.

## Workflow

### 1. Establish the trust question

Answer the user's actual question in this form:

- What code is the website claiming to run?
- Can an external auditor verify that claim from public evidence?
- Is the website's TLS endpoint bound to attested code, or only to a conventional certificate?
- Can the operator still change behavior with `allowed_envs`, mutable URLs, mutable image refs, or instant upgrades?
- Does the evidence only support Stage 0 security, or does it approach Stage 1 DevProof?

### 2. Check both sides of the system

Do not stop at repo review. A TEE app can have clean source and still be ruggable in deployment.

- Repo side: source availability, Dockerfiles, compose files, lockfiles, CI reproducibility flags, attestation logic, AppAuth or timelock code, secret or URL injection paths.
- Website side: TLS certificate, live headers, attestation endpoint, dstack 8090 metadata, compose hash evidence, certificate fingerprint binding, obvious gateway patterns.

### 3. Distinguish security from DevProof

Use [references/devproof-stages.md](./references/devproof-stages.md) for the actual bar.

- If you can see live attestation but the operator can still swap URLs, image digests, secrets, or upgrades, classify it as `Stage 0`, not `Stage 1`.
- If reproducibility or upgrade transparency is missing, the app is not DevProof even when Trust Center is green.
- If the website has TLS but no attested TLS or gateway proof, say so explicitly.

### 4. Treat missing evidence as a real gap

Do not silently assume that "probably hardcoded" or "likely public" is good enough.

- If the repo is unavailable or incomplete, mark auditability down.
- If the live website exposes no attestation evidence, mark attestation down.
- If you cannot link the website certificate to attested code, mark TLS binding as partial or failed.
- If upgrades are opaque, say the app remains operator-trusted.

### 5. Produce an auditor-style answer

Always report:

- `Verdict`: safe, partially safe, or not safe to trust under the DevProof model
- `Stage`: unproven, Stage 0, or Stage 1 candidate
- `Score`: weighted trust score from the checker
- `Critical blockers`: the concrete reasons the app falls short
- `Evidence`: direct repo paths, live endpoints, cert facts, or compose-hash facts
- `Next step`: the shortest path to upgrade the app's trust model

Use [references/report-template.md](./references/report-template.md) if you need a longer audit note.

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
