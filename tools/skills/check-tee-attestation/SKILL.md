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

## Live Targets Report (Batch)

Use the batch runner when you need a full case-studies report across multiple targets.

Run:

```bash
python scripts/run_live_targets_report.py
```

Inputs:
- `scripts/live_targets.json` defines targets, repos, URLs, and attestation endpoints.

Outputs:
- `case-studies-live-report-YYYY-MM-DD.md` at repo root.

If a target fails, the report will include:
- `commit resolution log` for repo checkout issues
- `Run status: failed` with error details

## Commit Resolution Rules (How to Check)

When a target pins `repo_commit` as a short SHA:
- The runner must fetch full history and all branches before resolving.
- Resolution happens locally via `git rev-parse <prefix>^{commit}`.
- If resolution fails, the report must include a `commit resolution log`.

Checklist:
- If the report says `commit checkout failed`, verify the log includes:
  - `short commit provided; resolving locally after fetching history`
  - `fetched full history (unshallow)` or `fetched full history (deep fetch)`
  - `resolved commit prefix ...` (or an explicit failure reason)
- If the log does not include these, the runner used an outdated script or did not fetch all branches.

## Workflow (7 Phases)

1. Threat model and trust claims.
2. Attestation evidence collection (8090, Trust Center, Cloud API).
3. Quote verification (dcap-qvl/manual parsing; compose_hash vs mr_config_id).
4. TLS binding check (passthrough vs gateway; certFingerprint).
5. Code audit for operator gap (allowed_envs, ${VAR} URLs, image pinning, KMS).
6. Cross-reference deployed compose vs source.
7. Evidence archiving for audit history.

## Step-by-Step Checks (What to Verify)

1. Repo identity
   - Confirm the repo URL or local path is correct.
   - If using `repo_commit`, ensure it can be resolved to a full SHA.

2. Live endpoint reachability
   - `url` returns a valid HTTP response.
   - If it fails (SSL EOF / timeout), treat results as inconclusive.

3. Attestation presence and integrity
   - 8090 or explicit attestation endpoint responds.
   - Extract `app_compose` and verify `compose_hash`.

4. TLS binding
   - Fetch live cert fingerprint.
   - Compare to attested fingerprint or report_data.

5. Source-to-image linkage
   - Identify deployed image digest from `app_compose`.
   - Rebuild and compare digest.
   - If rebuild fails, capture the exact error and reason.

6. Operator gap detection
   - Search for `${VAR}` indirection in images/URLs.
   - Check `allowed_envs` for secrets, URLs, or image selectors.

7. Upgrade transparency
   - Look for public changelogs, on-chain releases, or trust center logs.
   - If missing, mark as a gap.

## Troubleshooting Common Failures

Commit checkout failed:
- Ensure full history and all branches are fetched.
- Confirm the short SHA exists in remote history.
- If the repo uses non-default branches, fetch `refs/heads/*`.

Rebuild failure due to external fetch:
- Check build args or envs (e.g., version variables for tarball URLs).
- Missing versions often cause 404 downloads and gzip errors.

No deployed image digest found:
- The live `app_compose` likely omits image digests.
- Mark reproducibility as unverifiable and note the gap.

## User-Friendly Usage (Detailed)

### A. Minimal inputs (what users must provide)

Required:
- `name`: human-friendly target name
- `repo_url` or `repo`: GitHub URL or local path
- `url`: live application URL

Strongly recommended:
- `attestation_url`: 8090 endpoint or explicit attestation report
- `repo_commit`: short or full SHA from deployed evidence

Optional:
- `repo_branch`: only when the repo uses a non-default branch
- `repo_subdir`: if the deployable app is in a subfolder
- `repo_urls`: list of repos; the runner uses the first entry
- `trust_center_url`, `notes`, `source_files`: documentation only

### B. Minimal target example

```json
{
  "name": "example-app",
  "repo_url": "https://github.com/org/repo",
  "repo_commit": "1a2b3c4",
  "url": "https://example.com",
  "attestation_url": "https://<app-id>-8090.dstack-pha-prod9.phala.network/"
}
```

### C. Quick run (single target)

1. Add the target to `scripts/live_targets.json`.
2. Run:

```bash
python scripts/run_live_targets_report.py
```

3. Open the generated report:
`case-studies-live-report-YYYY-MM-DD.md`

### D. How to read the report (fast path)

Only four sections are needed for a quick judgment:
- `Verdict`
- `Critical Blockers`
- `Evidence`
- `Next Step`

If `Run status: failed`, do not trust the rest of that target's output.

### E. Output expectations (for consistency)

The report must:
- Show `commit resolution log` when checkout fails.
- Use a short evidence list (<= 4 items per category).
- Avoid duplicating full build logs in both `Critical Blockers` and `Evidence`.
- Record live fetch outcomes and errors clearly.

### F. Common errors and user guidance

`commit checkout failed`
- Means the commit could not be resolved after fetching full history.
- Check that the commit exists on a remote branch or tag.

`UNEXPECTED_EOF_WHILE_READING`
- Live endpoint TLS handshake failed.
- Mark endpoint health and TLS binding as failed or skipped.

`rebuild skipped: no deployed image digest found`
- The live app_compose omits image digests.
- Mark reproducibility as unverifiable.

`rebuild digest mismatches`
- Rebuild succeeded but digest does not match deployed image.
- Treat reproducibility as failed, ask for pinned builds or reproducible build docs.

### G. Environment prerequisites

Before running:
- `git` must be available
- `docker` with `buildx` should be available for reproducibility checks
- outbound HTTPS access to GitHub and target URLs

If any prerequisite is missing, record it explicitly to avoid false negatives.

### H. Operator gap quick checks

Red flags:
- Image references like `image: repo:${VAR}@${DIGEST}`
- Any URL or image selector in `allowed_envs`
- KMS IDs or key-provider IDs in operator-controlled envs

If any red flag appears, the result is at best `Stage 0` (PARTIAL).

### I. Transparency quick checks

Mark `Upgrade transparency` as PASS only if:
- Deployments are publicly logged (changelog, on-chain, or trust center history)
- Image digests are pinned and traceable across releases

Otherwise mark as FAIL with a short explanation.

## Use This Skill Inside Claude (Copy/Paste Workflow)

Claude cannot run local scripts. The easiest workflow is:
1. Paste the instructions below into Claude.
2. Provide target info (repo/url/attestation/commit).
3. Ask Claude to output the exact `live_targets.json` entry and the run command.
4. Run the command locally and share the report back if you want Claude to interpret it.

### Claude Prompt Template (Minimal)

```text
You are an audit assistant. Follow the skill rules below exactly and produce actionable steps only.

[PASTE: "User-Friendly Usage (Detailed)" section]

Target info:
- name: <name>
- repo_url or repo: <repo>
- repo_commit: <short or full SHA, if known>
- url: <live URL>
- attestation_url: <attestation URL, if known>
- repo_branch/repo_subdir: <only if needed>

Output:
1) The exact `live_targets.json` entry
2) The command to run locally
3) Which report sections to read first
```

### Claude Prompt Template (Detailed)

```text
You are an audit assistant. Use the skill rules below to build a complete audit plan.

[PASTE: "User-Friendly Usage (Detailed)" section]

Target info:
- name: <name>
- repo_url or repo: <repo>
- repo_commit: <short or full SHA, if known>
- url: <live URL>
- attestation_url: <attestation URL, if known>
- repo_branch/repo_subdir: <only if needed>
- notes/trust_center_url/source_files: <optional>

Tasks:
1) Provide the minimal valid `live_targets.json` entry
2) Provide the full entry with optional fields if available
3) Provide the local run command
4) Provide a short checklist of how to read the report
5) Provide troubleshooting steps if `commit checkout failed`
```

## Agent Mode (Tool-Enabled Clients)

If the client can run local commands and access the network, use the dedicated agent runner.

See `AGENT.md` for the full contract and requirements.

Quick run:

```bash
python scripts/agent_run.py <<'JSON'
{ "targets": [ { "name": "example-app", "repo_url": "https://github.com/org/repo", "url": "https://example.com" } ] }
JSON
```

## Verification Checklist (Strict Chain)

Use a strict chain: Source -> Build -> Image -> Compose/App-compose -> Attestation -> TLS -> Transparency.

For each target, explicitly answer the prompts below in the report. If any step cannot be verified, say "unverified" and explain why.
Record the date/time of each live fetch in your notes (local time is fine).

### A. Identify the exact deployment

Prompt to answer:
- App ID / instance ID?
- Live URL?
- Attestation endpoint (8090 or app-specific)?
- Trust Center / Cloud API / on-chain links?

How to check:
- Use the provided live URL, attestation URL, and trust center link.
- If only a custom domain is given, resolve _dstack-app-address to find the 8090 endpoint.

### B. Verify attestation exists and is valid

Prompt to answer:
- Did you fetch 8090 metadata or the official attestation endpoint?
- Is a real quote or measurements present (not empty/dev)?
- Does compose_hash match the app_compose you fetched?
- Was quote signature verified (dcap-qvl or trusted verifier)?

How to check:
- Fetch 8090 or app attestation endpoint; extract app_compose.
- Compute compose_hash from app_compose and compare.
- If possible, verify the quote signature. If not, mark unverified.

### C. Verify TLS binding

Prompt to answer:
- What is the live TLS certificate fingerprint?
- Does it match the attested cert fingerprint or report_data binding?
- If TLS terminates at a gateway, what is the trust boundary?

How to check:
- Fetch the live TLS cert and compute sha256 fingerprint.
- Compare to attested fingerprint (or report_data binding) from attestation payload.
- If a gateway is involved, explicitly state what is attested (gateway vs app).

### D. Verify source -> image

Prompt to answer:
- What exact commit is used for deployment?
- What is the deployed image digest (must be @sha256 in app_compose)?
- Does a local rebuild match that digest?
- If rebuild fails, what is the exact failure reason?

How to check:
- Checkout the exact commit used for deployment (tag/commit from app_compose or evidence).
- Extract deployed image digest from app_compose.
- Rebuild with buildx and compare digest; if it fails, capture the error.

### E. Operator-gap checks

Prompt to answer:
- Are any URLs or image refs in allowed_envs?
- Are there any image: ${VAR} entries where VAR is in allowed_envs?

How to check:
- Scan app_compose for allowed_envs.
- Any URL/image in allowed_envs => operator can steer data or swap code.
- Any image: ${VAR} with VAR in allowed_envs => deployment is unverifiable to third parties.

### F. Upgrade transparency

Prompt to answer:
- Are upgrades publicly logged (on-chain or public release history)?
- If not, what is the transparency gap?

How to check:
- Look for on-chain upgrade events, public changelog, or pinned digest history.
- If none, mark as a gap.

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
