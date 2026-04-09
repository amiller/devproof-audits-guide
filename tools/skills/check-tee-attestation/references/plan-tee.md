# Best-Practice TEE / DevProof Audit Plan (synthesized from hermes + is-this-real-tea + devproof-audits-guide)

This plan targets third-party audits: verify whether a TEE app truly prevents the developer or operator from misbehaving, not merely "running inside a TEE." The core goal is to prove the operator gap is closed: can the operator still exfiltrate user data through config, upgrades, or backdoors?

---

## 1. Goals and Principles

- Goal: produce a verifiable, reproducible conclusion that answers: "Can the operator steal data, keys, or upgrade without notice?"
- Principles:
- Trust only hard evidence chains: source code -> build artifacts -> deployment config -> hardware proof.
- Do not trust self-claims: in-app `/attestation` is only a reference; key evidence must come from 8090, Trust Center, or on-chain records.
- Center on the operator gap: can `allowed_envs`, variable images, or configurable URLs enable data exfiltration?
- Audit present state and historical traceability: not only "safe now," but also "safe in the past."

---

## 2. Inputs and Evidence Checklist

- Required:
- GitHub URL or local source path
- Deployment URL (or `app_id` + `cluster`)
- Optional but strongly recommended:
- 8090 snapshot: `https://{app_id}-8090.{cluster}.phala.network/`
- Trust Center: `https://trust.phala.com/app/{app_id}`
- Cloud API attestation: `https://cloud-api.phala.network/api/v1/apps/{app_id}/attestations`
- App `/attestation` response (for TLS binding)
- Evidence snapshots (`quote.json`, `metadata`, TLS cert PEM, `sha256sum`)

---

## 3. Fast Triage (5 minutes)

If any of the following is true, immediately classify as Stage 0 (operator can misbehave) and proceed to deep audit:

1. No TDX quote from 8090 (`--dev-os`)
2. `${VAR}` controls URLs or images in `docker_compose_file`
3. Images are not pinned by `@sha256:`
4. KMS is Pha KMS and there is no on-chain AppAuth or timelock
5. TLS is not passthrough (443s), so end-to-end binding is impossible

---

## 4. Full Audit Flow (recommended 7 phases)

### Phase 0: Threat Model and Scope

- Clarify security claims (e.g., "operator cannot see private keys or unpublished content")
- Define data paths and confidentiality boundaries (inside TEE / outside TEE)
- Identify hosting model (self-hosted vs platform-hosted like Phala/dstack)

### Phase 1: Independent Attestation Evidence

1. Resolve `app_id` + `cluster` from the deployment URL
2. Fetch 8090 metadata and parse `app_compose` (ground truth)
3. Compute `compose_hash` (SHA256 of canonical JSON)
4. Fetch Cloud API for `quote` / `event_log` / `vm_config`
5. Fetch Trust Center as secondary attestation evidence

Key outputs:
- `app_compose` (includes `docker_compose_file`, `allowed_envs`, `kms_enabled`, `pre_launch_script`)
- `compose_hash`
- `quote_hex` + RTMR / MR* fields

### Phase 2: Hardware Proof Verification

- Verify the TDX quote signature with dcap-qvl
- If unavailable, fall back to manual parsing (extract fields only, no signature verification)
- Check whether `compose_hash` matches `mr_config_id`
- If `report_data` exists, validate bindings (e.g., TLS cert fingerprint)
- If available, replay event logs with `dstack-verifier`

### Phase 3: TLS Binding and Domain Trust Model

- Determine if the URL is TLS passthrough (443s)
- If passthrough:
- Capture the live TLS cert fingerprint
- Compare to `/attestation` `certFingerprint`
- If a custom domain is used:
- Resolve `_dstack-app-address` TXT records
- Recommend CT monitoring (Certspotter / crt.sh)
- Explain trust boundary: browsers rely on CT; SDKs should use attested TLS

### Phase 4: Source Audit (operator gap core)

Trace data flow line-by-line:

- Configurable URLs:
- Search `${VAR}` in `docker-compose.yml` / `app_compose`
- Cross-check `allowed_envs` to find operator-controlled URLs
- If the URL handles user data -> high risk

- External network calls:
- Find `fetch` / `axios` / `requests` usage
- Identify user data in each outgoing request

- Attestation enforcement:
- Is attestation only logged without blocking execution?
- Are known issues or mismatches ignored?

- Keys and KMS:
- Is `deriveKey` used inside the TEE?
- Any hardcoded fallback?
- Can keys be injected via env vars?

- Build reproducibility:
- Is base image pinned by digest?
- `SOURCE_DATE_EPOCH` / timestamp normalization present?
- Lockfiles complete?

- Upgrades and governance:
- AppAuth / on-chain compose registry enabled?
- Timelock enforced?
- `DEPLOYMENTS.md` or on-chain history present?

### Phase 5: Deploy Config vs Source Cross-Check

- Compare 8090 `docker_compose_file` with repo compose files
- Are image refs pinned by digest?
- Are there `${IMAGE_VAR}` + `allowed_envs` blind spots?
- Map image tags to the exact deployed commit (do not audit `HEAD`)

### Phase 6: DevProof Stage Decision (ERC-733)

Stage 0 triggers (any = fail):
- No TDX quote
- Operator-configurable data channel (URL/endpoint)
- Images not pinned by digest
- No on-chain transparent upgrade

Stage 1 must satisfy all:
- On-chain KMS + AppAuth
- Image digest pinned
- No exfiltration vector
- TLS binding verified
- Reproducible builds
- Upgrade timelock

### Phase 7: Report and Evidence Archiving

- Report must include:
- Executive Summary
- Key questions table (operator gap / attestation / reproducibility / data flow / upgrades)
- Critical Findings (with file:line and reproduction steps)
- Trust Boundary diagram
- "What is guaranteed / not guaranteed"
- Unverified parts (and why)

- Evidence snapshot suggestions:
- `evidences/YYYY-MM-DD/metadata.json`
- `quote.json`, `cert.pem`, `sha256sum.txt`, `deploy-info.json`
- Keep in git for audit history

---

## 5. Best-Practice Summary (synthesized from the three repos)

- The operator gap is the #1 risk: any configurable URL can become an exfiltration channel.
- 8090 is the only trusted source for third-party audits; in-app `/attestation` is insufficient.
- On-chain transparency logs are the core of DevProof: Pha KMS can only prove "now," not "the past."
- Image digest pinning is the minimum bar: tags can be overwritten.
- Reproducible builds determine whether "source is auditable" is actually true.
- Custom domains are not a vulnerability by themselves, but require CT monitoring + attested TLS.
- Evidence must be durable: overwriting `/evidences` is a common blind spot.

---

## 6. Reusable Checklist (condensed)

1. 8090 provides `app_compose` + quote
2. `compose_hash` matches `mr_config_id`
3. No `${VAR}` controls URLs or images in `docker_compose_file`
4. Images are pinned by `@sha256:`
5. KMS is Base/on-chain; AppAuth + timelock
6. TLS cert fingerprint matches attestation
7. Build is reproducible (pinned base + `SOURCE_DATE_EPOCH` + lockfiles)
8. No dev fallback or known-issue bypass
9. Data does not leave the TEE, or is encrypted before leaving
10. Upgrade history is recorded (on-chain or `DEPLOYMENTS.md`)

---

## 7. Suggested Output Format (template)

The final report must be in English.

### Plain-Language Version (no Stage terms)

Replace Stage language with a one-glance decision card focused on conclusion and reasons:

One-line conclusion: "Can the operator steal data? (Yes/No/Partially)" + one key reason.

Visual template (check matrix + red/yellow/green signal):

```
One-glance decision: Can/Can’t/Partially + key reason

| Key Question | Status | Signal | Evidence Summary |
|---|---|---|---|
| Can the operator exfiltrate data? | PASS / FAIL / PARTIAL | GREEN / RED / YELLOW | e.g., allowed_envs can alter URLs |
| Is hardware attestation real? | PASS / FAIL / PARTIAL | GREEN / RED / YELLOW | e.g., TDX quote verified |
| Is deployment reproducible? | PASS / FAIL / PARTIAL | GREEN / RED / YELLOW | e.g., image digest pinned |
| Does data leave the TEE? | PASS / FAIL / PARTIAL | GREEN / RED / YELLOW | e.g., external DB/LLM |
| Are upgrades traceable? | PASS / FAIL / PARTIAL | GREEN / RED / YELLOW | e.g., Base KMS + timelock |

Signal legend: GREEN = closed; YELLOW = partial/unknown; RED = exploitable path
```

```markdown
## Executive Summary

## Key Questions
| Question | Answer | Evidence |

## Critical Issues
- [Issue] (file:line)
- Exploit steps
- Impact
- Fix

## Architecture & Data Flow

## Attestation Analysis

## Build Reproducibility

## Upgrade Transparency

## Trust Boundaries

## What’s Done Well

## Verification Checklist

## Security Guarantees
### What’s protected
### What’s still possible
### What can’t be verified
```

---

## 8. Integration With Existing Tools

- Use the 6-phase pipeline in is-this-real-tea as the automation baseline
- Use the DevProof Stage 1 checklist for final judgment
- Use hermes’ evidence-chain closure method:
- Source commit -> CI digest -> compose_hash -> TDX quote -> Trust Center
- Archive each deployment in `evidences/`

---

## 9. Final Decision Standard

Only if all evidence chains are closed can you claim "the developer cannot misbehave":

1. Auditable code + reproducible builds
2. Image digest pinned + `compose_hash` matches quote
3. On-chain transparent upgrades + timelock
4. No operator-configurable data channels
5. End-to-end TLS bound to the TEE
6. Historical evidence is traceable (audit history)

Otherwise, default conclusion: Stage 0 (operator can misbehave).
