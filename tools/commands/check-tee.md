---
name: check-tee
description: Check a TEE deployment's safety by analyzing a repo and website under the dstack DevProof model
arguments:
  - name: repo
    description: Local repo path or GitHub URL
    required: false
  - name: url
    description: Live website URL to verify
    required: false
  - name: attestation_url
    description: Optional attestation endpoint URL
    required: false
---

# Check TEE Attestation

<check-tee-attestation>

Evaluate a TEE deployment using the DevProof model and report if it is safe to interact with.

## Target

Repo: {{args.repo}}
Website: {{args.url}}
Attestation: {{args.attestation_url}}

## Instructions

1. If `repo` is a URL, clone it. If it's a path, use it directly.
2. Run the checker:

```bash
python tools/skills/check-tee-attestation/scripts/check_tee_attestation.py \
  --repo "{{args.repo}}" \
  --url "{{args.url}}" \
  --attestation-url "{{args.attestation_url}}" \
  --format markdown
```

3. Summarize the result as:
   - Verdict
   - Stage
   - Score
   - Critical blockers
   - Evidence

</check-tee-attestation>
