# Claude Quickstart (check-tee-attestation)

Paste this entire file into Claude. Then fill in the Target Info section and ask Claude to output the JSON entry + run command.

## What Claude Should Do

- Produce a single valid `live_targets.json` entry for the target
- Provide the exact local command to run
- List the 4 report sections to read first (Verdict, Critical Blockers, Evidence, Next Step)
- If `repo_commit` is short, note that the runner will resolve it after fetching full history

## Target Info (fill in)

- name: <name>
- repo_url or repo: <repo URL or local path>
- repo_commit: <short or full SHA, optional>
- url: <live app URL>
- attestation_url: <attestation URL, optional>
- repo_branch: <only if non-default>
- repo_subdir: <only if app is in a subfolder>

## Constraints

- Do not invent fields not listed above.
- Keep the JSON entry minimal unless extra fields are explicitly given.
- If the user provides `repo_commit`, include it in the entry.
- If `attestation_url` is missing, suggest it but do not fabricate it.

## Output Format Required

1) `live_targets.json` entry (JSON only)
2) Run command
3) Report quick-read checklist (4 items)

## Example Output (structure only)

```json
{ "name": "example", "repo_url": "https://github.com/org/repo", "url": "https://example.com" }
```

Command:
```
python tools/skills/check-tee-attestation/scripts/run_live_targets_report.py
```

Checklist:
- Verdict
- Critical Blockers
- Evidence
- Next Step
