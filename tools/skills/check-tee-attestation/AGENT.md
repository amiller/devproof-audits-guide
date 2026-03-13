# Agent Mode (Tool-Enabled Clients)

This skill can be used end-to-end by agents that have **shell + network** access (e.g., Claude Code, Cursor agents, Codex).

## Required Capabilities

- Run local shell commands (`python`, `git`, `docker buildx`).
- Network access to GitHub and live URLs.
- Read/write local files.

## One-Command Usage (Agent)

Provide the target JSON via stdin and run:

```bash
python tools/skills/check-tee-attestation/scripts/agent_run.py <<'JSON'
{
  "targets": [
    {
      "name": "example-app",
      "repo_url": "https://github.com/org/repo",
      "repo_commit": "1a2b3c4",
      "url": "https://example.com",
      "attestation_url": "https://<app-id>-8090.dstack-pha-prod9.phala.network/"
    }
  ]
}
JSON
```

This will emit the generated report path (e.g., `case-studies-live-report-YYYY-MM-DD.md`).

## If the Agent Cannot Run Docker

Reproducibility checks may fail. The agent should:
- Note the missing prerequisites explicitly in the output it provides to the user.
- Treat reproducibility as inconclusive rather than a strong failure.

## Minimal Contract

Agent must output:
- The report file path
- Any `Run status: failed` entries with the error block
