# dstack Audit Plugin

Claude Code plugin for auditing dstack/Phala TEE applications.

## Codex Skill

This repo now also includes an installable Codex skill at `tools/skills/check-tee-attestation/`.

Use it when you want a single workflow that accepts a GitHub repo plus a deployed website and returns:

- whether the website is safe to trust under the dstack DevProof model
- what stage it reaches
- how strong the attestation and TLS binding are
- which repo or deployment gaps still block Stage 1

Example:

```bash
python tools/skills/check-tee-attestation/scripts/check_tee_attestation.py \
  --repo /path/to/repo \
  --url https://target.example
```

Local regression:

```bash
python tools/skills/check-tee-attestation/scripts/run_regression_cases.py
```

Live sample regression:

```bash
python tools/skills/check-tee-attestation/scripts/run_regression_cases.py \
  tools/skills/check-tee-attestation/scripts/live_regression_cases.json
```

## Installation

```bash
# Use the plugin from a directory
claude --plugin-dir /path/to/dstack-audit-plugin

# Or symlink to your plugins directory
ln -s /path/to/dstack-audit-plugin ~/.claude/plugins/dstack-audit
```

## Usage

### Command: `/audit`

Start an audit of a dstack application:

```
/audit                          # Audit current directory
/audit ./path/to/repo           # Audit specific path
/audit https://github.com/...   # Clone and audit
```

### Command: `/check-tee`

Check if a repo + website are safe to interact with under the DevProof model:

```
/check-tee repo=./path/to/repo url=https://app.example
/check-tee repo=https://github.com/org/repo url=https://app.example attestation_url=https://app.example/v1/attestation/report
```

### Skill: Auto-triggers

The skill automatically activates when you mention:
- "audit a dstack app"
- "audit TEE application"
- "check for operator exfiltration"
- "verify attestation binding"

### Manual Script

Run the automated checks directly:

```bash
./skills/dstack-audit/scripts/audit-checks.sh /path/to/repo
```

DevProof checker:

```bash
python tools/skills/check-tee-attestation/scripts/check_tee_attestation.py \
  --repo /path/to/repo \
  --url https://app.example \
  --attestation-url https://app.example/v1/attestation/report
```

## What It Checks

### Critical (Operator Exfiltration)
- Configurable URLs in code (base_url, api_url, endpoint)
- Environment variable loading patterns
- docker-compose.yml hardcoded vs variable URLs

### Attestation
- TDX quote verification code
- Signature verification implementation
- Binding between signing key and quote

### Red Flags
- "Known issue" comments
- Hash mismatch acceptance
- Development fallbacks
- Disabled verification flags

### Build Reproducibility
- Pinned base images
- SOURCE_DATE_EPOCH
- CI reproducibility flags

## Files

```
dstack-audit-plugin/
├── .claude-plugin/
│   └── plugin.json
├── commands/
│   └── audit.md              # /audit command
├── skills/
│   └── dstack-audit/
│       ├── SKILL.md          # Main skill
│       ├── references/
│       │   ├── checklist.md      # Full audit checklist
│       │   ├── report-template.md # Report format
│       │   └── search-patterns.md # Grep patterns
│       └── scripts/
│           └── audit-checks.sh   # Automated scanning
└── README.md
```

## Common Vulnerabilities Found

1. **Operator-configurable URLs** - URLs loaded from env vars that should be hardcoded
2. **Unverified attestation binding** - Signing key not extracted from TDX quote
3. **Hash mismatch acceptance** - "Known issue" comments bypassing verification
4. **Non-reproducible builds** - Missing SOURCE_DATE_EPOCH, unpinned images
5. **Development fallbacks** - Mock data reachable in production
