# dstack Audit Plugin

Claude Code plugin for auditing dstack/Phala TEE applications.

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
