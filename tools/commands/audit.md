---
name: audit
description: Audit a dstack/Phala TEE application for security issues
arguments:
  - name: target
    description: Path to repo or GitHub URL to audit
    required: false
---

# dstack Security Audit

<dstack-audit>

Perform a comprehensive security audit of the specified dstack/Phala TEE application.

## Target

{{#if args.target}}
Audit target: `{{args.target}}`
{{else}}
Audit target: current directory
{{/if}}

## Instructions

1. **Clone/Access the Repository**
   {{#if args.target}}
   If `{{args.target}}` is a URL, clone it first. Otherwise, use it as the path.
   {{else}}
   Use the current working directory.
   {{/if}}

2. **Run Automated Checks**
   Execute the audit script from the dstack-audit skill:
   ```bash
   # From the plugin's scripts directory
   ./audit-checks.sh /path/to/repo
   ```

   Or use Grep tool with patterns from `references/search-patterns.md` in the dstack-audit skill.

3. **Focus on Critical Issues**

   **Most Important**: Check if URLs handling user data are operator-configurable.
   - Look for `*_URL`, `base_url`, `endpoint` in code
   - Verify they're HARDCODED in docker-compose.yml (not `${VAR}`)
   - This is the most common vulnerability pattern

4. **Manual Review**
   - Trace attestation verification code
   - Check for "known issue" comments near verification
   - Review development fallbacks
   - Analyze data flow to external services

5. **Generate Report**
   Use the template from `references/report-template.md` in the dstack-audit skill.

## Key Questions to Answer

1. **Can the operator exfiltrate user data?**
   - Are there configurable URLs that receive user content?

2. **Is attestation cryptographically verified?**
   - Is the signing key bound to the TDX quote?

3. **Can the build be reproduced?**
   - Are images pinned? Is SOURCE_DATE_EPOCH set?

4. **What trust assumptions exist?**
   - Which external services are trusted without verification?

</dstack-audit>
