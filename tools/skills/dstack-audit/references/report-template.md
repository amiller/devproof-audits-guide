# [Project Name] dstack Audit Report

**Project**: [URL]
**Date**: [Date]
**Auditor**: [Name]

## Executive Summary

[2-3 sentence summary of findings]

| Component | Status | Notes |
|-----------|--------|-------|
| Configuration Control | ✅/⚠️/❌ | [Brief note] |
| Attestation Verification | ✅/⚠️/❌ | [Brief note] |
| Build Reproducibility | ✅/⚠️/❌ | [Brief note] |
| Data Storage | ✅/⚠️/❌ | [Brief note] |
| Smart Contracts | ✅/⚠️/❌/N/A | [Brief note] |

**Legend**: ✅ Verified | ⚠️ Concerns | ❌ Failed | N/A Not Applicable

---

## Deployment Data

| Field | Value | Verified |
|-------|-------|----------|
| App ID | `xxx` | ✅/❌ |
| Compose Hash | `xxx` | ✅/❌ |
| Docker Image | `xxx@sha256:xxx` | ✅/❌ |
| Source Commit | `xxx` | ✅/❌ |

---

## Critical Issues

### 1. [Issue Title]

**Severity**: CRITICAL
**File**: `path/to/file.py:line`

**Problem**:
[Description of the vulnerability]

**Code**:
```python
# Vulnerable code snippet
```

**Attack Vector**:
[How an attacker/operator could exploit this]

**Impact**:
[What's compromised - data exfiltration, integrity, etc.]

**Recommendation**:
[Specific fix]

---

## High Priority Issues

### 2. [Issue Title]

**Severity**: HIGH
**File**: `path/to/file.py:line`

[Same format as Critical]

---

## Medium Priority Issues

### 3. [Issue Title]

**Severity**: MEDIUM
**File**: `path/to/file.py:line`

[Same format]

---

## What's Done Well

- [Positive finding 1]
- [Positive finding 2]
- [Positive finding 3]

---

## Data Flow Diagram

```
User → [Entry Point] → [Processing]
                           ↓
                    [External Service] ← ⚠️ [TRUST BOUNDARY]
                           ↓
                      [Storage]
```

[Annotate with trust boundaries and configurable endpoints]

---

## Trust Model Analysis

| Component | Trusted By | Protects Against | Does NOT Protect Against |
|-----------|------------|------------------|--------------------------|
| TEE (TDX) | User | Cloud provider | Operator |
| dstack | User | Side channels | Malicious compose |
| [Service] | Code | [What] | [What] |

---

## Verification Checklist

| Check | Status | Evidence |
|-------|--------|----------|
| Source code public | ✅/❌ | [Link] |
| Docker image public | ✅/❌ | [Link] |
| Build reproducible | ✅/❌ | [How verified] |
| Critical URLs hardcoded | ✅/❌ | [Which file] |
| Attestation at startup | ✅/❌ | [Code location] |
| Per-request verification | ✅/❌ | [Code location] |
| Secrets in KMS | ✅/❌ | [How] |
| Contracts verified | ✅/❌/N/A | [Explorer link] |

---

## Recommendations

### Immediate (Critical)

1. [Action item with specific file/line changes]

### High Priority

2. [Action item]
3. [Action item]

### Medium Priority

4. [Action item]
5. [Action item]

---

## Open Questions

- [Question for project team]
- [Clarification needed]

---

## Appendix: Files Reviewed

| File | Purpose | Concerns |
|------|---------|----------|
| `src/main.py` | Entry point | None |
| `src/config.py` | Settings | URL configurable |
| `docker-compose.yml` | Deployment | [Issue] |
