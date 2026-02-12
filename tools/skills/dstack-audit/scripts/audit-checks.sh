#!/usr/bin/env bash
# dstack TEE Application Audit - Automated Checks
# Usage: ./audit-checks.sh /path/to/repo
#
# Requires: grep (standard) or ripgrep (rg) for better results
# Note: When using with Claude Code, prefer using the Grep tool directly

set -euo pipefail

REPO_PATH="${1:-.}"
cd "$REPO_PATH"

echo "=========================================="
echo "dstack Audit: $(basename "$PWD")"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Use ripgrep if available, otherwise fall back to grep
if command -v rg &>/dev/null; then
    RG="rg"
elif [[ -x "/home/amiller/.nvm/versions/node/v23.4.0/lib/node_modules/@anthropic-ai/claude-code/vendor/ripgrep/x64-linux/rg" ]]; then
    RG="/home/amiller/.nvm/versions/node/v23.4.0/lib/node_modules/@anthropic-ai/claude-code/vendor/ripgrep/x64-linux/rg"
else
    RG=""
fi

section() {
    echo ""
    echo "## $1"
    echo "---"
}

warn() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

critical() {
    echo -e "${RED}🚨 $1${NC}"
}

ok() {
    echo -e "${GREEN}✅ $1${NC}"
}

info() {
    echo "   $1"
}

# Exclusion patterns for minified/bundled files
RG_EXCLUDES="--glob '!**/*.min.js' --glob '!**/bundle.js' --glob '!**/entry.js' --glob '!**/vendor.js' --glob '!**/dist/**' --glob '!**/build/**' --glob '!**/node_modules/**' --glob '!**/*.bundle.js' --glob '!**/chunk-*.js' --glob '!**/*.chunk.js'"
GREP_EXCLUDES="--exclude='*.min.js' --exclude='bundle.js' --exclude='entry.js' --exclude='vendor.js' --exclude='*.bundle.js' --exclude-dir='dist' --exclude-dir='build' --exclude-dir='node_modules'"

# Search function that uses rg if available, grep otherwise
search_code() {
    local pattern="$1"
    local show_lines="${2:-false}"

    if [[ -n "$RG" ]]; then
        if [[ "$show_lines" == "true" ]]; then
            eval "$RG" -n -i "\"$pattern\"" --glob "'**/*.py'" --glob "'**/*.ts'" --glob "'**/*.js'" $RG_EXCLUDES 2>/dev/null || true
        else
            eval "$RG" -l -i "\"$pattern\"" --glob "'**/*.py'" --glob "'**/*.ts'" --glob "'**/*.js'" $RG_EXCLUDES 2>/dev/null || true
        fi
    else
        if [[ "$show_lines" == "true" ]]; then
            eval grep -rn -i "\"$pattern\"" --include="'*.py'" --include="'*.ts'" --include="'*.js'" $GREP_EXCLUDES . 2>/dev/null || true
        else
            eval grep -rl -i "\"$pattern\"" --include="'*.py'" --include="'*.ts'" --include="'*.js'" $GREP_EXCLUDES . 2>/dev/null || true
        fi
    fi
}

search_code_exact() {
    local pattern="$1"
    local show_lines="${2:-false}"

    if [[ -n "$RG" ]]; then
        if [[ "$show_lines" == "true" ]]; then
            eval "$RG" -n "\"$pattern\"" --glob "'**/*.py'" --glob "'**/*.ts'" --glob "'**/*.js'" $RG_EXCLUDES 2>/dev/null || true
        else
            eval "$RG" -l "\"$pattern\"" --glob "'**/*.py'" --glob "'**/*.ts'" --glob "'**/*.js'" $RG_EXCLUDES 2>/dev/null || true
        fi
    else
        if [[ "$show_lines" == "true" ]]; then
            eval grep -rn "\"$pattern\"" --include="'*.py'" --include="'*.ts'" --include="'*.js'" $GREP_EXCLUDES . 2>/dev/null || true
        else
            eval grep -rl "\"$pattern\"" --include="'*.py'" --include="'*.ts'" --include="'*.js'" $GREP_EXCLUDES . 2>/dev/null || true
        fi
    fi
}

# ============================================
section "1. CONFIGURATION CONTROL"
# ============================================

echo "### Configurable URLs in code:"
results=$(search_code 'base_url|api_url|endpoint|_url')
if [[ -n "$results" ]]; then
    echo "$results" | head -10
    search_code 'base_url|api_url|endpoint|_url' true | head -20
    warn "Found configurable URLs - verify these are hardcoded in docker-compose.yml"
else
    ok "No obvious configurable URLs found"
fi

echo ""
echo "### Environment variable loading:"
results=$(search_code 'BaseSettings|pydantic_settings|environ|getenv|process\.env|dotenv')
if [[ -n "$results" ]]; then
    echo "$results" | head -10
    search_code 'BaseSettings|pydantic_settings|environ|getenv|process\.env|dotenv' true | head -20
    warn "Environment loading detected - check what's configurable"
else
    ok "No environment loading patterns found"
fi

echo ""
echo "### docker-compose.yml environment:"
if [[ -f docker-compose.yml ]]; then
    echo "Variables using \${VAR} syntax (operator-configurable):"
    grep -E '\$\{.*\}|\$[A-Z_]+' docker-compose.yml 2>/dev/null | head -20 || echo "   None found"
    echo ""
    echo "Hardcoded values:"
    grep -E '^\s*-\s+[A-Z_]+=https?://' docker-compose.yml 2>/dev/null | head -10 || echo "   None found"
else
    warn "No docker-compose.yml found"
fi

# ============================================
section "2. EXTERNAL NETWORK CALLS"
# ============================================

echo "### HTTP clients in use:"
results=$(search_code_exact 'httpx|requests\.|aiohttp|fetch\(|axios|AsyncOpenAI|OpenAI')
if [[ -n "$results" ]]; then
    echo "$results" | head -10
else
    echo "   None found"
fi

echo ""
echo "### External API calls (https:// URLs):"
results=$(search_code_exact 'https?://')
if [[ -n "$results" ]]; then
    search_code_exact 'https?://' true | grep -v '^\s*#' | head -20
else
    echo "   None found"
fi

# ============================================
section "3. ATTESTATION/VERIFICATION CODE"
# ============================================

echo "### Attestation-related code:"
results=$(search_code 'attestation|verify.*quote|tdx|report_data|intel_quote')
if [[ -n "$results" ]]; then
    echo "$results" | head -10
    ok "Attestation code found - review implementation"
else
    warn "No attestation code found"
fi

echo ""
echo "### Signature verification:"
results=$(search_code_exact 'recover_message|verify_signature|ecdsa|secp256k1|eth_account')
if [[ -n "$results" ]]; then
    echo "$results" | head -10
    ok "Signature verification found - review implementation"
else
    info "No signature verification found"
fi

# ============================================
section "4. RED FLAGS"
# ============================================

echo "### 'Known issue' or workaround comments:"
results=$(search_code 'known issue|known bug|workaround')
if [[ -n "$results" ]]; then
    search_code 'known issue|known bug|workaround' true | head -10
    critical "Found 'known issue' comments - review carefully"
else
    ok "No 'known issue' comments found"
fi

echo ""
echo "### Hash mismatch acceptance:"
results=$(search_code 'mismatch|ignore.*hash|skip.*verif|bypass')
if [[ -n "$results" ]]; then
    search_code 'mismatch|ignore.*hash|skip.*verif|bypass' true | head -10
    critical "Potential hash mismatch acceptance found"
else
    ok "No obvious hash mismatch acceptance"
fi

echo ""
echo "### Development fallbacks:"
results=$(search_code_exact 'dev_mode|development_mode|_dev_|fallback|mock_|fake_|stub_')
if [[ -n "$results" ]]; then
    search_code_exact 'dev_mode|development_mode|_dev_|fallback|mock_|fake_|stub_' true | head -10
    warn "Development fallbacks found - verify not reachable in production"
else
    ok "No development fallbacks found"
fi

echo ""
echo "### Disabled verification:"
results=$(search_code_exact 'verify.*=.*False|skip.*verify|no.*verify|disable.*check')
if [[ -n "$results" ]]; then
    search_code_exact 'verify.*=.*False|skip.*verify|no.*verify|disable.*check' true | head -10
    critical "Potentially disabled verification found"
else
    ok "No disabled verification flags found"
fi

# ============================================
section "5. BUILD REPRODUCIBILITY"
# ============================================

echo "### Dockerfile analysis:"
for df in Dockerfile Dockerfile.*; do
    [[ -f "$df" ]] || continue
    echo "File: $df"

    # Check for pinned base image
    if grep -E '^FROM.*@sha256:' "$df" >/dev/null 2>&1; then
        ok "Base image pinned by digest"
    else
        warn "Base image NOT pinned by digest"
    fi

    # Check for SOURCE_DATE_EPOCH
    if grep -q 'SOURCE_DATE_EPOCH' "$df" 2>/dev/null; then
        ok "SOURCE_DATE_EPOCH set"
    else
        warn "SOURCE_DATE_EPOCH not set"
    fi

    # Check for apt-get update
    if grep -q 'apt-get update' "$df" 2>/dev/null; then
        warn "apt-get update without snapshot pinning"
    fi
    echo ""
done

echo "### CI/CD reproducibility:"
if [[ -d .github/workflows ]]; then
    if grep -rl 'rewrite-timestamp\|SOURCE_DATE_EPOCH' .github/workflows/ 2>/dev/null; then
        ok "Reproducibility flags found in CI"
    else
        warn "No reproducibility flags in CI workflows"
    fi
else
    info "No GitHub workflows found"
fi

# ============================================
section "6. SECRETS/STORAGE"
# ============================================

echo "### Secret-related code:"
results=$(search_code 'secret|api_key|token|password|credential')
if [[ -n "$results" ]]; then
    search_code 'secret|api_key|token|password|credential' true | grep -v 'test\|mock\|example' | head -15
else
    echo "   None found"
fi

echo ""
echo "### Storage/persistence:"
results=$(search_code_exact 'database|sqlite|postgres|redis|persist|save.*file')
if [[ -n "$results" ]]; then
    search_code_exact 'database|sqlite|postgres|redis|persist|save.*file' true | head -10
else
    echo "   None found"
fi

# ============================================
section "7. SMART CONTRACTS"
# ============================================

echo "### Contract addresses:"
if [[ -n "$RG" ]]; then
    eval "$RG" -on "'0x[a-fA-F0-9]{40}'" --glob "'**/*.py'" --glob "'**/*.ts'" --glob "'**/*.js'" --glob "'**/*.json'" $RG_EXCLUDES --glob "'!**/package-lock.json'" 2>/dev/null | head -10 || echo "   None found"
else
    eval grep -ron "'0x[a-fA-F0-9]\{40\}'" --include="'*.py'" --include="'*.ts'" --include="'*.js'" --include="'*.json'" $GREP_EXCLUDES --exclude="'package-lock.json'" . 2>/dev/null | head -10 || echo "   None found"
fi

# ============================================
section "SUMMARY"
# ============================================

echo ""
echo "Manual review required for:"
echo "1. Verify each configurable URL is appropriate"
echo "2. Check attestation binding (signing key ↔ TDX quote)"
echo "3. Review any 'known issue' comments"
echo "4. Trace user data flow to external services"
echo "5. Verify docker-compose.yml hardcodes critical URLs"
echo ""
echo "=========================================="
