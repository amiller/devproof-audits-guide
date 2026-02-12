# Search Patterns for dstack Audit

Use these patterns with the Grep tool to find common vulnerabilities.

## Configuration Control

### Find Configurable URLs

```
pattern: base_url|api_url|endpoint|_URL|_url
glob: *.py,*.ts,*.js
```

### Find Environment Loading

```
pattern: BaseSettings|environ|getenv|process\.env|dotenv
glob: *.py,*.ts,*.js
```

### Find pydantic Settings Classes

```
pattern: class.*Settings.*BaseSettings
glob: *.py
```

## External Network Calls

### Python HTTP Clients

```
pattern: httpx|requests\.|aiohttp|urllib\.request|http\.client
glob: *.py
```

### JavaScript/TypeScript HTTP

```
pattern: fetch\(|axios\.|http\.|https\.
glob: *.ts,*.js
```

### User Data in Requests

```
pattern: user_prompt|message|content|payload|body
glob: *.py,*.ts,*.js
```

## Attestation Code

### Find Attestation/Verification

```
pattern: attestation|verify|quote|report_data|tdx|sgx
glob: *.py,*.ts,*.js
```

### Find Signature Verification

```
pattern: recover_message|verify_signature|ecdsa|secp256k1|eth_account
glob: *.py,*.ts,*.js
```

### Find Hash Comparisons

```
pattern: hash.*==|==.*hash|computed.*expected|expected.*computed
glob: *.py,*.ts,*.js
```

## Red Flags

### Known Issue Comments

```
pattern: known issue|known bug|TODO.*fix|FIXME|workaround
glob: *.py,*.ts,*.js
```

### Hash Mismatch Acceptance

```
pattern: mismatch|ignore.*hash|skip.*verification|bypass
glob: *.py,*.ts,*.js
```

### Development Fallbacks

```
pattern: dev_mode|development_mode|fallback|mock|fake|stub
glob: *.py,*.ts,*.js
```

### Disabled Verification

```
pattern: verify.*=.*False|skip.*verify|no.*verify|disable.*check
glob: *.py,*.ts,*.js
```

## Docker/Build

### Unpinned Base Images

```
pattern: ^FROM.*:.*(?!@sha256)
glob: Dockerfile*
```

### Missing Reproducibility

```
pattern: SOURCE_DATE_EPOCH|rewrite-timestamp
glob: Dockerfile*,.github/**/*.yml
```

### apt-get Without Snapshot

```
pattern: apt-get update
glob: Dockerfile*
```

## Secrets/Storage

### Secret Handling

```
pattern: secret|key|token|password|credential|api_key
glob: *.py,*.ts,*.js,*.yml,*.yaml
```

### Database/Storage

```
pattern: database|sqlite|postgres|redis|storage|persist|save
glob: *.py,*.ts,*.js
```

## Smart Contracts

### Contract Addresses

```
pattern: 0x[a-fA-F0-9]{40}
glob: *.py,*.ts,*.js,*.json
```

### On-chain Verification

```
pattern: compose_hash|app_id|authorized|allowlist
glob: *.py,*.ts,*.js
```

## docker-compose.yml Specific

### Environment Variables

```
pattern: \$\{.*\}|\$[A-Z_]+
glob: docker-compose*.yml
```

### Hardcoded vs Variable

Look for patterns like:
- `URL=https://...` (hardcoded - good)
- `URL=${URL}` (variable - check if critical)
