# OAuth3 (Burnt Labs) TEE Verification Report

**Report Date:** 2026-03-03
**App ID:** `b7de194832e39104e31cbb56b0efadd9fd3466b4`
**Instance ID:** `07f8fd641d50842c1388444af32a545416413885`
**Domain:** `07f8fd641d50842c1388444af32a545416413885-8080.dstack-pha-prod5.phala.network`
**dstack Version:** 0.5.6
**Source:** https://github.com/burnt-labs/oauth3

---

## Quick Status

| Check | Status | Notes |
|-------|--------|-------|
| TEE Attestation | PASS | Intel TDX, GetQuote used for /attestation and /verify/gmail |
| Hardware Integrity | PASS | TDX quote with valid MRTD/RTMRs |
| Transparency Log | **FAIL** | Pha KMS — no public upgrade log |
| Reproducible Build | PARTIAL | Nix flake with pinned deps, but CI doesn't publish image digest |
| Source Provenance | **FAIL** | Cannot trace: compose_hash → image digest → source commit |
| Image Pinning | **FAIL** | `${DOCKER_IMAGE}` — operator chooses image |
| Secret Isolation | **FAIL** | All secrets operator-supplied env vars, DeriveKey never called |

**Overall: Stage 0** — Operator can rug users in multiple independent ways.

---

## What the App Does

OAuth3 is a Rust SSO authentication server (Axum + Diesel + PostgreSQL) that serves three roles:

### 1. Token Custodian + Authenticated Proxy

Third-party apps never see real Google/GitHub tokens. oauth3 stores upstream provider tokens and proxies API calls, injecting the real Bearer token server-side:

```
Third-party app  →  Bearer oaak_xxx (oauth3 token)  →  oauth3 TEE  →  Bearer ya29.xxx (Google token)  →  Google API
```

Scopes control access: `proxy` (all providers), `proxy:google` (Google only), `proxy:google:read` (read-only). Cookie sessions get full access; API keys and OAuth app tokens are scoped. The SSRF check validates the target host matches `api_base_url` but doesn't prevent the base itself from being malicious (see Gap 4).

### 2. OAuth2 Authorization Server (RFC 6749 + PKCE)

Not just an OAuth client — it **issues its own tokens** to third-party apps:
- Authorization code flow with consent screen and PKCE (S256 mandatory for public clients)
- Refresh token rotation with replay detection — each rotation creates a chain; using a revoked token signals compromise
- All oauth3-issued tokens stored as SHA-256 hashes (never plaintext)
- 10-min access tokens, 30-day refresh tokens, 10-min auth codes
- App registration: `POST /account/apps`, secret rotation, redirect URI management
- Token revocation always returns 200 per RFC 7009 (doesn't reveal token existence)

### 3. TEE-Attested Gmail Compliance Oracle

The most novel feature. `POST /verify/gmail`:
1. Uses Google token to search inbox for emails from a **hardcoded** suspect address (prevents client-side bypass)
2. Only reads `resultSizeEstimate` — never touches message content
3. **Immediately revokes** the Google token at Google's endpoint
4. **Deletes** the identity from the database (user must re-link Google)
5. Returns `{address, clean, message_count, suspect, timestamp}` wrapped in a TDX quote
6. User submits `{result, quote}` to a smart contract that verifies the TDX quote and checks `address == msg.sender`

The user's email never appears in the output (would be visible on-chain). Single-use token destruction prevents Gmail surveillance. Fields are alphabetically ordered for deterministic serialization so the smart contract can parse the same struct.

### Additional Features

- **5 OIDC/OAuth2 providers:** Google, GitHub, Dex, Whoop, Oura
- **API keys:** `oak_` prefixed, 48 alphanumeric chars (~286 bits entropy), SHA-256 hashed in DB, returned once on creation
- **Triple auth:** Cookie sessions → Bearer tokens (oauth3-issued) → API keys (`oak_` prefix detection)
- **Attestation middleware:** `?attest=true` on any endpoint wraps the JSON response with a TDX quote over the SHA-256 of the response body
- **Attestation key extraction:** `/attestation-key` reads the ECDSA P-256 public key from the TDX quote structure (offset 0x2BC), giving the TEE a persistent identity
- **Provider tokens stored plaintext** in `user_identities` table — must be recoverable for proxy forwarding. This is the highest-sensitivity data in the DB.

---

## What's Verified

### Cryptographically Proven
- Hardware isolation (Intel TDX enclave on Phala prod5)
- Specific code running (MRTD/RTMRs match compose hash)
- Attestation available on-demand via `?attest=true` query parameter

### NOT Proven (Trust Required)
- **Operator can swap the running image** (`${DOCKER_IMAGE}`)
- **Operator knows session signing key** (`COOKIE_KEY_BASE64`)
- **Operator can redirect OIDC to malicious server** (`PROVIDER_GOOGLE_ISSUER`)
- **Operator can intercept proxy API calls** (`PROVIDER_GOOGLE_API_BASE_URL`)
- **No upgrade history** — what ran yesterday?

---

## Current Gaps

### Gap 1: Operator Controls Running Image

**Problem:** `docker-compose.phala.yml` uses `image: ${DOCKER_IMAGE}`. The operator chooses which binary executes inside the TEE. There is no on-chain or public registry constraining this.

**Impact:** Operator can deploy a backdoored image at any time with zero notice. Since the app handles OAuth tokens and user sessions, a malicious image could exfiltrate all user credentials.

**Fix:** Pin image by digest in compose (`ghcr.io/burnt-labs/oauth3@sha256:...`). Publish digests in CI. Use Base KMS with on-chain compose hash registry.

### Gap 2: Cookie Key Not Derived from TEE KMS

**Problem:** `COOKIE_KEY_BASE64` is an operator-supplied environment variable. The dstack `DeriveKey` API exists in the codebase (`src/attestation/mod.rs`) but is **never called**. All secrets (cookie key, DB password, OAuth client secrets) come from env vars the operator controls.

**Impact:** The operator can forge any user's session cookie outside the TEE. They don't need to compromise the TEE — they already know the signing key.

**Fix:** Derive `COOKIE_KEY_BASE64` from `DeriveKey("/oauth3/cookie-key")` at startup. Remove it from `allowed_envs`. This ties the key to the specific TEE instance and code measurement.

**Code location:** `src/config.rs` — the `decode_cookie_key` function correctly derives signing/encryption keys from the base key, but the base key itself is operator-supplied.

### Gap 3: OIDC Issuer Operator-Configurable

**Problem:** `PROVIDER_GOOGLE_ISSUER` is in `allowed_envs`. The OIDC discovery flow (`openidconnect::CoreProviderMetadata::discover_async`) fetches the well-known config from this URL. The operator could set it to a fake identity provider.

**Impact:** Full OIDC redirect attack — fake login page, intercepted auth codes, forged ID tokens (since the operator also controls the JWKS endpoint in this scenario).

**Fix:** Hardcode known issuer URLs in the compose file:
```yaml
PROVIDER_GOOGLE_ISSUER: https://accounts.google.com  # not ${VAR}
```

**Code location:** `src/auth/oidc.rs` — `start_oidc_live` function.

### Gap 4: Proxy API Base URL Operator-Configurable

**Problem:** `PROVIDER_GOOGLE_API_BASE_URL` controls where the authenticated proxy (`/proxy/{provider}/{*path}`) sends requests with the user's access token as a Bearer header.

**Impact:** Operator can point this to their server and intercept every proxied API call, including user OAuth access tokens. The SSRF check (`src/web/proxy.rs`) only validates path traversal, not the base URL itself.

**Fix:** Hardcode API base URLs for known providers, or remove the proxy feature from the TEE deployment.

### Gap 5: Placeholder Authentication Mode

**Problem:** When a provider's `mode` is `"placeholder"`, the callback creates a user with a fake subject (`{provider}-placeholder-sub`) without any identity verification.

**Impact:** If placeholder mode is active in production (`.env.example` defaults to `PROVIDER_GOOGLE_MODE=placeholder`), anyone can create accounts without authenticating. The mode is seeded into the DB from env on first run.

**Fix:** Hard-error if `mode=placeholder` in production. Add startup check:
```rust
if mode == OidcMode::Placeholder && !cfg!(debug_assertions) {
    panic!("Placeholder mode cannot be used in production");
}
```

### Gap 6: No Upgrade Transparency

**Problem:** Running on Pha KMS with no public upgrade log. No timelock on compose hash changes. No `DEPLOYMENTS.md` tracking upgrade history.

**Impact:** Users cannot verify what code ran last week or get notice before changes.

**Fix:** Migrate to Base KMS (on-chain compose hash registry). Implement timelock on upgrades. Maintain DEPLOYMENTS.md.

### Gap 7: Dev Cookie Key Fallback

**Problem:** If `COOKIE_KEY_BASE64` is unset, a random key is generated at runtime with a warning log. The deploy script (`phala-deploy.sh`) does require it, but the app itself doesn't hard-error.

**Impact:** Low — sessions would break on restart. But this is a defense-in-depth failure; production code should never silently fall back.

**Fix:** Panic on missing `COOKIE_KEY_BASE64` in production (or better, derive from KMS per Gap 2).

---

## Trust Boundaries

```
              TRUSTED COMPUTE BASE (TCB)
    ┌─────────────────────────────────────────────┐
    │                                             │
    │   ┌───────────────────────────────────┐     │
    │   │         Intel TDX Hardware        │     │
    │   │   ┌───────────────────────────┐   │     │
    │   │   │    OAuth3 App + Postgres   │   │     │
    │   │   │                           │   │     │
    │   │   │  ⚠ Cookie key = env var   │   │     │
    │   │   │  ⚠ Image = ${DOCKER_IMAGE}│   │     │
    │   │   │  ⚠ OIDC issuer = env var  │   │     │
    │   │   └───────────────────────────┘   │     │
    │   │               │                   │     │
    │   │       ┌───────┴───────┐           │     │
    │   │       │  dstack SDK   │           │     │
    │   │       │  GetQuote ✅  │           │     │
    │   │       │  DeriveKey ❌ │           │     │
    │   │       └───────────────┘           │     │
    │   └───────────────────────────────────┘     │
    │                   │                         │
    │           ┌───────┴───────┐                 │
    │           │   Pha KMS     │                 │
    │           │  (opaque)     │                 │
    │           └───────────────┘                 │
    └─────────────────────────────────────────────┘

    OPERATOR CONTROLS:
    ├── Which image runs (${DOCKER_IMAGE})
    ├── Session signing key (COOKIE_KEY_BASE64)
    ├── OIDC issuer URL (PROVIDER_GOOGLE_ISSUER)
    ├── API proxy target (PROVIDER_GOOGLE_API_BASE_URL)
    ├── Database password (POSTGRES_PASSWORD)
    └── 16 more env vars
```

---

## Positive Findings

1. **Attestation middleware is well-designed** — any endpoint can be attested with `?attest=true`, wrapping responses with TDX quotes
2. **Gmail verification endpoint** — properly revokes tokens and unlinks identities after use
3. **Nix-based reproducible build** — `flake.nix` with pinned Rust 1.92, deterministic timestamps, LTO
4. **No admin/debug endpoints** — clean route structure, no backdoor paths
5. **Non-root container** — runs as `appuser` (UID 10001)
6. **SSRF protection on proxy** — host mismatch check (though base URL is operator-controlled)

---

## Allowed Environment Variables (21)

| Variable | Risk | Notes |
|----------|------|-------|
| `DOCKER_IMAGE` | **CRITICAL** | Operator picks running binary |
| `PROVIDER_GOOGLE_ISSUER` | **HIGH** | Redirects entire OIDC flow |
| `PROVIDER_GOOGLE_API_BASE_URL` | **HIGH** | Proxy sends user tokens here |
| `COOKIE_KEY_BASE64` | **HIGH** | Operator can forge sessions |
| `DATABASE_URL` | **HIGH** | Could point to external DB |
| `PROVIDER_GOOGLE_CLIENT_SECRET` | **HIGH** | Operator holds OAuth secret |
| `POSTGRES_PASSWORD` | MEDIUM | DB credential |
| `PROVIDER_GOOGLE_CLIENT_ID` | MEDIUM | OAuth app identity |
| `PROVIDER_GOOGLE_SCOPES` | MEDIUM | Could request broader perms |
| `PROVIDER_GOOGLE_MODE` | MEDIUM | Could enable placeholder mode |
| `APP_PUBLIC_URL` | MEDIUM | Could redirect users |
| `DSTACK_DOCKER_REGISTRY` | LOW | Registry for image pull |
| `DSTACK_DOCKER_USERNAME` | LOW | Registry auth |
| `DSTACK_DOCKER_PASSWORD` | LOW | Registry auth |
| `PROVIDER_GOOGLE_TYPE` | LOW | Provider type config |
| `APP_BIND_ADDR` | LOW | Listen address |
| `APP_FORCE_SECURE` | LOW | HTTPS enforcement |
| `RUST_LOG` | LOW | Log verbosity |
| `CVM_NAME` | LOW | Instance name |
| `DISK_SIZE` | LOW | Storage config |
| `POSTGRES_USER`/`POSTGRES_DB` | LOW | DB config |

---

## Path to Stage 1

1. **Derive cookie key from KMS** — Replace env var with `DeriveKey("/oauth3/cookie-key")` at startup
2. **Pin image by digest** — Change `${DOCKER_IMAGE}` to `ghcr.io/burnt-labs/oauth3@sha256:...`
3. **Hardcode OIDC issuer URLs** — `PROVIDER_GOOGLE_ISSUER: https://accounts.google.com` (not a variable)
4. **Hardcode API base URLs** — or remove proxy feature from TEE deployment
5. **Migrate to Base KMS** — on-chain compose hash registry for upgrade transparency
6. **Publish image digests in CI** — output sha256 digest from Nix build
7. **Hard-error on placeholder mode** in production
8. **Remove COOKIE_KEY_BASE64 from allowed_envs** once KMS-derived
9. **Maintain DEPLOYMENTS.md** with upgrade history

---

## Verification Commands

```bash
# Check 8090 metadata
curl -s https://07f8fd641d50842c1388444af32a545416413885-8090.dstack-pha-prod5.phala.network/ | jq .

# Check app health
curl https://07f8fd641d50842c1388444af32a545416413885-8080.dstack-pha-prod5.phala.network/healthz

# Get attested response
curl "https://07f8fd641d50842c1388444af32a545416413885-8080.dstack-pha-prod5.phala.network/me?attest=true"

# Get attestation info
curl https://07f8fd641d50842c1388444af32a545416413885-8080.dstack-pha-prod5.phala.network/attestation
```

---

## References

- Source: https://github.com/burnt-labs/oauth3
- 8090 Metadata: https://07f8fd641d50842c1388444af32a545416413885-8090.dstack-pha-prod5.phala.network/
- App: https://07f8fd641d50842c1388444af32a545416413885-8080.dstack-pha-prod5.phala.network/
- Compose hash: `9161c9c38dc06f4a2558d8a58cc1b379cba922641e22beedc3f6f7c819bda41c`
- OS image hash: `ead0c34c9aabca991f94b2dc9a40a413b2fa9e04a57cf792daad045e3adbf253`
- Aggregated MR: `74c8648043f5a9e7ec896b75fa0ea7b77a05ab144a65f2e3044ad98c18435d38`
