> **Method note.** This follow-up was produced by a multi-agent workflow (`darkbloom-followup-audit`,
> 2026-06-07): one examiner per finding (F1–F6 + a regressions sweep), each verdict re-checked by an
> independent adversarial skeptic before synthesis. Repo refreshed `cf4c0ef` → `069a6c3` (114 commits).

# Darkbloom (d-inference) — Follow-up Audit (2026-06-07)

Original audit at HEAD `cf4c0ef`; this re-audit at HEAD `069a6c3` (114 commits later). Live network: `https://api.darkbloom.dev/v1/providers/attestation` returns HTTP 200 with 67 providers. Code was relocated since the original audit: `coordinator/internal/api/` → `coordinator/api/`, `coordinator/internal/attestation/` → `coordinator/attestation/`; the Swift app moved out of `app/EigenInference`.

This report separates two things the original audit treated together: **fixed in code** (the build-from-repo prod path enforces the control) versus **verifiable in the live deployment** (a third party with no account can confirm it against the live API). Most movement this cycle is in the first category, not the second.

## Status at a glance

| Finding | Original severity | New status | One-line residual gap (external-verifier view) |
|---|---|---|---|
| F1 — MDA→SE-key binding not gated, not in feed | High | Partially fixed | Live symptom gone (60/60 hold) but only as a side effect of forced live re-attestation; no server-side gate and `se_key_bound` still absent from the feed. |
| F2 — feed omits SE-signed blob + signature | High | Not fixed | Feed struct byte-identical to `cf4c0ef`; no signed blob/signature/`binary_hash`/`encryption_public_key`, so all security-state claims remain coordinator-asserted plaintext. |
| F3 — no coordinator attestation / image hash | Medium | Not fixed | No coordinator quote or image hash; endpoints 404; prod EigenCloud substrate undisclosed. |
| F4 — release registry has no public transparency log | Medium | Not fixed | No public `GET /v1/releases`, no Sigstore/Rekor/on-chain anchor; silent add/delete still externally undetectable. |
| F5 — client-side verifiers incomplete | Medium | Partially fixed | F5a: browser verifier still asserts chain-only, never the SE-key binding, though `se_public_key` is now in the feed. F5b: still no consumer SDK. |
| F6 — docs disagree on plaintext + substrate | Low | Regressed | New second false "never sees plaintext" claim added (CLAUDE.md:3); ARCHITECTURE.md now self-contradicts on substrate. |
| NEW — unauthenticated MDM webhook trust-injection | (not in F1–F6) | Fixed (in code) | Solicited-UUID gate + cross-checks fix it on the prod path, but the live endpoint returns 200 to forged POSTs, so the fix is not externally distinguishable from a no-op. |

## F1 — MDA→SE-key binding computed but not gated, not exposed

**What changed.** The live symptom is genuinely and durably gone. A fresh pull of the feed (67 providers, HTTP 200, 2026-06-07) run through the reproducer shows 60/60 `mda_verified`-with-chain providers now HOLD the cryptographic binding (was 13/30 FAIL at the original audit); 1 `mda_verified` provider has no chain in the feed.

```
python3 verify/binding-check.py /tmp/feed_new.json -> binding HOLDS 60 / binding FAILS 0
```

The cause is **incidental**, not a targeted F1 fix. Commit `a391376` (#268, item 2) caps `RestoreProviderState` at `self_signed` (`coordinator/registry/registry.go:639-650`), so hardware trust is re-earned via a fresh challenge on every reconnect. That re-runs `verifyAppleDeviceAttestation` with `nonce = sha256(current SE pubkey)` (`coordinator/api/provider.go:1875-1879`), forcing Apple to embed the live key as the FreshnessCode. This cures the *stale-key* root cause the report named (one of three suggested remediations), but it is a reliability commit, not a binding gate.

**What still doesn't hold externally.**
- **No server-side gate.** The `SEKeyBound` logic at `coordinator/api/provider.go:1945-1984` is byte-identical to the audited `cf4c0ef` code (only relocated). A FreshnessCode mismatch produces only `Warn ("MDA verified but FreshnessCode mismatch — SE key NOT bound")`; an outright-invalid MDA chain returns with only a Warn and no demote (`provider.go:1923-1929`); only a serial mismatch calls `MarkUntrusted` (`provider.go:1932-1940`). Hardware trust is granted from MDM `SecurityInfo` at `provider.go:1841,1858` *before* any binding is computed. `SEKeyBound` is read nowhere outside the setter, the field decl (`registry.go:204`), and the authenticated `/me` handler (`me_handlers.go:64,573`); the scheduler gates only on `trustRank(p.TrustLevel) >= trustRank(minTrust)` plus `RuntimeVerified` (`scheduler.go:528,895,996`). The control F1 named is therefore fully unenforced — the 60/60 hold depends entirely on continuous live re-attestation and would silently regress between an SE-key rotation and the next successful challenge, or if stored-hardware restore is ever reintroduced.
- **Still not in the feed.** `se_key_bound` is absent from the public response struct (`coordinator/api/provider.go:1991-2025`); the live feed dump confirms the field is not present. A no-account third party can only reconstruct the binding by recomputing `sha256(se_public_key)` against the leaf freshness OID (exactly what the reproducer does) — it is not directly readable.

Fix PR: #268 / `a391376` (incidental; no targeted F1 gate or feed-field commit exists).

## F2 — feed omits the SE-signed AttestationBlob + signature

**What changed.** Nothing in the feed shape. The response struct at `coordinator/api/provider.go:1991-2025` has the identical JSON field set as the audited `cf4c0ef` struct (`git show cf4c0ef:coordinator/internal/api/provider.go` lines 1532-1626) across all 114 commits. Live feed keys: `acme_verified, authenticated_root_enabled, chip_name, gpu_cores, hardware_model, mda_cert_chain_b64, mda_os_version, mda_sepos_version, mda_serial, mda_udid, mda_verified, mdm_verified, memory_gb, models, provider_id, se_public_key, secure_boot_enabled, secure_enclave, serial_number, sip_enabled, status, system_volume_hash, trust_level` — none of the four F2 fields. `grep -rn 'signed_attestation_b64|attestation_signature_b64'` over `*.go/*.ts/*.tsx` returns no matches.

The console route `console-ui/src/app/api/attestation/route.ts` is a pass-through proxy (`fetch ${COORD_URL}/v1/providers/attestation` then `NextResponse.json(data)`); the browser path (`AttestationPanel.tsx:125`) only runs `verifyCertificateChain`. `binary_hash` and `encryption_public_key` are now consumed *server-side* for registration trust gating against the known-hash policy (`coordinator/api/provider.go:1655-1735`), but that hardens enforcement (F1/F4); it does not make the security state externally re-checkable.

**What still doesn't hold externally.** An outsider cannot cryptographically re-verify any provider security claim. The feed ships `se_public_key` and the MDA cert chain (enabling the F1 device-identity + binding checks) but not the SE-signed AttestationBlob, its signature, `binary_hash`, or `encryption_public_key`. So `sip_enabled`, `secure_boot_enabled`, `authenticated_root_enabled`, `system_volume_hash`, the running binary hash, and the X25519 encryption key remain coordinator-asserted plaintext JSON with no signature verifiable against the SE key. The suggested fix (add the four fields; `attestation.Verify` already exists) was not applied.

Fix PR: none.

## F3 — no coordinator attestation endpoint or image hash

**What changed.** Nothing. No coordinator attestation route is registered (`coordinator/api/server.go:1290-1474`); `GET /v1/coordinator/attestation`, `/v1/attestation`, and `/v1/releases` all return 404 live.

**What still doesn't hold externally.** There is still no coordinator quote and no coordinator image hash an outsider can check, so the coordinator — which on the default path decrypts prompts (see F6) — is unattested. The production substrate remains undisclosed and the docs are internally inconsistent about it: the substrate comment is unchanged since `cf4c0ef` (`coordinator/api/server.go:11`, `main.go:8`), and `ARCHITECTURE.md:12` disagrees with `:29` (detailed under F6).

Fix PR: none.

## F4 — release registry has no public transparency log

**What changed.** The transparency-out gap is unchanged. Only two release routes are registered: `POST /v1/releases` (scoped release key, GitHub Action) and the public `GET /v1/releases/latest` (`coordinator/api/server.go:1381-1382`). No read-only `GET /v1/releases` exists — live it now returns `404 {"error": "...endpoint GET /v1/releases is not implemented"}` (was 405 at the original audit; functionally identical), and `GET /v1/releases/latest` returns only the single latest active record (v0.5.16). Listing all releases and deletion remain admin-only and log only to the internal logger (`server.go:1425-1426`; `release_handlers.go:140`, `:486-496`, `:500-536`), so silent add/delete leaves no external trace.

`POST /v1/releases` now re-downloads and re-hashes the R2 artifact before recording (`release_handlers.go:72-150` → `verifyReleaseArtifact:335-440` → `s.store.SetRelease`) — integrity-in hardening — but writes the blessed hash to Postgres with no append-only log and no signature over the registration. `grep -rin 'sigstore|rekor|transparency|in-toto|oidc|on-chain|onchain'` finds no transparency mechanism. The new `admin-ui/src/app/releases/page.tsx` (commit `e8687af`, #269) renders the full release table but queries Postgres directly (`admin-ui/src/lib/queries/releases.ts:23-43`) and the entire admin-ui is gated behind HTTP Basic Auth with no public routes (`admin-ui/src/proxy.ts`, `admin-ui/src/lib/auth.ts:24-48` fail-closed). No public releases proxy was added to the consumer-facing console-ui (`console-ui/src/app/api` has no `releases` dir).

**What still doesn't hold externally.** External verifiers still cannot enumerate the blessed-binary set, look up whether a given hash was ever blessed, or detect silent adds/deletes. No read-only `GET /v1/releases`, no Sigstore/GH-OIDC-signed registration, no Rekor entry, no on-chain anchor. The blessed-hash set behind the protocol's binary-allowlist definition is auditable only by holders of admin/Basic-Auth credentials.

Fix PR: none (#269/`e8687af` is an admin-only ops dashboard, not a public log).

## F5 — client-side verifiers (web verifier + Python SDK)

**F5a (browser verifier) — not fixed.** `console-ui/src/lib/cert-verify.ts` still verifies only the X.509 chain up to Apple's root and emits "Genuine Apple device — certificate chain valid" on chain validity alone. `verifyCertificateChain` takes only `(certChainB64, onStep)` — no `se_public_key` parameter (`cert-verify.ts:139-142,321-325`). The OID constant list contains serial/udid/os/sepos only; the freshness OID `1.2.840.113635.100.8.11.1` is absent, and `extractOIDValue` actively discards non-printable bytes — i.e. the freshness code itself (`cert-verify.ts:31-34,108-109`). All three callers pass only `(certs, onStep)`; `se_public_key` is collected into display state but never verified (`AttestationPanel.tsx:125`, `VerificationPanel.tsx:531,556`, `stats/page.tsx:2637`). Commit #130 added adjacent chain-link verification — a real but different robustness fix.

The partial credit is real: the feed now exposes `se_public_key` for all 67 providers and the server-side binding holds (60/60), so the data needed for a client-side binding check now exists offline — the verifier just refuses to use it. Worse, the feed does not expose the coordinator's own `se_key_bound` verdict (it lives only in the authenticated `/me` handler, `me_handlers.go:64-65`), so for a no-account consumer the binding stays coordinator-asserted and is only inferable by recomputing the hash.

**F5b (Python SDK) — cosmetic only.** Docs dropped the custom `eigeninference` import for a bare `from openai import OpenAI` client (`docs/ARCHITECTURE.md:54-55`), but no SDK exists (pypi `eigeninference` 404, pypi `darkbloom` 404, npm `darkbloom` 404), so the documented consumer path performs zero attestation. The `darkbloom verify` CLI is a provider-operator self-check (`provider-swift/Sources/darkbloom/VerifyCommand.swift:5-31`), not a consumer verifier.

Fix PR: #130 (adjacent chain links only; no binding assertion, no SDK).

## F6 — docs disagree on who sees plaintext + substrate inconsistent

**Status: regressed.** The original false claim ("Coordinator never sees plaintext prompts. Decryption only inside the hardened provider process.") is still verbatim at `CLAUDE.md:181`, and a **new** second false instance was added to the opening summary at `CLAUDE.md:3` ("All inference is end-to-end encrypted — the coordinator never sees plaintext prompts."), where `cf4c0ef` had no plaintext claim at line 3 (`git show cf4c0ef:CLAUDE.md`). `README.md:25`, `README.md:117`, and `docs/ARCHITECTURE.md:29` still correctly describe the coordinator decrypting, so the docs are in direct conflict.

The substrate axis also regressed: at `cf4c0ef`, `ARCHITECTURE.md` was internally consistent (all "AMD SEV-SNP" at lines 12/57/259). Now only line 12 was edited to "EigenCloud TEE in prod / GCP VM in dev" while `:29` and `:225` still say "AMD SEV-SNP" — a new within-file contradiction, and neither matches the paper's Intel TDX (`DEVPROOF-REPORT.md:300`).

The underlying behavior makes the `CLAUDE.md` claim false on the production path: sender→coordinator sealing is opt-in, and the default path is plaintext into the CVM (`coordinator/api/sender_encryption.go:118` "Plaintext requests bypass the wrapper entirely."; `:121-122` `if !isSealedContentType -> next(w, r)`). The live sealed-mode endpoint is unchanged from the original audit (`curl https://api.darkbloom.dev/v1/encryption-key` → `kid 833aec78e1c7c828`, `x25519-nacl-box`), confirming no deployment-level behavior change. The only fixed sub-item (removal of the nonexistent `eigeninference` package) belongs to F5b, not F6's plaintext/substrate scope, so it earns no F6 credit. Downgraded from "Partially fixed" to "Regressed."

Fix PR: none.

## NEW — unauthenticated MDM webhook trust-injection (missed by F1–F6)

A regression introduced in the 114-commit window (and present already at `cf4c0ef`): the public, unauthenticated `POST /v1/mdm/webhook` accepted a forged `SecurityInfo` matched only on an attacker-supplied UDID and could drive a `self_signed → hardware` trust upgrade.

**Fixed in code, on the default prod path, with tests.** `HandleWebhook` runs a mandatory solicited-command gate (`consumeCommand`) before any `SecurityInfo`/MDA parse, waiter dispatch, or trust callback; unsolicited/unknown UUIDs are dropped (`coordinator/mdm/mdm.go:476-484`, parse/callbacks at `:510-562`). A solicited UUID is still dropped on UDID mismatch (`mdm.go:486-493`). Command UUIDs are random, one-shot (deleted on consume), 30-min TTL, and kept out of Info logs (`mdm.go:170-202,108,495-507`). The actual upgrade additionally requires `SIP && SecureBootLevel==full` plus an independent `mdmClient.LookupDevice(serial).UDID==udid` cross-check before `SetAttested(true, TrustHardware)` (`coordinator/cmd/coordinator/main.go:368-404`). A read-only command allowlist fails closed (`mdm.go:149-166,290`). Regression tests assert the anti-forgery behavior (`coordinator/mdm/mdm_security_test.go:62-147`; no-secret default covered by `mdm_webhook_test.go:66`). The optional webhook secret is defense-in-depth only; the UUID gate is the mandatory control (`server.go:1226-1255`, `main.go:407-410`). Commits: #270, #233.

**What still doesn't hold externally.** The fix is coordinator-internal and not externally verifiable: the live endpoint returns HTTP 200 to a forged unsolicited POST (drops are silent), so a no-account third party cannot distinguish the enforcing prod binary from a no-op — "Fixed" rests on build-from-repo + code review, not a live oracle. Separately, the Rust→Swift provider cutover in this window staled the originally-audited binary hash (`88848229`); the live v0.5.16 Swift bundle (hash `41fb4842`) was never re-audited and the feed still exposes no `binary_hash` — but that overlaps F3/F4.

## Net assessment

Darkbloom did not move its external-verifiability stage. It was Stage 0 — no security claim in the live feed is cryptographically re-checkable by a no-account third party — and it remains Stage 0. Every improvement this cycle is either **enforcement-in (server-side gating of `binary_hash`/`encryption_public_key`, the MDM webhook UUID gate, forced live re-attestation)** or **internal tooling (admin-ui releases dashboard)**; none of it adds an external oracle. The one externally observable change — the F1 binding now holding 60/60 in the live feed — is a *side effect* of a reliability commit (`a391376`) forcing live re-attestation, not a binding gate, and it remains reconstructable only by recomputing `sha256(se_public_key)` against the leaf freshness OID, because `se_key_bound` is still not published. F2, F3, F4 are untouched; F5a's verifier still asserts chain-only; F6 regressed with a second false plaintext claim and a new substrate self-contradiction.

The single highest-leverage remaining gap is **F2**: the feed ships every security-state field (`sip_enabled`, `secure_boot_enabled`, `authenticated_root_enabled`, `system_volume_hash`, plus the binary hash and X25519 key it omits) as coordinator-asserted plaintext with no SE signature. Shipping the SE-signed AttestationBlob + signature (the verification logic already exists in `attestation.Verify`) would convert the entire per-provider security state — and, as a byproduct, the F1 binding and F5a's client check — from "trust the coordinator's JSON" into something an outsider can verify against the SE key. Until then, the chain of trust terminates at the coordinator's word.