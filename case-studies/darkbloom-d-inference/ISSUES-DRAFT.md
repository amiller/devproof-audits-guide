# GitHub Issues — Drafts

Six issues for `Layr-Labs/d-inference`. Framed as **devproofness / verifiability** gaps, not security bugs (Eigen's `security@eigenlabs.org` channel is for actual exploits; these are about whether outside parties can independently verify the system's claims). Each issue is standalone and copy-pasteable.

**Repo HEAD audited:** `cf4c0ef` · **Audit date:** 2026-05-10 · **Live API:** `api.darkbloom.dev` · **Reference verifier:** openssl + Python `cryptography`, no payment, no account.

Suggested labels for all six: `devproof`, `verifiability`, `transparency`. Add `enhancement` rather than `bug` — none break a documented guarantee, they're gaps in the chain that an outside auditor can build.

Numbering matches `DEVPROOF-REPORT.md`. **Five of six are also findable from the research paper alone** — see `DEVPROOF-REPORT.md` §"Concordance with the research paper" for the per-issue paper analysis. Each issue below cites the relevant paper section under "Paper concordance" where applicable.

---

## F1 — `trust_level=hardware` is set even when the MDA→SE-key binding fails (43% of live providers today)

### Summary

The coordinator's `verifyAppleDeviceAttestation` (`coordinator/internal/api/provider.go:1411-1497`) computes `SEKeyBound = (sha256(SE_pubkey_b64) == leaf_cert.OID(1.2.840.113635.100.8.11.1))` to verify that the SE pubkey signing the AttestationBlob is the same one Apple's MDA cert chain vouches for. **However, `MDAVerified=true` and `trust_level=hardware` are set regardless of `SEKeyBound`.** `SEKeyBound` is also not exposed in the public `/v1/providers/attestation` feed, so external auditors cannot detect the gap themselves.

In the live network on 2026-05-10, **13 of 30 (43%) hardware-trust providers have `SEKeyBound=false`** — Apple's cert vouches for a real Apple device, but the SE pubkey those providers use today is not the one Apple bound. Routing then sends prompts to providers whose strongest claim is "the same coordinator that registered me asserts this is the right SE pubkey now."

### Reproduce

```bash
curl -sS https://api.darkbloom.dev/v1/providers/attestation > feed.json
python3 - <<'PY'
import json, base64, hashlib
from cryptography import x509
d = json.load(open('feed.json'))
holds, fails = 0, 0
for p in d['providers']:
    if not p.get('mda_verified'): continue
    chain = p.get('mda_cert_chain_b64') or []
    if not chain: continue
    leaf = x509.load_der_x509_certificate(base64.b64decode(chain[0]))
    ext = next((e for e in leaf.extensions
                if e.oid.dotted_string == '1.2.840.113635.100.8.11.1'), None)
    if not ext: continue
    raw = bytes(ext.value.value if hasattr(ext.value,'value') else ext.value)
    if len(raw) >= 2 and raw[0] == 0x04 and raw[1] == len(raw)-2: raw = raw[2:]
    expected = hashlib.sha256(p['se_public_key'].encode('ascii')).digest()
    if raw == expected: holds += 1
    else: fails += 1
print(f'holds {holds}, fails {fails}')
PY
# 2026-05-10: holds 17, fails 13
```

A working provider (binding holds, `f99b7905`, M2 Max, serial `WRPWFW61H9`):

```
SE pubkey      qKxKds4zZk81flmOxcOmQVYSL0xkeg88tLBfXd7ghhJ/QYjW5ZKBAzASJ0TPwseWv38jW61NESGDtGsJqdzJ9Q==
sha256(b64)    984a169f28cd03dd50df4772724174bf3573486b20384918fe44eca467d86a98
OID 100.8.11.1 984a169f28cd03dd50df4772724174bf3573486b20384918fe44eca467d86a98 ✓
```

A failing provider (`46a8fd75`, M4 Max, serial `HH0K6TJY0J`, leaf cert valid 2026-04-24 → 2026-07-24):

```
SE pubkey      RUw/GIa+bga22J5hBA2HksqWx1XdqN0apPAyIQZwXNkihmylxRMoBo0eLkA213MOOye8+0RlH+f1gBooTKxD6A==
sha256(b64)    d7337511c8acde7ac8e072e3ffaf5f3756d1d36e11b0c6230ed652148a8d87b6
OID 100.8.11.1 50b295bd88cf6977d95e000845d9dd8250d64e9ce08371f80e33f4ac14ff3d26 ✗
```

Cert ages don't explain the split (matches median 7d, fails median 8d, both well within the 90-day window). Most likely the SE key was rotated (re-install / refresh) between MDA requests; the existing leaf binds an earlier SE key.

### Code sites

- `coordinator/internal/api/provider.go:1487-1497` — `MDAVerified=true` and `SEKeyBound=...` set independently
- `coordinator/internal/registry/scheduler.go:370,650` — routing only checks `trust_level >= MinTrustLevel`, not `SEKeyBound`
- `coordinator/internal/api/provider.go:1540-1626` — `/v1/providers/attestation` response struct does not include `SEKeyBound`
- `coordinator/internal/api/me_handlers.go:64,576` — `SEKeyBound` IS exposed in the authenticated `/me` endpoint, just not the public feed

### Paper concordance

Findable from the paper alone as an inconsistency between architectural claim and operational definition:
- §17 conclusion (lines 985-988) lists *"MDA nonce-based SE key binding"* as one of five attestation layers that "provides defense-in-depth where each layer independently verifies properties that the others cannot."
- Definition 5 *"Verified Provider"* (§5.4 lines 358-374) item 5 only requires *"Apple MDA certificate chain is valid and serial number matches self-reported attestation"* — no binding requirement.

So the paper's conclusion claims a property that its operational verification definition doesn't enforce.

### Suggested fix (any of these closes the gap)

1. **Recommended:** require `SEKeyBound==true` for `trust_level=hardware`. Demote to `self_signed` otherwise. This silently downgrades 13 providers today until they re-attest, which is the right answer for the "hardware trust" claim to mean what it says, and aligns Definition 5 with the §17 architectural claim.
2. Re-issue MDA whenever the SE pubkey changes during a registration cycle. Trigger a fresh `verifyAppleDeviceAttestation` from `provider.go` whenever `attestResult.PublicKey` differs from the value stored at last MDA time.
3. **At minimum:** publish `se_key_bound` in the `/v1/providers/attestation` response so external verifiers can detect the gap themselves. This is a one-field change in the response struct at `provider.go:1540-1626`.

(1) is the right fix; (3) is the minimum to make the public feed honest about what `trust_level=hardware` actually proves today.

---

## F2 — Public attestation feed does not include the SE-signed AttestationBlob

### Summary

`/v1/providers/attestation` exposes the SE pubkey, the MDA cert chain, and a flat list of security-state claims (`sip_enabled`, `secure_boot_enabled`, `system_volume_hash`, `authenticated_root_enabled`, `serial_number`, etc.). It does **not** expose the SE-signed `AttestationBlob` itself or its signature. As a result, an external auditor can verify "this is a real Apple device" (via the MDA cert chain) but **must trust the coordinator's verification** for every other field. None of those flags can be re-checked from outside; they are coordinator-asserted, not coordinator-relayed.

This makes the "users can verify" framing in `docs/ARCHITECTURE.md` §"User Attestation Verification" weaker than it reads. The doc says users can "decod[e] the cert chain… verify the cert chain against Apple's root CA" — true and we did — but the doc implies that this is the meaningful end of the verification, when actually the cert only covers the device identity, not the SIP/SecureBoot/binary-hash claims that carry most of the trust weight.

### Reproduce

```bash
curl -sS https://api.darkbloom.dev/v1/providers/attestation \
  | jq '.providers[0] | keys'
# Returns: provider_id, chip_name, hardware_model, serial_number, trust_level,
#          status, memory_gb, gpu_cores, models, secure_enclave, sip_enabled,
#          secure_boot_enabled, authenticated_root_enabled, system_volume_hash,
#          se_public_key, mdm_verified, acme_verified, mda_verified,
#          mda_cert_chain_b64, mda_serial, mda_udid, mda_os_version,
#          mda_sepos_version
# Missing: signed_attestation_b64, attestation_signature_b64, binary_hash,
#          encryption_public_key
```

The `binary_hash` and `encryption_public_key` fields exist on the internal `attestation.AttestationBlob` (`coordinator/internal/attestation/attestation.go:46-62`) but are not surfaced in the public response.

### Code sites

- `coordinator/internal/attestation/attestation.go:46-91` — `AttestationBlob` struct + `SignedAttestation` wrapper (raw JSON preserved for sig verification, exactly the format an external verifier would need)
- `coordinator/internal/api/provider.go:1540-1626` — `/v1/providers/attestation` handler builds a flat `providerAttestation` struct without the signed blob

### Paper concordance

Not directly paper-findable — implementation question. §7.3.3 (line 600) says *"the complete certificate chain is stored and exposed via a public API endpoint, enabling consumers to independently verify each provider against Apple's publicly available root CA certificate"* — the paper claim is true for the cert chain, but doesn't enumerate which other fields are or aren't exposed. Requires a `curl` to the live API to discover.

### Suggested fix

Add four optional fields to the public response:

```go
SignedAttestationB64    string `json:"signed_attestation_b64,omitempty"`
AttestationSignatureB64 string `json:"attestation_signature_b64,omitempty"`
BinaryHash              string `json:"binary_hash,omitempty"`
EncryptionPublicKey     string `json:"encryption_public_key,omitempty"`
```

The blob verification logic an external auditor would write is already implemented in `attestation.Verify` — they would re-run the same check (re-encode the blob with sorted keys, SHA-256, P-256 ECDSA verify against `se_public_key`). With these fields, the verification chain becomes: MDA cert chain → Apple Root → leaf binds SE pubkey via freshness OID → SE pubkey verifies the signed blob → blob carries `binary_hash` and `encryption_public_key`. Closes the gap end-to-end.

Optional follow-up: also expose the most recent challenge-response (with `status_signature` per `attestation.go:329-441`) so the *live* security state can be re-checked, not just the registration-time blob.

---

## F3 — No public coordinator attestation endpoint

### Summary

`CLAUDE.md`, the deploy runbook, and the research paper Figure 1 all state that the production coordinator runs in a TEE — paper Fig 1 specifically labels it Intel TDX, with the supplementary `papers/diagram-test.pdf` saying *"EigenCompute (Intel TDX TEE)"*. However, there is no public endpoint where an outside auditor can fetch a TEE quote for the coordinator. `GET /v1/coordinator/attestation` returns 404. EigenCloud's docs (`docs.eigencloud.xyz`) return 403 to anonymous fetch; the marketing page (`eigencloud.xyz`) does not specify the underlying TEE substrate.

This is the load-bearing piece of the trust model: when sealed mode is not used (the default — `Content-Type: application/eigeninference-sealed+json` is opt-in per `coordinator/internal/api/sender_encryption.go`), every prompt is decrypted by the coordinator before being re-encrypted to the chosen provider. The coordinator-as-TEE claim is the only thing keeping Eigen Labs from seeing plaintext at that boundary, and there is no way for an outside party to verify it.

For comparison, every other CVM-backed inference provider in the broader cohort publishes its TEE quote:

- **Tinfoil:** `https://atc.tinfoil.sh/attestation` (SEV-SNP report + Sigstore-signed predicate)
- **Phala dstack apps:** 8090 endpoint per app
- **NEAR Private AI Verifier:** same dstack pattern, plus on-chain anchor

### Reproduce

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://api.darkbloom.dev/v1/coordinator/attestation
# 404
curl -sS -o /dev/null -w '%{http_code}\n' https://api.darkbloom.dev/v1/coordinator
# 404
```

### Paper concordance

Findable from the paper alone as an omission. §7 covers provider attestation in detail (four layers, §7.1–§7.4) and §7.3.3 explicitly describes a public-API endpoint for provider chains. There's no parallel section for the coordinator. Figure 1 shows the coordinator in Intel TDX with *"Container Image Attested"* but the attestation surface is never described.

A reader would ask: *"§7 gives the provider's verification API in detail. Where's the equivalent for the coordinator's TDX VM? What does an outside party fetch to verify the running image?"* No answer in the paper.

### Suggested fix

Add `GET /v1/coordinator/attestation` returning, at minimum:
- The TEE quote (Intel TDX per the paper)
- The image digest the coordinator is running (matched against `coordinator/Dockerfile` build pipeline)
- A signed predicate from the build pipeline (Sigstore is the obvious choice if EigenCloud doesn't already provide one) tying the image digest to a Git commit hash on this repo

A close-enough first version: even just publishing the EigenCloud-provided attestation document + the source commit it was built from would let an outside auditor compare to a Git tag and `coordinator/Dockerfile`. If EigenCloud's attestation surface is itself opaque, that fact should be documented in `docs/ARCHITECTURE.md` so the trust model is honest about where the chain ends.

---

## F4 — Release registry has no public history; silent ADDs are a CT-analogous MITM vector

### Summary

The integrity-in side is recently hardened (PR #99 added constant-time release-key comparison, payload validation, and R2 bundle re-download + re-hash at registration). The transparency-out side is the gap.

`GET /v1/releases/latest` is the only public endpoint (`release_handlers.go:443-468`). Listing all releases requires admin auth (`release_handlers.go:470-482`). `DELETE /v1/admin/releases` (`:484-522`) deactivates a registered release and re-syncs the routing gate immediately. **`POST /v1/releases` adds a registered hash with no public log**. Both writes are externally invisible.

Silent **adds** are strictly more damaging than silent deletes — they are a structural MITM vector for any user routed to the new binary. The threat model is the same one Certificate Transparency was designed for: a trusted issuer (CA / coordinator-with-release-key) vouches for an entity (cert / binary) that the relying party cannot independently enumerate. The attack today:

1. Attacker obtains the scoped release-key (`release_handlers.go:69-74`) — insider, leaked GH Actions secret, or compromised `macos-latest` runner.
2. `POST /v1/releases` with a metadata payload pointing at the canonical R2 URL pattern. `verifyReleaseArtifact` re-downloads and re-hashes (`release_handlers.go:321-426`); this is good integrity-in, but it only confirms the artifact at the URL hashes to the supplied value — it says nothing about the artifact's source.
3. Attacker stands up a provider running the new binary. Once the new hash is registered, the provider's `AttestationBlob.binaryHash` matches a blessed value, the routing gate (`scheduler.go:370`) accepts it.
4. Coordinator routes some traffic to the attacker. Routing scores are operator-defined and externally invisible; a malicious coordinator could selectively target users.
5. Neither the official Python SDK (no verifier — see F5b) nor the web verifier (does not check `binary_hash` — it's not in the public feed per F2) nor any external monitor (no public registration log) detects it.

The cohort handles this in two ways. **Tinfoil:** every CVM image attestation is a Sigstore in-toto predicate signed via GitHub OIDC pinned to `^https://github.com/tinfoilsh/confidential-model-router/.github/workflows/.*@refs/tags/.*`; attestations land in Rekor; an attacker without that GH OIDC identity can't sign predicates that pass policy. **NEAR:** on-chain dstack image-hash registry at `0x8fa1593f…` on Base; anyone watches the contract.

### Reproduce

```bash
# Latest works:
curl -sS https://api.darkbloom.dev/v1/releases/latest
# {"version":"0.4.7","binary_hash":"88848229...","bundle_hash":"f3eb0c1c...",...}

# Specific historical version (no public path):
for v in v0.4.6 v0.4.5 v0.3.10 all list history; do
  printf '%-20s ' "/v1/releases/$v"
  curl -sS -o /dev/null -w '%{http_code}\n' "https://api.darkbloom.dev/v1/releases/$v"
done
# all return 404

# But the artifacts ARE still on R2 (not GC'd):
curl -sI 'https://pub-3d1cb668259340eeb2276e1d375c846d.r2.dev/releases/v0.3.10/eigeninference-bundle-macos-arm64.tar.gz' | head -3
# HTTP/1.1 200 OK
# Content-Length: 20112925
# Last-Modified: Thu, 16 Apr 2026 12:35:40 GMT
```

So old artifacts survive on the CDN, but the *registered hashes* at the coordinator are not historically queryable.

### Paper concordance

Findable from the paper alone as an omission. Definition 5 item 2 says *"Binary hash matches a known blessed version"* but the paper doesn't describe how the "blessed" set is constructed, modified, or made auditable. §17 Future Work doesn't mention transparency.

A reader asks: *"the blessed-binary set determines which providers can serve. How does a consumer know the set hasn't grown to include a backdoored binary? Where's the audit log?"* No answer.

### Suggested fix

**Smallest useful step:**
1. Make `GET /v1/releases` (without `/latest`) return all *active* releases as a JSON array. Read-only, no admin token. Already exists internally as `s.store.ListReleases()` — just route a no-auth handler at `release_handlers.go`.
2. Make `GET /v1/releases/v<X.Y.Z>` return the registered metadata for that version (if any), even if `active=false`. This way "was hash X ever blessed?" is answerable from outside.

**CT-equivalent (right answer):**
3. Sigstore-sign each `POST /v1/releases` payload using GitHub OIDC from the release workflow (the same identity policy Tinfoil uses for its CVM image attestations). Pin identity to `^https://github.com/Layr-Labs/d-inference/.github/workflows/release.yml@refs/tags/.*`. Publish the Rekor log entry alongside the release in `/v1/releases/latest`. Anyone can then walk: GitHub commit → Sigstore-signed predicate → Rekor log → registered hash → in-attestation `binaryHash` field → routing gate.
4. Or: publish each registration to an on-chain anchor (Solana, since billing already lives there, or Base, since the EigenLayer ecosystem already anchors there). The constraint is *append-only*; the chain choice is taste.

---

## F5a — Web verifier stops at "genuine Apple device"; same incomplete-easy-path pattern as NEAR Private Chat

### Summary

`console.darkbloom.dev` ships a real cryptographic verifier at `console-ui/src/lib/cert-verify.ts` (332 lines, pkijs + WebCrypto). The comment at line 5 is candid: *"This replaces the fake 'verify' button that just checked JSON fields. Now we actually parse DER certificates, verify signatures, and extract Apple-specific OID values."* It runs five steps and returns "Genuine Apple device — certificate chain valid."

**What it checks:** parse chain → extract leaf OIDs (serial, UDID, OS, SepOS) → verify intermediate→leaf → verify root fingerprint → confirm.

**What it does NOT check:**
- **MDA→SE-key binding** (freshness OID `1.2.840.113635.100.8.11.1` vs `sha256(se_public_key_b64)`). For the 13/30 providers where the binding fails (F1), the verifier shows ✓✓✓✓✓ and the same green "Genuine Apple device" message.
- **SE-signed AttestationBlob.** Can't — the public feed doesn't ship the blob (F2).
- **Coordinator attestation.** Provider-tier only.

This is structurally identical to NEAR Private Chat's *"easy path is incomplete"* pattern: a published, real verifier that stops one step short of the load-bearing property and leaves the user with a green check that doesn't mean what it appears to mean.

### Code sites

- `console-ui/src/lib/cert-verify.ts:139-318` — `verifyCertificateChain` function and the five steps
- `console-ui/src/lib/cert-verify.ts:185-192` — OIDs extracted (serial, UDID, OS, SepOS — but not freshness)
- `console-ui/src/lib/cert-verify.ts:314-315` — final success message *"Genuine Apple device — certificate chain valid"*
- `console-ui/src/components/VerificationPanel.tsx:204-209` — UI surfacing of `verifyResult.success` as `"Genuine Apple device"`

### Suggested fix

~60 lines in `cert-verify.ts`:

1. Add `const OID_FRESHNESS = "1.2.840.113635.100.8.11.1";` near the existing OID constants.
2. In step 2 (extract OIDs), also extract the freshness code bytes.
3. After step 4 (root verified), add a step 5 that computes `await crypto.subtle.digest("SHA-256", new TextEncoder().encode(provider.se_public_key))` and compares to the freshness bytes.
4. If mismatch: fail with *"SE key not bound to this device — coordinator could be substituting another provider's key"*.
5. Renumber the existing step 5 (final confirmation) as step 6.

Same fix shape as F1 (server-side gate); applying both makes the user-visible verdict honest.

---

## F5b — Python SDK referenced in docs is not actually published; realistic Python users get zero attestation enforcement

### Summary

`docs/ARCHITECTURE.md:81-82` shows:

```python
from eigeninference import EigenInference
client = EigenInference(base_url="https://coordinator.darkbloom.io", api_key="eigeninference-...")
```

This package does not exist publicly. We checked:

- **PyPI:** `eigeninference`, `darkbloom`, `eigen-inference`, `d-inference`, `eigenlabs-inference` — all 404 on `/pypi/{name}/json` and `/simple/{name}/`.
- **npm:** `eigeninference`, `darkbloom`, `@eigenlabs/inference`, `@darkbloom/sdk`, `@darkbloom/client` — all 404.
- **GitHub:** `Layr-Labs` org has no Python SDK repo. Same project also lives at `darkbloomdev/darkbloom` (`fork=false`, identical structure but a stale 2026-04-20 snapshot — likely a brand-rename in progress); no SDK there either. No `sdk/`, `python/`, or `clients/` directory in either tree.

The realistic Python path is what the `README.md` actually shows:

```python
from openai import OpenAI
client = OpenAI(base_url="https://api.darkbloom.dev/v1", api_key="eigeninference-...")
```

The bare OpenAI client has no concept of MDA, SE keys, or binary hashes. **Zero attestation enforcement on this code path.** A user paying for the TEE-equivalent privacy claim ends up with the same posture as any HTTPS API. This is the dominant practical risk that Tinfoil's audit calls out (*"use the verifier or you've got nothing"*) — Darkbloom is structurally worse here because Tinfoil ships `tinfoil-go` / `tinfoil-py` on PyPI and Darkbloom ships nothing, while the docs imply otherwise.

### Suggested fix

Either:

1. **Ship the SDK.** A thin `eigeninference` (or `darkbloom`) PyPI package wrapping the OpenAI client, that runs the cert-chain + binding check (per F1) before each request and refuses to send if the chosen provider's binding fails. This is `cert-verify.ts` ported to Python — ~200 lines using `cryptography` and the existing `attestation.Verify` logic from `coordinator/internal/attestation/attestation.go`.

2. **Or remove the example.** Strike the `from eigeninference import EigenInference` block from `docs/ARCHITECTURE.md:80-90` so users aren't pointed at a package that doesn't exist. Replace with the OpenAI-client example that's already in `README.md`, plus an explicit note that the realistic Python path runs no client-side attestation today.

(1) is the right answer; (2) is the minimum to stop misleading users while the SDK is in development.

---

## F6 — Three project docs disagree about who sees plaintext (docs nit)

| Source | Says |
|---|---|
| `README.md` §How It Works | "The coordinator encrypts each request with the provider's X25519 public key before forwarding it." (correct: coordinator sees plaintext) |
| `docs/ARCHITECTURE.md` §Coordinator | "Consumers send plain text over HTTPS; the Confidential VM is the trust boundary." (correct) |
| `CLAUDE.md` §Key Design Decisions | "Coordinator never sees plaintext prompts. Decryption only inside the hardened provider process." (**incorrect** — sender encryption is opt-in) |

`CLAUDE.md` is the outlier. A two-word edit (*"Coordinator never sees"* → *"When sealed mode is used, coordinator never sees"*) would resolve it. Same passage should also reflect the asymmetric enforcement model from `provider.go:585-628` so the rollout posture is documented.

Also: `docs/ARCHITECTURE.md` describes prod as *"GCP Confidential VM (AMD SEV-SNP)"* but `CLAUDE.md` and the deploy runbook say prod runs on EigenCloud (TEE), and the research paper Figure 1 plus `papers/diagram-test.pdf` say *"EigenCompute (Intel TDX TEE)"*. The architecture doc should reflect the current prod substrate (Intel TDX per the paper).

Plus, per F5b: `docs/ARCHITECTURE.md:81-82` references an `eigeninference` Python package that is not on PyPI, GitHub, or anywhere else we could find. Either ship the package or remove the example.

These can be one PR, ~20 lines of changes, no behavior change.
