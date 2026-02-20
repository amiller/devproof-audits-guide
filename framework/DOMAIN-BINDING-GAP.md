# Domain-to-AppID Binding Gap in dstack

**Date:** 2026-02-20
**Severity:** Architectural gap (affects all dstack apps using custom domains)
**Status:** Open — no mitigation exists in current dstack design

---

## Summary

dstack's gateway routes custom-domain traffic to apps based on a mutable DNS TXT record (`_dstack-app-address.{domain}`). This binding is unattested, unlogged, and controlled entirely by the domain owner. A domain owner can silently redirect traffic to a different TEE app at any time, with no on-chain record.

This is distinct from the built-in subdomain routing (`{appid}-{port}.cluster.phala.network`), which is cryptographically bound to attestation-derived app IDs.

---

## Two Routing Modes, Two Trust Models

| Property | Built-in subdomain | Custom domain |
|----------|-------------------|---------------|
| Format | `{appid}-443.dstack-pha-prod9.phala.network` | `hermes.example.com` |
| Routing decision | Gateway parses appid from SNI hostname | Gateway resolves `_dstack-app-address` DNS TXT |
| TLS termination | Gateway TEE | App's TEE (dstack-ingress sidecar) |
| Binding strength | **Cryptographic** — appid derived from attestation | **DNS** — mutable, outside TEE |
| On-chain record | Base KMS logs compose hash changes | Nothing binds domain→appid |
| Can be redirected? | No (appid = code measurement) | Yes (change TXT record) |

---

## The Attack

1. Operator deploys legitimate app (app_id X) on custom domain `app.example.com`
2. Sets `_dstack-app-address.app.example.com` TXT → app_id X
3. Users verify attestation, trust the app
4. Operator changes TXT record → app_id Y (malicious TEE app)
5. Gateway follows DNS, routes traffic to app Y
6. App Y obtains a fresh Let's Encrypt cert for `app.example.com` (it's a valid TEE, CA will issue)
7. Operator exfiltrates data
8. Operator reverts TXT record → app_id X
9. No on-chain evidence of steps 4–8

**Time window:** DNS TTL (often 300s) + ACME issuance time (~30s). The switch can be live in under 10 minutes.

---

## Existing Mitigations (Detect, Not Prevent)

### CAA Records
Can restrict cert issuance to specific CAs. dstack recommends Let's Encrypt with a pinned ACME account. But this only prevents *non-TEE* impersonation — a different TEE app under the same ACME account can still get a cert.

### Certificate Transparency
Every cert issued for a custom domain appears in CT logs (unlike built-in subdomains which use wildcard certs). CT monitoring can detect that a *new* cert was issued for a domain, which may indicate the domain was pointed at a different app. This is after-the-fact detection with hours of delay.

### `/evidences/` Endpoint
Clients can fetch attestation quotes and verify the app's code hash. But this requires active verification on every connection — no browser does this automatically.

### Summary of Mitigations

| Mitigation | Prevents attack? | Detection delay |
|-----------|-----------------|-----------------|
| CAA records | Prevents non-TEE impersonation only | N/A |
| CT monitoring | No — detects after the fact | Hours (log ingestion delay) |
| Client attestation check | Only if client verifies every time | Real-time if checked |
| Base KMS on-chain log | Logs compose changes, not domain changes | N/A — wrong layer |

---

## What's Missing: On-Chain Domain Binding

The missing primitive is an on-chain registry binding domains to app IDs:

```
DomainRegistry.bind(domain, appId, composeHash)
```

The gateway (which is itself attested and can read on-chain state) would then **refuse** to route a domain to an app_id that doesn't match the on-chain binding. Changes to the binding would require an on-chain transaction, creating a permanent audit trail.

### Requirements
- Gateway must check on-chain binding before routing custom domain traffic
- Domain owner must prove DNS control (via TXT record) at binding time
- Binding changes emit on-chain events (same as Base KMS compose hash updates)
- Gateway rejects routing if DNS TXT doesn't match on-chain binding

### Why This Matters for DevProof
Without domain binding, **Stage 1 cannot be achieved for apps on custom domains.** The ERC-733 requirement "developer cannot unilaterally alter, censor, or exfiltrate without notice period" is violated because the domain-to-app routing can be silently changed.

Apps on built-in subdomains (`{appid}-443...`) with Base KMS **can** achieve Stage 1, because both the routing (attestation-derived) and upgrade history (on-chain) are verifiable.

---

## CT Logs as Partial Monitoring

While CT logs cannot enumerate apps on built-in subdomains (wildcard certs), they are useful for custom domains:

| What CT logs reveal | Useful? |
|-------------------|---------|
| All certs ever issued for `app.example.com` | Yes — each cert may correspond to a different TEE instance |
| When certs were issued | Yes — unexpected issuance = possible domain redirect |
| Which app_id holds the cert | No — cert doesn't contain app_id |
| Cluster topology (wildcard certs) | Yes — 47 dstack clusters enumerable |
| Per-app enumeration on built-in subdomains | No — hidden behind wildcard |

### CT Monitoring Recommendation
For any custom-domain dstack app, set up CT monitoring (e.g., via crt.sh or Google's CT search) to alert on new certificate issuance. Multiple certs issued in a short window for the same domain is a red flag.

---

## Proposed Fix: Embed app_id in TLS Certificates

A lighter-weight alternative to on-chain domain binding: have dstack-ingress embed the app_id in the TLS certificate itself, using CT logs as the transparency layer.

### Current State

Certs issued by dstack-ingress are vanilla Let's Encrypt domain-validated certs:
```
Subject: CN = app.example.com
SAN: DNS:app.example.com
```

No TEE identity. The cert proves someone controlled DNS for the domain and ran ACME inside *some* TEE — but not *which* TEE.

### Proposed Change

dstack-ingress embeds the app_id (and optionally compose_hash) in the certificate:

**Option A: Custom X.509 extension**
```
X509v3 extensions:
    1.3.6.1.4.1.XXXXX.1 (dstack-app-id):
        db82f581256a3c9244c4d7129a67336990d08cdf
    1.3.6.1.4.1.XXXXX.2 (dstack-compose-hash):
        a8105997bfe1010d620679c18894aec23b5056b2ac1311048810ce14271362e3
```

**Option B: SAN encoding**
```
SAN: DNS:app.example.com,
     DNS:_dstack.db82f581256a3c9244c4d7129a67336990d08cdf.app.example.com
```

Option B works with existing Let's Encrypt infrastructure (no custom extensions needed), though it requires DNS control of the subdomain.

### Why This Works

1. **CT logs become an app_id transparency log.** Every cert issuance is logged immutably with the app_id. Search crt.sh for all certs ever associated with a domain — if the app_id changes, it's visible.

2. **Domain redirect attacks become detectable in CT.** If a different app_id appears in a cert for `app.example.com`, that's evidence of a redirect — even after the DNS TXT record is reverted.

3. **No on-chain component needed.** Uses existing CT infrastructure (already mandated by browsers) as the transparency layer. No smart contract changes, no new protocol.

4. **Clients can verify app_id from the TLS handshake.** A browser extension or verification tool could extract the app_id from the cert and check it against expected values, without hitting a separate `/evidences/` endpoint.

### Limitations

- Let's Encrypt may not support custom X.509 extensions (Option A). SAN encoding (Option B) is more practical.
- CT log ingestion has delays (hours). Not real-time prevention.
- Requires dstack-ingress code changes to include app_id in the CSR.
- Does not prevent the redirect — only makes it visible after the fact. But "visible after the fact in an immutable log" is a significant improvement over "completely invisible."

### Comparison of Approaches

| Approach | Prevents redirect? | Detectable? | Detection delay | Requires protocol change? |
|----------|-------------------|-------------|-----------------|--------------------------|
| Current (nothing) | No | No | N/A | No |
| DNS monitoring | No | Yes (polling) | Minutes | No |
| App_id in cert (this proposal) | No | Yes (immutable CT log) | Hours | dstack-ingress only |
| On-chain domain binding | Yes (gateway enforces) | Yes | Real-time | dstack gateway + smart contract |

The cert-embedding approach is the best bang-for-buck: it requires only a dstack-ingress change, uses existing infrastructure, and produces an immutable audit trail. On-chain domain binding is stronger but requires more protocol work.

---

## Scope

This gap affects **every dstack app using a custom domain**, not just any specific project. It is an architectural limitation of the current dstack gateway design.

Apps using only built-in subdomains + Base KMS are not affected by this specific gap.

---

## Practical Monitoring for Auditors (Today)

The gap can't be closed without protocol changes, but auditors can monitor for evidence of exploitation using existing tools.

### 1. DNS TXT Record Monitoring

Monitor `_dstack-app-address.{domain}` for changes. Any change means the domain now routes to a different app.

| Service | Cost | Polling Interval | History |
|---------|------|-------------------|---------|
| [ZoneWatcher](https://zonewatcher.com) | Paid | Minutes | Unlimited |
| [NsLookup.io](https://www.nslookup.io/dns-monitoring) | Free | ~15 min | Yes |
| [DNS Spy](https://dnsspy.io) | Paid | Configurable | Full audit trail |
| DIY (cron + `dig`) | Free | As fast as you want | Self-managed |

DIY example:
```bash
# Log TXT record value every minute
* * * * * echo "$(date -u +\%s) $(dig +short TXT _dstack-app-address.hermes.example.com)" >> /var/log/dstack-dns-audit.log
```

### 2. CT Log Monitoring

Monitor for new certificate issuance on the custom domain. A new cert may indicate a different TEE app claimed the domain.

- [crt.sh](https://crt.sh) — search `%.hermes.example.com`, subscribe to Atom feed
- [Certspotter](https://sslmate.com/certspotter/) — free monitoring, email alerts on new issuance
- [Google CT Search](https://transparencyreport.google.com/https/certificates) — manual lookup

### 3. Periodic Attestation Checks

Fetch `/evidences/` and verify the app_id and compose_hash haven't changed unexpectedly:

```bash
# Compare current attestation to expected values
curl -s https://hermes.example.com/evidences/quote.json | \
  jq '.tcb_info.compose_hash' | \
  diff - <(echo '"expected_compose_hash"')
```

### 4. Combined Approach

For a dstack app on a custom domain, an auditor should run all three:

| Layer | What to monitor | Tool |
|-------|----------------|------|
| DNS | `_dstack-app-address` TXT record | ZoneWatcher / cron+dig |
| TLS | New cert issuance for the domain | Certspotter / crt.sh |
| TEE | compose_hash at `/evidences/` | Periodic curl + diff |

A change at any layer without a corresponding public announcement is a red flag.

**Limitation:** All of these are polling-based. A sufficiently brief redirect (change TXT, serve malicious content, revert TXT — all within one polling interval) could go undetected. This is why the real fix is on-chain domain binding enforced by the attested gateway.

---

## References

- [Zero Trust HTTPS: Custom Domains on Phala Cloud](https://phala.com/posts/zero-trust-https-how-to-setup-custom-domains-on-phala-cloud)
- [dstack Whitepaper: Zero Trust TLS Protocol](https://docs.phala.com/dstack/design-documents/whitepaper#zero-trust-tls-protocol)
- [dstack Gateway source: tls_passthrough.rs](https://github.com/aspect-build/dstack/blob/main/gateway/src/tls_passthrough.rs)
- [ERC-733 Security Stages](../references/erc733-summary.md)
