# Custom Domain Trust Model in dstack

**Date:** 2026-02-20
**Updated:** 2026-02-22 (retraction — original version overstated severity)
**Status:** Informational — describes trust tiers, not a gap

---

## Summary

dstack routes custom-domain traffic to apps based on a DNS TXT record (`_dstack-app-address.{domain}`). The original version of this document called this an "architectural gap" because the binding is mutable and not on-chain. **This was overstated.** A domain redirect attack requires the attacker to obtain a new TLS certificate, and all publicly trusted CAs are required to log to Certificate Transparency (CT) since 2018. The attack is therefore always detectable via CT logs.

The real trust model has two tiers:
1. **Browser users** — trust the domain + CT monitoring for detection of redirect attacks
2. **Client SDKs** — should perform attested TLS, making the domain just a discovery mechanism

The inherent trust boundary for custom domains is the domain registrar, same as everything else on the web.

---

## Two Routing Modes, Two Trust Models

| Property | Built-in subdomain | Custom domain |
|----------|-------------------|---------------|
| Format | `{appid}-443.dstack-pha-prod9.phala.network` | `hermes.example.com` |
| Routing decision | Gateway parses appid from SNI hostname | Gateway resolves `_dstack-app-address` DNS TXT |
| TLS termination | Gateway TEE | App's TEE (dstack-ingress sidecar) |
| Binding strength | **Cryptographic** — appid derived from attestation | **DNS** — mutable, but redirect detectable via CT |
| On-chain record | Base KMS logs compose hash changes | CT logs record every cert issuance |
| Can be redirected? | No (appid = code measurement) | Yes, but attacker must obtain new cert → CT logged |

---

## Domain Redirect Scenario

1. Operator changes `_dstack-app-address` TXT record → different app_id (malicious TEE app)
2. Gateway routes `app.example.com` to the new app
3. New app has a different TEE enclave — **no access to the old cert-data volume**
4. New app **must** obtain a new Let's Encrypt cert to serve valid TLS
5. All publicly trusted CAs are required to submit to CT logs (mandatory since 2018)
6. New cert appears in CT logs → **always detectable**
7. Operator reverts TXT record

**Key insight:** There is no way to serve valid TLS on a custom domain without a CT-logged certificate. Self-signed certs are rejected by browsers and standard TLS clients. The cert private key is inside the TEE's encrypted volume and cannot be extracted. Therefore CT monitoring provides a hard guarantee of detection.

**Detection delay:** CT log ingestion takes hours. The attack window is real but bounded, and the evidence is immutable.

**Inherent limit:** The domain registrar can seize the domain. This is the trust boundary for all DNS-based systems, not specific to dstack.

---

## Two Tiers of Client Trust

### Tier 1: Browser Access (CT-Detectable)

Browser users trust the domain's TLS cert, validated by the standard WebPKI. CT monitoring detects domain redirect attacks after the fact.

**Guidance for auditors:**
- Set up CT monitoring (Certspotter, crt.sh) for custom domains
- A new cert outside the normal 60-day renewal window is a red flag
- This is sufficient for Stage 1 (ERC-733) — the attack is detectable

### Tier 2: Client SDK (Attested TLS)

Client SDKs should verify the TEE attestation quote during the TLS handshake. At this level:
- The domain is just a discovery mechanism (how to find the app)
- Trust comes from the attestation (what code is running)
- Domain redirect is irrelevant — the client rejects any app_id it doesn't expect

**Guidance for SDK developers:**
- Fetch `/evidences/` and verify app_id + compose_hash
- Pin expected values in the client
- Treat domain as untrusted input

---

## CT Monitoring for Custom Domains

CT logs are useful for custom domains (where each app gets its own cert) but not for built-in subdomains (hidden behind wildcard certs).

| What CT logs reveal | Useful? |
|-------------------|---------|
| All certs ever issued for `app.example.com` | Yes — each cert may correspond to a different TEE instance |
| When certs were issued | Yes — unexpected issuance = possible domain redirect |
| Which app_id holds the cert | No — cert doesn't contain app_id (see enhancement below) |
| Cluster topology (wildcard certs) | Yes — dstack clusters enumerable |
| Per-app enumeration on built-in subdomains | No — hidden behind wildcard |

### Monitoring Setup

| Tool | Cost | Notes |
|------|------|-------|
| [Certspotter](https://sslmate.com/certspotter/) | Free | Email alerts on new issuance |
| [crt.sh](https://crt.sh) | Free | Search + Atom feed |
| DNS monitoring (ZoneWatcher, cron+dig) | Free/Paid | Detect TXT record changes |

---

## Enhancement: Embed app_id in TLS Certificates

A useful enhancement (not a critical fix): have dstack-ingress embed the app_id in the TLS certificate itself, so CT logs tie domain to app_id immutably.

**Option A: Custom X.509 extension**
```
X509v3 extensions:
    1.3.6.1.4.1.XXXXX.1 (dstack-app-id):
        db82f581256a3c9244c4d7129a67336990d08cdf
```

**Option B: SAN encoding** (works with existing LE infrastructure)
```
SAN: DNS:app.example.com,
     DNS:_dstack.db82f581256a3c9244c4d7129a67336990d08cdf.app.example.com
```

This would make CT logs not just detect "a new cert was issued" but also "which app_id got it." Nice to have, not required for security.

---

## Retraction Note

The original version of this document (2026-02-20) characterized custom domain routing as an "architectural gap" with "no on-chain evidence" of attacks. This was incorrect:

1. CT logging is mandatory for all publicly trusted certificates
2. A domain redirect attack requires a new cert (different TEE = different encrypted volume)
3. Therefore the attack is always detectable via CT logs
4. The on-chain domain binding proposal was framed as a required fix — it is actually an optional enhancement

The corrected framing: custom domains have a weaker trust model than built-in subdomains (DNS-mutable vs cryptographic), but the attack is detectable. Client SDKs should use attested TLS for strong guarantees.

---

## References

- [Zero Trust HTTPS: Custom Domains on Phala Cloud](https://phala.com/posts/zero-trust-https-how-to-setup-custom-domains-on-phala-cloud)
- [dstack Whitepaper: Zero Trust TLS Protocol](https://docs.phala.com/dstack/design-documents/whitepaper#zero-trust-tls-protocol)
- [dstack Gateway source: tls_passthrough.rs](https://github.com/aspect-build/dstack/blob/main/gateway/src/tls_passthrough.rs)
- [ERC-733 Security Stages](../references/erc733-summary.md)
