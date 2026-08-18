# DevProof

Proving that developers can't rug users. Not security auditing—**trust model verification**.

## What is DevProof?

DevProof is about proving *absence of privileged access*, not finding vulnerabilities. Think warrant canary, not intrusion detection.

TEE apps make strong claims: "your data never leaves the enclave," "the operator can't see your messages." These claims are often partially true. DevProof finds the partial parts.

**The core insight**: TEE protects against the **cloud provider**. It does NOT protect against the **operator**. The operator controls which code runs, which environment variables are set, when to upgrade. Users verify attestation and think they're safe—but they're trusting that the operator configured things correctly.

## ERC-733 Security Stages

[ERC-733](references/erc733-summary.md) defines a progression from prototype to trustless:

| Stage | Name | Definition |
|-------|------|------------|
| **0** | Prototype/Ruggable | TEE improves security but developer remains single point of failure |
| **1** | **Dev-Proof** | Developer cannot unilaterally alter, censor, or exfiltrate without notice period |
| **2** | Decentralized TEE | Multiple enclaves/vendors, no single party controls |
| **3** | Trustless TEE | ZK hybrids, multi-vendor cross-attestation |

**Stage 1 is the goal.** Every project can reasonably achieve it with attention to detail.

## Stage 1 Checklist

From ERC-733 (fail any = Stage 0):

- [ ] Enclaves attested on-chain
- [ ] Code auditable (open source or formal verification)
- [ ] Community can reproducibly compute code measurement
- [ ] Developer has no access to application secrets
- [ ] Well-defined upgrade process with notice period
- [ ] No dependency on centralized infrastructure except TEE vendors
- [ ] No backdoor or debug paths

See [framework/STAGE-1-CHECKLIST.md](framework/STAGE-1-CHECKLIST.md) for detailed verification steps.

## Case Studies

| Project | Stage | Key Issue |
|---------|-------|-----------|
| [hermes](case-studies/hermes/) | 0 | Pha KMS (no public upgrade log), mutable image tags |
| [near-private-chat](case-studies/near-private-chat/) | 0 | Backend routing unverified, 56 compose hashes authorized |
| [near-ai-private-inference](case-studies/near-ai-private-inference/) | 0 | Inner compose not in RTMR3, model weights unverified, operator log access |
| [primus](case-studies/primus/) | 0 | Closed-source core (`libpado.so`), binary blobs |
| [talos](case-studies/talos/) | ~1 | Reproducible builds, but enclave ID verification gap |
| [tee-totalled](case-studies/tee-totalled/) | 0 | `LLM_BASE_URL` operator-configurable (exfiltration) |
| [tokscope-xordi](case-studies/tokscope-xordi/) | 0 | v1.1.2: images public, repro builds improved; still `${VAR}` image refs, Pha KMS |
| [confer.to](case-studies/confer/) | 0 | Analysis in progress |
| [venice-private-inference](case-studies/venice-private-inference/) | 0 | ECIES wire protocol works; `veniceai/skills` misnames it "HPKE/Noise", omits every TDX-verification step |
| [phala-private-ai-verifier](case-studies/phala-private-ai-verifier/) | 0 | Attestation-only SDK; no E2EE code, `signing_public_key` never read, "verified" is not confidentiality |
| [tinfoil-confidential-inference](case-studies/tinfoil-confidential-inference/) | ~1 | Closes the Phala/NEAR compose-hash gap (config sha256 in launch-measured cmdline). Model weights are dm-verity-anchored with HF commit pinned in the attested config — runtime tampering produces EIO, no HF-by-name fetch like NEAR AI. Per-model enclaves fully attested; router has 2 externally-sourced slots (`DOMAIN`, `USAGE_REPORTER_SECRET`) — code-trace-shown to be off the prompt path |
| [xordi-toy-example](case-studies/xordi-toy-example/) | **1** | Reference implementation with Base KMS |
| [aci-protocol](case-studies/aci-protocol/) | — (protocol) | First **protocol** study in the guide. ACI is transparency-and-binding, not impossibility: a fully conformant service can still be Stage 0 (no upgrade history, no notice period, no transparency-log anchor). Top gap **P1**: nothing attested tells a client whether a host forces attested serving — the guard (`provider.aci_verified`) is opt-in and invisible pre-send, so a verified workload can forward your plaintext to a commercial API and disclose it afterward on a receipt that still verifies |
| [redpill-phala-aci-gateway](case-studies/redpill-phala-aci-gateway/) | 0 | Current RedPill/Phala surface, replacing the dead `api.red-pill.ai`. Chain is sound and reproducible (quote→keyset→SPKI→measured Compose; receipts verify end-to-end; **production** dstack OS as of 2026-08-18, `is_dev:false` independently resolved). Top gap **G1**: the legacy `/v1/attestation/report` ignores its `model` parameter, returning a passing gateway-scoped attestation for `claude-opus-5` and for models that don't exist |
| [trustedrouter-confidential-router](case-studies/trustedrouter-confidential-router/) | ~1 | First **GCP Confidential Space** study. Clean chain (Google-signed EAT JWT, `eat_nonce[0]==SHA-256(TLS leaf)`, digest==published) and routing is locked/attested (hardcoded upstream URLs, control plane can't inject). Top gap **G6**: shared ACME TLS **private key** cached in operator-readable GCS (CMEK not image-bound) → operator can MITM with the genuine cert + relayed attestation, which per-session verification cannot catch. Prompts not persisted; upgrades mooted by verify-each-session |

## Common Failures

The same patterns appear in every Stage 0 app:

1. **Configurable URLs** - `API_URL=${API_URL}` instead of hardcoded
2. **Pha KMS** - No public upgrade log (can't answer "what ran last week?")
3. **Mutable image tags** - `image:v1.0` instead of `image@sha256:...`
4. **"Known issue" bypasses** - Hash mismatch accepted with comment
5. **Dev fallbacks** - `if DEV_MODE: return hardcoded_key`

See [LEARNINGS.md](LEARNINGS.md) for detailed patterns.

## Framework

- [DOMAIN-BINDING-GAP.md](framework/DOMAIN-BINDING-GAP.md) - Custom domain routing gap (affects all dstack apps)
- [APP-MEASUREMENT-HOOK.md](framework/APP-MEASUREMENT-HOOK.md) - Cross-vendor confidential-inference gap: no app-facing way to bind code/model into the quote (model substitution + prompt exfil)
- [STAGE-1-CHECKLIST.md](framework/STAGE-1-CHECKLIST.md) - How to verify Stage 1
- [templates/DEVPROOF-REPORT.md](framework/templates/DEVPROOF-REPORT.md) - Gap analysis template
- [templates/DEPLOYMENTS.md](framework/templates/DEPLOYMENTS.md) - Upgrade history template
- [templates/RELEASE-CHECKLIST.md](framework/templates/RELEASE-CHECKLIST.md) - Deploy process

## Tools

### Verification Scripts
- **[verify-compose-hash.py](tools/verify-compose-hash.py)** - Verify compose hash from 8090 endpoint
  ```bash
  ./tools/verify-compose-hash.py <app-id> [cluster]
  # Example: ./tools/verify-compose-hash.py f44389ef4e953f3c53847cc86b1aedc763978e83 dstack-pha-prod9
  ```

### External Tools
- **Trust Center UI**: [trust.phala.com](https://trust.phala.com) - Visual attestation verification
- **[@phala/dstack-verifier](https://github.com/Phala-Network/trust-center/tree/main/packages/verifier)** - Full attestation verification library
- **[dstack-mr](https://github.com/kvinwang/dstack-mr)** - OS measurement computation
- **[dcap-qvl](https://github.com/Phala-Network/dcap-qvl)** - TDX quote verification

### Data Sources (for third-party auditing)
- **8090 endpoint**: `https://<app-id>-8090.<cluster>.phala.network/` - TCB info, app_compose, event log
- **Note**: `phala cvms attestation` only works for apps you own - useless for third-party auditing

### Claude Code Skills
- [dstack-audit-plugin](tools/dstack-audit-plugin/) - Automated audit skill

## References

- [ERC-733 Summary](references/erc733-summary.md) - TEE+EVM security stages
- [Disintermediation](references/disintermediation.md) - The github-zktls framing

## The Goal

> "Not merely that the developer cannot misbehave, but that this is *provable to users before they interact*."
> — GitHub as a Trusted Execution Environment

DevProof is complete when users can verify, before trusting an app with sensitive data, that the developer is as constrained as anyone else.
