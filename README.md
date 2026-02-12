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
| [primus](case-studies/primus/) | 0 | Closed-source core (`libpado.so`), binary blobs |
| [talos](case-studies/talos/) | ~1 | Reproducible builds, but enclave ID verification gap |
| [tee-totalled](case-studies/tee-totalled/) | 0 | `LLM_BASE_URL` operator-configurable (exfiltration) |
| [confer.to](case-studies/confer/) | 0 | Analysis in progress |
| [xordi-toy-example](case-studies/xordi-toy-example/) | **1** | Reference implementation with Base KMS |

## Common Failures

The same patterns appear in every Stage 0 app:

1. **Configurable URLs** - `API_URL=${API_URL}` instead of hardcoded
2. **Pha KMS** - No public upgrade log (can't answer "what ran last week?")
3. **Mutable image tags** - `image:v1.0` instead of `image@sha256:...`
4. **"Known issue" bypasses** - Hash mismatch accepted with comment
5. **Dev fallbacks** - `if DEV_MODE: return hardcoded_key`

See [LEARNINGS.md](LEARNINGS.md) for detailed patterns.

## Framework

- [STAGE-1-CHECKLIST.md](framework/STAGE-1-CHECKLIST.md) - How to verify Stage 1
- [templates/DEVPROOF-REPORT.md](framework/templates/DEVPROOF-REPORT.md) - Gap analysis template
- [templates/DEPLOYMENTS.md](framework/templates/DEPLOYMENTS.md) - Upgrade history template
- [templates/RELEASE-CHECKLIST.md](framework/templates/RELEASE-CHECKLIST.md) - Deploy process

## Tools

- [dstack-audit-plugin](tools/dstack-audit-plugin/) - Claude Code skill for auditing

## References

- [ERC-733 Summary](references/erc733-summary.md) - TEE+EVM security stages
- [Disintermediation](references/disintermediation.md) - The github-zktls framing

## The Goal

> "Not merely that the developer cannot misbehave, but that this is *provable to users before they interact*."
> — GitHub as a Trusted Execution Environment

DevProof is complete when users can verify, before trusting an app with sensitive data, that the developer is as constrained as anyone else.
