# ERC-733: TEE-EVM Co-processing

Summary of the security stages framework from ERC-733.

**Source**: [draftv4.erc733.org](https://draftv4.erc733.org)
**Authors**: Justin Zhang (@voidcenter), Andrew Miller (@amiller)

---

## Why TEE+EVM?

> EVM and TEE share a common design principle: **removing trust in the application developer**.
> - EVM achieves this through decentralized consensus
> - TEE through hardware isolation and vendor-endorsed attestation

Both enable permissionless innovation by eliminating the need for developers to build trusted reputations.

---

## Security Stages

### Stage 0: Prototype / Ruggable

The application uses TEE but trust chains are incomplete. The developer or host remains a single point of failure.

**Outcome**: TEE improves security relative to plain cloud hosting but offers no verifiable guarantee that the developer cannot rug.

**This is the default starting point for every project.**

---

### Stage 1: Dev-Proof

The developer can no longer unilaterally alter, censor, or exfiltrate sensitive data without a notice period. TEE integrity is cryptographically verifiable and all major trust links are visible to external parties.

**Outcome**: The system is developer-proof—a compromised or malicious developer cannot violate the application's stated integrity or privacy guarantees, though availability may still depend on them.

**Stage 1 Requirements** (fail any = Stage 0):
- Enclaves are attested on-chain
- Project code is auditable through open-source or formal verification
- The community can reproducibly compute the code measurement
- The developer has no access to the application secrets
- There is a well-defined upgrade process with a notice period
- There is no dependency for integrity or privacy on centralized infrastructure except TEE vendors
- The project has no backdoor or debug paths

**Every project can reasonably achieve Stage 1 with attention to detail.**

---

### Stage 2: Decentralized TEE Network

Privilege is further distributed. Multiple enclaves, vendors, or governance actors share control so that no single party can censor, upgrade, or recover the system unilaterally.

**Outcome**: Practical decentralization—integrity and privacy are preserved even under developer or vendor failure.

**Additional Stage 2 requirements**:
- Not dependent on centralized infrastructure
- Multi-TEE deployment for redundancy
- Responsive to TCB updates
- No vendor lock-in (redundant across Intel TDX, AMD SEV, Nitro)
- Forward secrecy & data opt-out
- Long-term reproducibility (builds/attestations mirrored)
- Permissionless operation (any operator can join)
- Governance can veto faulty vendor TCB info

**Stage 2 is what powerful projects should aspire to but might be a significant challenge.**

---

### Stage 3: Trustless TEE

Enclaves coordinate through cryptographic verification (TEE × ZK hybrids or multi-vendor cross-attestation) such that neither developers, cloud hosts, nor hardware vendors are single points of failure.

**Outcome**: Fully trustless confidential computation.

**Additional Stage 3 requirements**:
- MPC DKG and signing
- Independent of Intel sealing key
- Indistinguishability obfuscation

**Stage 3 may be out of range of current techniques.**

---

## Comparison Table

| Requirement | Stage 1 | Stage 2 | Stage 3 |
|-------------|---------|---------|---------|
| On-chain attestation | Yes | Yes | Yes |
| Code auditable | Yes | Yes | Yes |
| Reproducible measurement | Yes | Yes | Yes |
| Dev has no access to secrets | Yes | Yes | Yes |
| Upgrade process | Notice period | DAO governance | DAO governance |
| No backdoors | Yes | Yes | Yes |
| No centralized infra | No | Yes | Yes |
| Multi-TEE redundancy | No | Yes | Yes |
| Responsive to TCB updates | No | Yes | Yes |
| No vendor lock-in | No | Yes | Yes |
| Permissionless operation | No | Yes | Yes |
| MPC DKG | No | No | Yes |
| Independent of sealing key | No | No | Yes |

---

## Key Insight

> The goal is "developer-proof"—not merely that the developer cannot misbehave, but that this is **provable to users before they interact**.

Most failure modes in TEE-based systems trace back to lingering reliance on the original developer, through sealing keys, upgrade mechanisms, or operational control.

---

## Reference Implementations

From ERC-733 Appendix F:

**Attestation Layer**:
- [Flashtestations](https://github.com/flashbots/flashtestations)
- [Dstack TEE](https://github.com/Dstack-TEE/dstack)
- [Oasis ROFL](https://docs.oasis.io/build/rofl/)

**On-Chain Registries**:
- [Automata CVM Registry](https://github.com/automata-network/automata-tee-workload-measurement)
- [Flashtestations Registry](https://github.com/flashbots/flashtestations)
- [Sparsity TEE Registry](https://github.com/sparsity-xyz/tee-registry-RI)

**KMS**:
- [Dstack KMS](https://github.com/Dstack-TEE/dstack/tree/master/kms)
- [Oasis Key Management](https://oasis.net/blog/decentralized-key-management-agents)
