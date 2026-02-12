# Disintermediation: The DevProof Goal

From "GitHub as a Trusted Execution Environment" (github-zktls paper).

---

## The Core Concept

> Ever since Ethereum introduced programmable money, there has been interest in extending the same trust model—where users verify code rather than reputation—to applications beyond simple token transfers.

The appeal is **disintermediation**:
- A sealed-bid auction where the auctioneer cannot peek at bids
- An exchange where the operator cannot front-run trades
- Identity credentials where the issuer cannot revoke access after the fact

Smart contracts achieve this for on-chain state, but the EVM's constrained execution model pushes real applications off-chain, where trusted intermediaries return.

---

## What TEE Enables

> The security value is not "trust nobody" but **"don't trust the application developer."**

For applications where the threat is developer misbehavior rather than platform compromise, this is the appropriate trust model.

A TEE provides:
1. **Isolated execution** - Code runs protected from tampering
2. **Remote attestation** - Third parties can verify what executed

The key property is that **attestations bind to code, not to the developer's account**. Anyone can fork and run the same code with valid attestations.

---

## Avoiding Reliance on App Developers

> Attestation alone is only partial progress. If the developer controls the only repository running the workflow, they retain power: they can disable the repository, refuse to trigger runs, or hold the service hostage.

ERC-733 calls the goal "developer-proof":
- Not merely that the developer cannot misbehave
- But that this is **provable to users before they interact**

Achieving this requires going beyond attestation to **permissionless operation**.

---

## Commit Binding

The key mechanism is **commit binding**. The attestation includes the exact commit SHA (or compose hash) that produced the artifact.

This means:
- The original author has no privileged role
- Auditors verify the code at the pinned commit, not the author's reputation
- The author cannot silently modify behavior—any change produces a different hash

> This mirrors how smart contracts work: author deploys, network operates, author has no ongoing privilege.

---

## The Warrant Canary Analogy

DevProof is like a warrant canary—proving **absence** rather than detecting presence.

| Security Auditing | DevProof |
|-------------------|----------|
| Looking for vulnerabilities | Proving constraints |
| Intrusion detection | Warrant canary |
| "Is this secure from attackers?" | "Is the developer constrained?" |
| Find the bugs | Verify the trust model |

The on-chain upgrade logs (Base KMS) are the canary: "If I change anything, it shows up here."

---

## What Makes Something DevProof?

From the paper's framing:

1. **Attestation** - Prove what code is running
2. **Commit binding** - Tie attestation to specific, immutable code
3. **Permissionless operation** - Anyone can run the code, not just the author
4. **On-chain transparency** - Every upgrade is publicly logged
5. **No operator discretion** - URLs hardcoded, not configurable

The operator (developer) becomes a **deployment mechanism**, not a trusted party.

---

## Credential Bridging

The paper's applications (GitHub faucet, email NFT, zkTLS) demonstrate **credential bridging**:

> Existing authorities—banks, social platforms, email providers—authenticate users constantly but do not export that authentication in portable forms. Attested computation bridges this gap, turning authentication users already possess into verifiable claims, without requiring cooperation from the original service.

This is disintermediation applied to identity: the user proves ownership to the TEE, the TEE produces an attestation, and downstream systems trust the attestation without trusting the developer who wrote the code.

---

## The DevProof Test

Ask: **Can the developer, at any point after deployment, compromise user privacy or security without leaving a public trace?**

If yes → Stage 0 (ruggable)
If no → Stage 1 (dev-proof)

The public trace requirement is why **Base KMS > Pha KMS**: every compose hash change is logged on-chain, queryable forever.
