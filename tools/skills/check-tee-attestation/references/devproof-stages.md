# DevProof Stages

Use this reference when converting raw evidence into a trust verdict.

## Core distinction

Security asks whether the enclave and code identity are genuine.
DevProof asks whether the developer or operator can still rug the user anyway.

## Stage meanings

### Unproven

Use this when the evidence is too thin to establish even a basic TEE trust story.

Typical reasons:

- no live attestation endpoint
- no repo or no deployable source
- website reachable only over plain HTTP
- certificate exists but no TEE binding evidence

### Stage 0: Security-only TEE

Use this when the deployment appears to run in a TEE, but the operator still keeps a meaningful trust handle.

Typical blockers:

- operator-configurable URLs or backends
- image references hidden behind `${VAR}`
- secrets or key material injected outside TEE controls
- reproducibility not demonstrated
- upgrades are immediate and opaque
- website TLS is conventional only, with no attested binding

### Stage 1 candidate: DevProof

Use this only when the public evidence supports all of these:

- attestation is externally checkable
- repo or artifact is meaningfully auditable
- deployment can be connected back to the audited artifact
- reproducibility is plausible and documented
- operator configuration cannot silently swap security-critical behavior
- upgrades are publicly visible, and timelock is preferred

Say `candidate` because a skill run is still not a substitute for a full human audit.

## What to score heavily

### Highest weight

- operator gap
- attestation coherence
- repo-to-deployment traceability

### Medium weight

- TLS binding
- reproducibility
- upgrade transparency

### Lower weight

- conventional code hygiene

Conventional security bugs matter, but this skill's primary job is to identify trust-model failures that make TEE claims misleading.
