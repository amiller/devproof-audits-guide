# Case Studies

Use these comparisons when the user wants concrete examples or when the checker finds a familiar failure mode.

## Positive or relatively strong patterns

### `near-private-chat`

Useful for:

- attestation endpoint discovery
- dstack 8090 metadata extraction
- TLS certificate binding concepts

Watch for:

- backend attestation fetching without full verification

### `talos`

Useful for:

- strong repo-to-image comparison
- showing that repo-to-artifact matching is possible and valuable

Watch for:

- image match alone still does not solve upgrade transparency

## Common failure patterns

### `xordi-toy-example`

Useful for:

- Stage 0 classification
- compose hash exists but reproducibility is incomplete
- runtime configurability still matters

### `tokscope-xordi`

Useful for:

- `image: ${VAR}` as an audit blind spot
- release notes that claim a digest without binding it into attested config

This is the clearest example for "the repo looks okay, but the operator still controls what actually runs."

### `primus`

Useful for:

- image-only auditability
- explaining the difference between "on GitHub" and "actually auditable"

## Tutorial mapping

- Attestation and reference values: repo-to-live hash reasoning
- Gateways and TLS: browser HTTPS vs attested TLS
- On-chain authorization: upgrade transparency and timelock pressure

When you cite a case study, tie it to the current finding instead of name-dropping multiple examples.
