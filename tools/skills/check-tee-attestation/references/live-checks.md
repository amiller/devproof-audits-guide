# Live Checks

Use this file when the user gives a website, domain, app ID, or attestation endpoint.

## Goals

- confirm the site is really using HTTPS
- inspect the live certificate
- find a public attestation surface
- recover dstack metadata when possible
- decide whether TLS is actually bound to attested code

## Common endpoint patterns

### dstack public website

If the host looks like:

`https://<app-id>-443.dstack-pha-prod9.phala.network`

try the matching 8090 endpoint:

`https://<app-id>-8090.dstack-pha-prod9.phala.network/`

The 8090 page often exposes `tcb_info`, including `compose_hash` and `app_compose`.

### Common attestation paths

Try these when the main domain is not itself a 8090 endpoint:

- `/attestation`
- `/attestation/report`
- `/v1/attestation/report`
- `/.well-known/attestation`
- `/quote`

Mark the result as partial if an endpoint exists but does not expose enough material to verify anything meaningful.

## TLS binding checks

### Strong result

Pass TLS binding only when one of these is true:

- the website exposes an attestation response containing the same certificate fingerprint seen in the live TLS handshake
- the app uses a dstack ingress or equivalent attested TLS setup and you can explain that trust boundary precisely
- the protocol binds a public key or certificate hash into `report_data` and the code or live evidence shows the comparison

### Partial result

Warn when:

- the site has valid TLS but no visible attestation binding
- the site appears to rely on a gateway but you cannot verify the gateway's own evidence
- the site uses a custom domain and only standard WebPKI is visible

### Fail result

Fail when:

- HTTPS is broken or absent
- the site only serves HTTP
- the app claims TEE trust but exposes no attestation path and no binding story

## 8090-specific checks

If you can extract `tcb_info.app_compose`, compute its SHA-256 and compare it with `compose_hash`.

Good sign:

- the hash matches
- `allowed_envs` is narrow
- images are pinned by digest

Bad sign:

- `allowed_envs` contains URLs, tokens, keys, or image selectors
- `docker_compose_file` uses `image: ${VAR}`
- `pre_launch_script` exists but is not auditable

## What not to overclaim

- Trust Center success does not imply DevProof.
- A CA-signed cert does not imply attested TLS.
- Public source code does not imply reproducibility.
- A repo match does not imply safe upgrades.
