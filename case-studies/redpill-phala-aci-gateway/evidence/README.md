# Evidence, 2026-08-18

- `aci-tee.redpill.ai.json`, `aci-inference.phala.com.json` — full ACI attestation
  reports, fetched with fresh 32-byte nonces. Same `workload_keyset_digest`
  (`sha256:c6e808d3…`), distinct TLS SPKI per hostname.
- `sessions.json` — the `/v1/aci/sessions` listing at the time of the audit
  (233 records; the set is dynamic and rotates hourly).

The full `aci sessions --json` audit output is ~24MB and is not kept here;
reproduce it with `aci sessions https://tee.redpill.ai --json`.

Live values at audit time: Compose hash `73fa4608…`, source commit `30296dd`,
os-image-hash `bd369a8c…` (dstack 0.5.9, `is_dev: false`).
