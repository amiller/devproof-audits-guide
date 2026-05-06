# Tinfoil Confidential Inference — Audit Analysis

**Audit date:** 2026-04-26
**Domains:** `inference.tinfoil.sh`, `atc.tinfoil.sh`, `api.tinfoil.sh`
**Reference verifier:** [`tinfoilsh/tinfoil-go/verifier`](https://github.com/tinfoilsh/tinfoil-go/tree/main/verifier) (latest tag `v0.12.10`, commit `4652fd1`)
**CVM image:** [`tinfoilsh/cvmimage`](https://github.com/tinfoilsh/cvmimage) (commit `54e49c6`)
**Router:** [`tinfoilsh/confidential-model-router`](https://github.com/tinfoilsh/confidential-model-router) (commit `928034f`, prod pin `v0.0.89` @ `sha256:13faf11e24...`)
**Measurement publisher:** [`tinfoilsh/measure-image-action`](https://github.com/tinfoilsh/measure-image-action) (commit `5a50c52`)
**Re-verifier we wrote:** [`amiller/awesome-private-inference: verifiers/tinfoil.py`](https://github.com/amiller/awesome-private-inference/blob/main/verifiers/tinfoil.py)
**Core question:** Tinfoil's attestation is structurally stronger than the Phala/NEAR family. So *where* is the operator-controllable surface, and is there a backdoor pattern equivalent to the [tee-totalled `LLM_BASE_URL`](../tee-totalled/DEVPROOF-REPORT.md) class?

---

## Executive Summary

### Bottom line — can Tinfoil read your prompts?

**No, not on the live managed-inference deployment, *if* your client actually runs the verifier.** The prompt path is:

```
your client
  └─ HPKE-encrypts prompt to a pubkey bound (in the SEV report) to the attested enclave
  └─ TLS pinned to the cert whose SPKI hash is in report_data[0:32]
  └─ router CVM (config sha256 in launch-measured kernel cmdline; image @sha256-pinned)
  └─ model CVM (config measured the same way; ZERO string-form env, ZERO secrets;
                 weights dm-verity-anchored, traceable to a HuggingFace commit hash)
  └─ vLLM running pinned weights, no operator-tunable runtime config
```

There is no point in that chain where Tinfoil's operator can read or alter your prompt without breaking the SEV launch measurement (Sigstore won't sign for it), the dm-verity Merkle tree (would EIO at page mmap), or the TLS pin (your client wouldn't connect).

> **Terminology — "prompt-path entry."** This report uses *"prompt-path"* as a code-trace test on each operator-controllable config slot (env var or `secrets:` entry that gets its value from the unmeasured external-config disk). An entry is **on the prompt path** if a code trace shows the operator can change its value to intercept, redirect, modify, decrypt, sign, log, or exfiltrate the user's plaintext prompt or response. An entry is **off the prompt path** if no such effect exists — every read site of the value is in code that can't affect plaintext handling (e.g. the value is HMAC'd into a fixed-URL telemetry payload that contains no prompt content, or is used as a hostname filter that can't override TLS pinning to an attested SPKI). The Stage 1 conditional later in this report ("no prompt-path entries in the externally-sourced env/secret lists") is exactly this test applied to each declared slot.

**The dominant practical risk is not on this case study's list at all** — it's whether the client actually runs the verification. A naive `openai.OpenAI(base_url="https://inference.tinfoil.sh/v1", api_key=...)` client doesn't; it just trusts whatever cert TLS hands it. Same backdoor exists for every TEE provider.

### What is proven (✅)

| Layer | Mechanism |
|---|---|
| Hardware attestation | AMD SEV-SNP, parsed by `google/go-sev-guest`, VCEK chain to AMD's Genoa root (in Tinfoil's reference Go verifier) |
| Code measurement reproducibility | Sigstore-signed in-toto statement on each release; predicate carries the full attested `/config.yml` and kernel `cmdline`, both reproducible from public artifacts |
| Container image integrity | Production configs pin by `@sha256:` digest |
| **Model weight integrity** | dm-verity Merkle root in attested config **+** HF `repo@commit` pin alongside; tampered bytes → EIO at page mmap. **Strongest in this registry.** |
| OS rootfs integrity | dm-verity `roothash=` in attested kernel cmdline |
| Live TLS pubkey binding | `report_data[0:32] == sha256(SPKI)` of the live cert; cert SANs also encode the HPKE pubkey + att-doc hash |
| HPKE pubkey attested | `report_data[32:64]`, also encoded in cert SANs |
| Debug-mode disabled | SNP guest policy bit 19 checked |
| Runtime config of model enclaves fully attested | Live audit: gpt-oss-120b, llama3-3-70b, gemma4-31b each have **0** string-form env entries and **0** `secrets:` |

### What is NOT verified — and what each "no" actually means

Different rows. They don't all mean the same thing. **None of them, on the current managed-inference deployment, let Tinfoil read your prompt.**

| Row | What it actually means | Reads prompts? |
|---|---|:---:|
| Runtime config fully attested *(router layer only)* | Schema-level. Boot reads a second disk (`tinfoil-ext-config`) that isn't in the launch measurement. **On the live deployment**, only the router has unattested slots (`DOMAIN`, `USAGE_REPORTER_SECRET`); a code trace through `main.go` and `billing/events.go` shows both are off the prompt path. The model enclaves that actually decrypt prompts have zero unattested slots. The schema *would permit* a future deployment to declare a prompt-path env var this way — that's the structural worry. | **No** |
| RTMR runtime composition | Tinfoil doesn't extend post-boot measurements into RTMR3 (dstack does). They don't need to: rootfs verity hash and config sha256 are *already* in the launch measurement, and nothing post-boot is supposed to change behavior. | **No** — feature unused, not gap |
| Live GPU attestation per request | GPU is verified at boot inside the CVM by NVIDIA's `local-gpu-verifier`; the boot aborts if it fails. NEAR/Phala/Venice expose a fresh NRAS token per request as freshness evidence; Tinfoil's design relies on boot-time validation. | **No** — CPU-resident TEE protects prompt confidentiality; GPU question is about output correctness |
| Per-request client nonce in `report_data` | Layout is fixed at `sha256(TLS pubkey) ‖ HPKE pubkey`; no nonce slot. Tinfoil gets freshness via the live TLS pin (your client opens a connection and sees the SEV-bound cert) instead. | **No** — alternative freshness mechanism |
| VCEK chain → AMD root *(our re-verifier)* | Tinfoil's reference Go verifier walks the chain. Our Python re-verifier defers it (v1). | **No** — limitation in our tool, not Tinfoil's |

### Per-enclave audit results (live, 2026-04-26)

The model-router at `inference.tinfoil.sh` is **not** the same enclave as the model-serving CVM. The router proxies to per-model enclaves with their own deployments, each Sigstore-signed under a per-model repo. Each one was audited separately:

| Enclave | Host | Repo | External env | External secrets |
|---|---|---|---:|---:|
| router (gateway) | `inference.tinfoil.sh` | `confidential-model-router` | **1** (`DOMAIN`) | **1** (`USAGE_REPORTER_SECRET`) |
| gpt-oss-120b | `gpt-oss-120b-0.inf6.tinfoil.sh` | `confidential-gpt-oss-120b` | 0 | 0 |
| llama3-3-70b | `llama3-3-70b.tinfoil.containers.tinfoil.dev` | `confidential-llama3-3-70b` | 0 | 0 |
| gemma4-31b | `gemma4-31b-inf6.tinfoil.containers.tinfoil.dev` | `confidential-gemma4-31b` | 0 | 0 |
| deepseek-v4-pro | `deepseek-v4-pro.tinfoil.containers.tinfoil.dev` | `confidential-deepseek-v4-pro` | — *(TLS EOF — unreachable)* | — |
| kimi-k2-6 | `kimi-k2-6.tinfoil.containers.tinfoil.dev` | `confidential-kimi-k2-6` | — *(TLS EOF — unreachable)* | — |

**The unattested-config surface is router-only.** The CVMs that actually decrypt and process user prompts (the per-model enclaves) declare zero string-form env entries and zero `secrets:` in their attested configs. They run a single container — typically vLLM, image pinned by `@sha256:` — with all env vars hardcoded into the signed `/config.yml`. The router has `DOMAIN` + `USAGE_REPORTER_SECRET` as operator-controllable, but a code trace through [`confidential-model-router/main.go`](https://github.com/tinfoilsh/confidential-model-router/blob/main/main.go) establishes neither is on the prompt path:

- **`DOMAIN`** is consumed exactly once, in `parseModelFromSubdomain` ([`main.go:120-146`](https://github.com/tinfoilsh/confidential-model-router/blob/main/main.go#L120-L146)). It's a host-suffix filter for routing model names from `<model>.<domain>` requests. Operator changes to `DOMAIN` either fall through to body-based routing or produce 404s — cannot redirect ciphertext (TLS pin is to the SEV-bound SPKI, independent of `DOMAIN`) and cannot select a malicious upstream (model→enclave URLs come from the *attested* router config, not from this env var).
- **`USAGE_REPORTER_SECRET`** flows into `billing.NewCollector` ([`billing/events.go:54-71`](https://github.com/tinfoilsh/confidential-model-router/blob/main/billing/events.go#L54-L71)) and HMACs outbound usage reports to `controlPlaneURL + "/api/internal/usage-reports"`. `controlPlaneURL` is *attested* (`CONTROL_PLANE_URL: "https://api.tinfoil.sh"`), so reports cannot be redirected. The report payload ([`events.go:88-106`](https://github.com/tinfoilsh/confidential-model-router/blob/main/billing/events.go#L88-L106)) is `{request_id, timestamp, api_key, input_tokens, output_tokens, model, route, streaming, enclave}` — billing metadata only, no prompt content. The secret is HMAC-only; it cannot decrypt anything or sign anything user-facing.

The router's two operator-controllable knobs are a routing-suffix filter and a billing-HMAC secret. Both can be used for self-DOS or to disrupt Tinfoil-internal accounting. Neither is a path to user-prompt exfiltration on this deployment.

### What actually matters for "are my prompts safe"

1. **Use the verifier.** Either Tinfoil's [SDK](https://github.com/tinfoilsh/tinfoil-go) or our Python [re-verifier](https://github.com/amiller/awesome-private-inference/blob/main/verifiers/tinfoil.py). A bare OpenAI-compatible client without verification gets you the same posture as any non-TEE HTTPS API. **This is the dominant practical risk across all TEE providers.**
2. **Trust in Tinfoil's CI.** Tinfoil's GitHub Actions builds the dm-verity images and produces the Sigstore signatures. The pipeline is open-source; anyone with the disk space can pull HF weights at the pinned commit, rebuild, and check the rootHash matches.
3. **Two unaudited model enclaves.** `deepseek-v4-pro` and `kimi-k2-6` returned TLS EOF before handshake when probed directly — could be transient or intentional gating. Their attested configs were not audited. Routing to those models via `inference.tinfoil.sh` presumably works; we just can't independently verify their CVMs from outside.

---

## Architecture

```
                            CLIENT
                              │
                              │  fetches single bundle
                              ▼
              ┌──────────────────────────────────┐
              │   atc.tinfoil.sh/attestation     │
              │   (Air Traffic Control)          │
              └──────────────────────────────────┘
                              │
              ┌──────────────────────────────────┐
              │  Bundle JSON                     │
              │  ├─ enclaveAttestationReport     │
              │  │    SEV-SNP v3 report          │
              │  │    measurement: <48B>          │
              │  │    report_data:               │
              │  │      [0:32] = sha256(TLS SPKI)│
              │  │      [32:64] = HPKE pubkey    │
              │  ├─ vcek (DER, AMD Genoa cert)   │
              │  ├─ enclaveCert (PEM, SANs encode│
              │  │   HPKE pubkey + att-doc hash) │
              │  ├─ digest (sha256 of            │
              │  │   tinfoil-deployment.json)    │
              │  └─ sigstoreBundle (DSSE)        │
              │      └─ in-toto Statement        │
              │         predicate: {             │
              │           snp_measurement,       │
              │           tdx_measurement,       │
              │           cmdline,               │
              │           hashes,                │
              │           config: <base64 yaml>  │  ← attested config
              │         }                        │
              └──────────────────────────────────┘
                              │
                              ▼
              ┌──────────────────────────────────┐
              │   Sigstore identity policy:      │
              │   ^https://github.com/tinfoilsh/ │
              │      confidential-model-router/  │
              │      .github/workflows/.*        │
              │      @refs/tags/.*               │
              │   Issuer: GitHub OIDC            │
              └──────────────────────────────────┘
                              │
                              ▼
                    Live TLS to bundle.domain
                    (must serve cert with SPKI
                     hash == report_data[0:32])
```

**Key contrast to Phala/NEAR.** Phala-private-ai-verifier (see [phala-private-ai-verifier](../phala-private-ai-verifier/DEVPROOF-REPORT.md)) compares `info.compose_hash` against `sha256(app_compose)` where **both are server-supplied** — a server can lie about both. Tinfoil's `cmdline` is *included in* the SEV launch measurement (the inputs to the SEV `LD_MEASURE` operation), and the cmdline carries `tinfoil-config-hash=<sha256 of the attested config>`. So the config is hardware-bound, not server-asserted. The same Sigstore predicate then republishes the same config bytes for offline auditing. This closes the compose-hash-backdoor pattern that bites Phala/NEAR.

---

## Trust chain we re-verified

Live probes against `https://atc.tinfoil.sh/attestation` on 2026-04-26 returned:

```
domain:                router.inf6.tinfoil.sh   (and inference.tinfoil.sh on subsequent fetches)
digest:                a7a8750deb5131eb9b38292946e0858330d62bbfdd7698bb8426b3719658d6cb
predicate:             https://tinfoil.sh/predicate/sev-snp-guest/v2  (bundle path serves SEV-SNP today)
predicate (sigstore):  https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1
snp_measurement:       a556afbcb97cab8b31606df387c5267e6b420fdd032cdb5681d1b2119155ed70ab936c906aaa4b8993f4947fa92aa006
report_data[0:32]:     3299f439946fe5d41528bd6962ca3a6f4f51cec936fce5e8199bbcb188d465de
report_data[32:64]:    4499f5abdc83cc72d7e6a66c833eaf90635d53ec1d5edfe4629ed279e0024976
live TLS SPKI sha256:  3299f439946fe5d41528bd6962ca3a6f4f51cec936fce5e8199bbcb188d465de   (== report_data[0:32])
hpke from cert SAN:    4499f5abdc83cc72d7e6a66c833eaf90635d53ec1d5edfe4629ed279e0024976   (== report_data[32:64])
hatt from cert SAN:    c0ba3644a9740f5e50cd1d4b90a805afca73f1adb70a183a7f3c2e2a2cca2936   (== sha256(format ‖ body))
```

Every binding holds. Sigstore's signed `snp_measurement` equals the SEV report's `measurement` field. The predicate's `cmdline` carries `tinfoil-config-hash=79badd38...` and the predicate's embedded base64 `config` round-trips to that same sha256.

So we know — **without trusting any `dstack-verifier` sidecar** — that the live `inference.tinfoil.sh` enclave booted from a kernel + initrd + cmdline whose launch measurement equals the value Tinfoil's release CI signed via Sigstore on a GitHub Actions runner under `tinfoilsh/confidential-model-router`. Stronger than any other provider in `awesome-private-inference`.

---

## The runtime-config gap (operator-controllable surface)

Tinfoil's CVM boots with **two** disks of configuration ([`cvmimage/tinfoil/cmd/boot/config.go:91-94`](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/config.go#L91-L94)):

```go
const (
    configDiskPath   = "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_tinfoil-config"
    externalDiskPath = "/dev/disk/by-id/scsi-0QEMU_QEMU_HARDDISK_tinfoil-ext-config"
)
```

The first is integrity-checked against the kernel cmdline's `tinfoil-config-hash=` ([`config.go:97-122`](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/config.go#L97-L122)). The second is read verbatim:

```go
// loadExternalConfig — config.go:189-204
func loadExternalConfig() error {
    if _, err := os.Stat(externalDiskPath); os.IsNotExist(err) {
        return fmt.Errorf("external config disk not found at %s", externalDiskPath)
    }
    data, err := readDiskAndStripNulls(externalDiskPath)
    ...
}
```

No hash. No signature. Whatever the operator writes there is what the boot process reads.

The container schema ([`config.go:49-55`](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/config.go#L49-L55)) deliberately distinguishes the two paths:

```go
// Environment variables:
// - "VAR" (string) = lookup VAR from external-config.yml   ← unattested value
// - "VAR: value" (map) = hardcoded value (attested)
Env []interface{} `yaml:"env,omitempty"`

// Secrets: list of keys to lookup from external-config.yml (sensitive)
Secrets []string `yaml:"secrets,omitempty"`
```

`buildEnv` ([`containers.go:397-432`](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/containers.go#L397-L432)) implements the dispatch: bare strings are looked up in the unattested external config; map-form `KEY: value` entries come from the attested config; `secrets:` always come from the unattested disk and are injected as env vars into the container.

### What the *router's* attested config declares

The router is **one of multiple enclaves**. Its attested `/config.yml` (decoded from the Sigstore predicate, sha256-bound to the launch measurement via cmdline) declares:

```yaml
containers:
  - name: "proxy"
    image: "ghcr.io/tinfoilsh/confidential-model-router@sha256:13faf11e24e8bccad9010b32f9e50df97739d0d33032250b14776d0d183de7bf"
    env:
      - DOMAIN                                  # ← string-form: external (unattested)
      - REFRESH_INTERVAL: "1m"                  # ← map: attested
      - USAGE_REPORTER_ID: "model-router"       # ← attested
      - CONTROL_PLANE_URL: "https://api.tinfoil.sh"  # ← attested
    secrets:
      - USAGE_REPORTER_SECRET                   # ← external (unattested)
```

The router's `main.go` reads each env var via `os.Getenv` and `flag.String(getEnvOrDefault(...))`:

```go
// confidential-model-router/main.go:68,72
usageReporterSecret = flag.String("usage-reporter-secret",
    getEnvOrDefault("USAGE_REPORTER_SECRET", ""), ...)
domain = flag.String("d",
    getEnvOrDefault("DOMAIN", "localhost"), ...)
```

`DOMAIN` controls which hostname the router's TLS cert is issued for — but since the user pins TLS by `sha256(SPKI)` from the attestation, an operator changing `DOMAIN` cannot redirect ciphertext (the TLS handshake to the unfamiliar host would not match the attested SPKI). `USAGE_REPORTER_SECRET` is the HMAC for billing telemetry; abuse is a Tinfoil-internal billing concern, not a user privacy concern.

**On the router specifically, both unattested slots are off the prompt path** (see source-code trace in the Executive Summary).

### What the *model* enclaves' attested configs declare

The router's attested config also lists per-model upstream enclaves
([`confidential-model-router/config.yml`](https://github.com/tinfoilsh/confidential-model-router/blob/main/config.yml)).
Each model enclave is its own CVM with its own Sigstore-signed deployment.
We re-verified each (where reachable) using the `verify_enclave(host, repo)`
path: fetch `/.well-known/tinfoil-attestation` directly from the model
host, fetch the Sigstore bundle for that model's repo via
`github-proxy.tinfoil.sh`, run the same chain.

The model enclaves' attested configs all look like this (gpt-oss-120b
shown; llama3-3-70b and gemma4-31b are equivalent):

```yaml
cvm-version: 0.7.3
containers:
  - name: gpt-oss-120b
    image: vllm/vllm-openai:v0.17.0-cu130@sha256:de06f6d78a2ce86856...
    env:
      - PYTORCH_CUDA_ALLOC_CONF: "..."   # map-form → attested
    # no `secrets:`, no string-form env entries
```

**Zero string-form env entries. Zero `secrets:`. Image pinned by digest.**
The CVM that actually decrypts and processes user prompts has nothing
operator-tunable at runtime. The runtime-config gap exists at the *router*
layer, not at the prompt-path layer.

### Why the schema is still worth surfacing

The schema permits any future Tinfoil deployment — especially third-party `tinfoil.containers.tinfoil.dev` deployments where the operator writes their own `/config.yml` — to declare a prompt-path env var the same way. Examples that would not surface in the launch measurement and would not flag in our re-verifier (until we extended it to enumerate slots):

```yaml
env:
  - LLM_UPSTREAM_URL          # operator-controlled at runtime → exfiltration
  - LOG_TO_S3_BUCKET          # operator-controlled → prompt logging
  - WEBHOOK_URL               # operator-controlled → fan-out
secrets:
  - HF_TOKEN                  # arbitrary credential injection
```

Because the *list* of externally-sourced slots is part of the attested config, a careful auditor can read the signed `/config.yml`, see which slots are bare strings or under `secrets:`, and decide whether to trust those slots given their semantic role in the container code. The verifier we built makes the slot list machine-readable.

This is the same class of problem named in [tee-totalled](../tee-totalled/DEVPROOF-REPORT.md) (`LLM_BASE_URL` as operator-configurable env) and in [xordi-toy-example](../xordi-toy-example/) (`MOCK_API_URL`). Tinfoil's attested-config layer makes the *surface* enumerable, which the others did not — but it does not eliminate the surface.

---

## Model weight integrity

This is the dimension where Tinfoil pulls cleanly ahead of every other provider in the registry. Each model enclave's attested `/config.yml` contains a `models:` section like:

```yaml
models:
  - name: "gpt-oss-120b"
    repo: "openai/gpt-oss-120b@b5c939de8f754692c1647ca79fbf85e8c1e70f8a"
    mpk:  "db5daddec41a3be3b51d1f4d009fb0e9b1243c2765e2bc5121acac79ab070a72_195764056064_0eefa619-50b7-588f-a072-d405fb439d36"

containers:
  - name: "gpt-oss-120b"
    image: "vllm/vllm-openai:v0.17.0-cu130@sha256:de06f6d78a..."
    command: ["--model", "/tinfoil/mpk/mpk-db5daddec41a3be3b51d1f4d009fb0e9b1243c2765e2bc5121acac79ab070a72", ...]
```

Three layers of binding:

1. **`mpk = <rootHash>_<size>_<uuid>`** — the dm-verity Merkle root of the weight bytes. Boot code at [`cvmimage/tinfoil/cmd/boot/models.go`](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/models.go) opens a block device by UUID and runs `veritysetup open ... <rootHash>` against it. vLLM's `--model` argument points at the resulting `/tinfoil/mpk/mpk-<rootHash>` mount. Reads go through the kernel's verity layer — **a single tampered byte produces EIO at the page mmap, not a silent wrong answer.**
2. **`repo = "openai/gpt-oss-120b@b5c939de..."`** — HuggingFace repo + git commit hash. Provenance, not enforcement: it tells an auditor "the dm-verity image we built was built from HF repo X at git commit Y." The commit hash is content-addressed by HF's git layer.
3. **Both fields live inside the Sigstore-signed `/config.yml`**, whose sha256 is in the SEV-launch-measured kernel cmdline (`tinfoil-config-hash=`). So the rootHash and HF pin are bound to the hardware launch, not server-asserted.

What this gets you end-to-end:

- ✅ Operator cannot swap weights at runtime (dm-verity enforces).
- ✅ Operator cannot change which weights are mounted post-build (rootHash is in attested config).
- ✅ Operator cannot silently use a different HF commit (the commit hash is part of the attested config; visible to any auditor pulling the bundle).
- ✅ No `HF_ENDPOINT` style attack: the CVM does not reach out to HuggingFace at boot or runtime. The verity-mounted disk is built once during release CI and shipped with the deployment.

Residual trust assumptions:

- ⚠️ **Tinfoil's release CI correctly translated "HF repo X at commit Y" into the published rootHash.** This is reproducible — anyone can pull the HF weights at the pinned commit, run the same dm-verity build, and check the rootHash matches. We have not run that reproduction in this audit (the weights are 100s of GB per model). The pipeline is open-source and lives in the `tinfoilsh` org alongside the rest of the build chain.
- ⚠️ **HuggingFace honestly serves the content at the pinned commit hash.** This is the same trust as any git host; HF allows force-pushes in some cases but cannot make the same commit hash address two different blobs without breaking sha256.

### Comparison vs other providers in the registry

| Provider | Weight integrity | Mechanism | Verifiable from outside? |
|---|:---:|---|:---:|
| **Tinfoil** | ✅ | dm-verity rootHash in attested config + HF repo+commit pin; enforced at every page read | reproducible from public HF content |
| **NEAR AI** | ❌ | vLLM downloads from HF by *model name only*, no commit pin, no SHA check; persistent `huggingface_cache` Docker volume; `HF_ENDPOINT` operator-configurable ([near-ai-private-inference DEVPROOF-REPORT.md:157-161](../near-ai-private-inference/DEVPROOF-REPORT.md)) | no |
| **Phala (Redpill `phala/*` paths)** | ❌ | inherits NEAR-AI / vLLM-from-HF pattern depending on backend shape | no |
| **Redpill federation** | ❌ | inherits whichever backend it routes to | no |
| **Venice** | ❌ | weights not referenced in any attestation surface | no |
| **Chutes** | ❌ | per-instance E2EE pubkey is hardware-bound, but weights are not | no |

The huggingface_hub library itself does not auto-verify SHA256 ([huggingface_hub#2364](https://github.com/huggingface/huggingface_hub/issues/2364)). Every provider that downloads at runtime by name is exposed to the same class of weight-substitution attacks NEAR AI has.

The "sneakily change weights once and then back" pattern people sometimes worry about: that's prevented at the git layer for any provider that pins by commit hash (Tinfoil) and unprevented for any provider that pulls by name (everyone else in this table). HF's content-addressed storage means a maintainer cannot reuse a commit hash for different content without breaking sha256. So a Tinfoil auditor who archives the deployment's bundle today can detect any future weight tampering by re-deriving the rootHash from HF at the pinned commit.

---

## What the re-verifier does

[`awesome-private-inference/verifiers/tinfoil.py`](https://github.com/amiller/awesome-private-inference/blob/main/verifiers/tinfoil.py) implements an independent re-verifier in Python. The trust chain it walks:

1. Fetch `https://atc.tinfoil.sh/attestation` (no API key required — bundle is public).
2. Parse the SEV-SNP report bytes ([`tinfoil_sev.py`](https://github.com/amiller/awesome-private-inference/blob/main/verifiers/tinfoil_sev.py)) — measurement, report_data, debug bit, version, TCB.
3. Reject if SNP guest policy debug bit (bit 19) is set.
4. Verify the Sigstore in-toto DSSE against a custom `_SanRegexIdentity` policy pinned to `^https://github\.com/tinfoilsh/confidential-model-router/\.github/workflows/[^@]+@refs/tags/[^@]+$` with the GitHub OIDC issuer. (Upstream `sigstore-python.policy.Identity` does exact-string match; we wrote a regex variant to mirror the Go reference's [`sigstore.go:84-93`](https://github.com/tinfoilsh/tinfoil-go/blob/main/verifier/sigstore/sigstore.go#L84-L93) pattern.)
5. Cross-check `predicate.snp_measurement == report.measurement`.
6. Decode the bundle's `enclaveCert` PEM. Check `sha256(SPKI) == report_data[0:32]`. Decode the cert's `dcode`-encoded SANs (`NN<base32>.{hpke,hatt}.tinfoil.sh`) and check the embedded HPKE pubkey == `report_data[32:64]` and the embedded `hatt` hash == `sha256(predicate_format ‖ predicate_body)`.
7. Open a live TLS connection to `bundle.domain` and check the live SPKI hash against `report_data[0:32]`.
8. **Decode the predicate's `config: <base64>`, verify its sha256 matches the `tinfoil-config-hash=` in the predicate's `cmdline`, parse the YAML, and tally per-container: container image (with `image_pinned_by_digest` flag), attested env vars, externally-sourced env vars, externally-sourced secrets.** Set `runtime_config_fully_attested` true only if every container has zero externally-sourced env vars and zero secrets.

Coverage parity with the Go reference verifier (commit `4652fd1`):

| Check | `tinfoilsh/tinfoil-go/verifier` | `verifiers/tinfoil.py` (ours) |
|-------|:---:|:---:|
| SEV-SNP report parse + measurement extract | ✅ | ✅ |
| SEV report VCEK chain → AMD Genoa root | ✅ | ⚠️ deferred to v2 |
| Sigstore DSSE verify w/ regex cert identity | ✅ | ✅ (custom policy class) |
| `predicate.snp_measurement == report.measurement` | ✅ | ✅ |
| `enclaveCert` SAN decode → HPKE pubkey check | ✅ | ✅ |
| `enclaveCert` SAN decode → att-doc hash check | ✅ | ✅ |
| Bundle `enclaveCert` SPKI → `report_data[0:32]` | ✅ | ✅ |
| Live TLS SPKI → `report_data[0:32]` | ✅ (non-bundle path; `enclave_other.go`) | ✅ |
| Debug-mode flag (`policy bit 19`) | ✅ | ✅ |
| **Decode + audit attested `/config.yml`** | ❌ | ✅ |
| **Tally externally-sourced env vars + secrets** | ❌ | ✅ |
| Multi-platform v1 / TDX live host | ✅ | ⚠️ stub (live host is SEV today) |
| HPKE handshake to actually encrypt a prompt | ❌ (out of verifier scope; lives in EHBP client) | ❌ |

The slots-tally is the new contribution. The Go reference confirms the launch measurement matches Sigstore but does not parse the attested `/config.yml` to surface what the operator can change at runtime.

---

## Comparison vs Phala/NEAR family

| | Phala/NEAR (compose-hash gap) | Tinfoil |
|---|---|---|
| Compose hash committed by hardware | ❌ — server-supplied vs server-supplied (`info.compose_hash == sha256(app_compose)`) | ✅ — `tinfoil-config-hash=` in cmdline → SEV launch measurement |
| Container image content pinned | ❌ usually tag | ✅ `@sha256:` digest in attested config |
| Model weights integrity | ❌ — runtime download from HF by name | ✅ dm-verity rootHash + HF commit pin in attested config (see "Model weight integrity") |
| Live TLS fingerprint pinned by client | ❌ | ✅ |
| OS rootfs integrity | varies | ✅ dm-verity `roothash=` in attested cmdline |
| RTMR runtime composition | dstack does it; Phala-private-ai-verifier does not check | ❌ Tinfoil does not extend at all (RTMR3 must be zero) |
| **Operator-controllable env vars / secrets at runtime** | varies (often unbounded) | ⚠️ **bounded** — list of slots is itemized in the attested config; values come from unmeasured disk |
| Per-request client nonce | ✅ | ❌ — freshness via live TLS pin, not a nonce |
| Live GPU NRAS per request | ✅ | ❌ — boot-time only |

Tinfoil closes the compose-hash backdoor that defines the Phala/NEAR class. It introduces a *narrower* operator surface (the external-config disk) which is at least introspectable from the attested config.

---

## Stage Assessment

**ERC-733 Stage:** **Stage 1.** The audit applied the [prompt-path test](../../framework/AUDIT-GUIDE.md#the-prompt-path-test) to every operator-controllable slot in the live deployment and found zero on the prompt path. Re-audit per `/config.yml` rotation; the schema permits new slots to be declared, so each new release needs the same slot-by-slot test.

(Earlier drafts of this report phrased the verdict as "Stage 1, *conditional on* no prompt-path entries." That wording was a hedge — every audit verdict is "conditional on the audit having been done correctly," which is tautological and not informative. The audit DID apply the test; the answer was zero; therefore Stage 1, period. The substantive operational note is "re-audit per release," not a verdict-level conditional.)

Going through the [Stage 1 Checklist](../../README.md#stage-1-checklist):

- [x] **Enclaves attested on-chain** — n/a here (off-chain attestation is published via Sigstore + GitHub Releases; this checkbox is the chain-anchored variant)
- [x] **Code auditable** — all repos open-source under `github.com/tinfoilsh`
- [x] **Community can reproducibly compute code measurement** — `tinfoilsh/measure-image-action` is the published action; `tinfoil-deployment.json` (with `cmdline`, `hashes`, `config`) is the Sigstore-signed subject; the SEV launch measurement is recomputable from OVMF + kernel + initrd + cmdline
- [ ] **Developer has no access to application secrets** — **fails the schema-level test.** `secrets:` in the attested config explicitly declares slots whose values come from the unattested external disk. On the live router this is `USAGE_REPORTER_SECRET` only (off the prompt path), but the schema permits arbitrary additions
- [x] **Well-defined upgrade process with notice period** — version-tagged GitHub Releases of `confidential-model-router` (production pin is `v0.0.89`) with Sigstore-signed deployment artifacts; the digest in the bundle is the only thing a user has to pin to detect upgrade
- [x] **No dependency on centralized infrastructure except TEE vendors** — Sigstore + GitHub Actions OIDC + AMD KDS (vendor) + Intel PCS (vendor; via `tdx-proxy.tinfoil.sh` for the in-flight TDX path). No proprietary KMS like Phala-KMS
- [ ] **No backdoor or debug paths** — debug bit *is* enforced. But the externally-sourced env-var schema is itself a debug-shaped path: an operator can change runtime behavior without a release, without notice, without changing any signed measurement

**The two failing checkboxes are the same finding viewed from two angles.** A Stage 1 Tinfoil deployment is achievable: it requires the attested `/config.yml` to declare zero string-form env entries and zero `secrets:` entries (or for those slots to be on a non-prompt path *and* documented as such in a way the operator cannot quietly change). The current production deployment is one rename away from being on the prompt path.

---

## Recommendations

**For Tinfoil:**

1. **Make external-config slots part of the public verifier matrix.** A user pulling `atc.tinfoil.sh/attestation` and verifying with the upstream Go SDK does not see "this enclave will read N env vars and M secrets from an unmeasured disk." Either expose this in the `GroundTruth` struct returned from `Verify()`, or document that the bundle's `config` field must be parsed and audited separately.
2. **Consider a no-external-config mode** for sensitive deployments. A flag in the attested config that says "this CVM must not read the external-config disk" would let auditable deployments declare themselves exempt from this surface. The boot code would refuse to mount the second disk; the verifier could surface a binary "external_config_disabled" bit.
3. **Extend RTMR3 with `sha256(external-config disk content)`** as an opt-in measurement. This would let operators choose between a low-friction runtime-injectable mode (current) and a stricter mode where the external config is hardware-bound after boot. Symmetric with how dstack extends app-compose into RTMR3.
4. **Document which env vars the production model-router treats as on-prompt-path vs telemetry-only.** The semantics are clear from the source today (`DOMAIN`, `USAGE_REPORTER_SECRET` are off-path) but the user-facing attestation does not say so.

**For our re-verifier (`verifiers/tinfoil.py`):**

5. Add the SEV-SNP launch-measurement re-computation from OVMF + kernel + initrd + cmdline (using `sev-snp-measure` or a vendored Python implementation). This removes the residual trust in Tinfoil's CI to honestly compute `snp_measurement` — currently we trust the Sigstore signer to do it correctly.
6. Add the AMD VCEK chain check to AMD's Genoa root (using `cryptography` for ECDSA P-384 + the embedded `genoa_cert_chain.pem`).
7. Surface the per-container slot list in the dashboard, not just an aggregate boolean.

**For `awesome-private-inference`:**

8. Add a `runtime_config_fully_attested` column to the live matrix. Tinfoil renders ⚠️ today with the slots itemized.

---

## Source Code

- **Re-verifier:** [`amiller/awesome-private-inference: verifiers/tinfoil.py`](https://github.com/amiller/awesome-private-inference/blob/main/verifiers/tinfoil.py), [`verifiers/tinfoil_sev.py`](https://github.com/amiller/awesome-private-inference/blob/main/verifiers/tinfoil_sev.py)
- **Tests + saved bundle fixture:** [`tests/test_tinfoil.py`](https://github.com/amiller/awesome-private-inference/blob/main/tests/test_tinfoil.py), [`tests/fixtures/tinfoil_atc_bundle.json`](https://github.com/amiller/awesome-private-inference/blob/main/tests/fixtures/tinfoil_atc_bundle.json)
- **Tinfoil reference Go verifier:** [`tinfoilsh/tinfoil-go/verifier`](https://github.com/tinfoilsh/tinfoil-go/tree/main/verifier)
- **CVM boot code (where the gap lives):** [`tinfoilsh/cvmimage/tinfoil/cmd/boot/config.go`](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/config.go), [`containers.go`](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/containers.go)
- **Production attested config:** [`tinfoilsh/confidential-model-router/tinfoil-config.yml`](https://github.com/tinfoilsh/confidential-model-router/blob/main/tinfoil-config.yml)
- **Measurement publisher:** [`tinfoilsh/measure-image-action/measure.py`](https://github.com/tinfoilsh/measure-image-action/blob/main/measure.py)

---

## Prior Art

- [phala-private-ai-verifier](../phala-private-ai-verifier/DEVPROOF-REPORT.md) — the SDK Tinfoil's `verifiers/tinfoil.py` is sometimes confused with. Different code path (Phala's Python SDK vs Tinfoil's Go SDK) but Phala does include a Tinfoil verifier of its own using Sigstore golden values.
- [tee-totalled](../tee-totalled/DEVPROOF-REPORT.md) — the canonical example of a single operator-controllable env var (`LLM_BASE_URL`) creating a complete prompt-exfiltration backdoor. Tinfoil's surface is *typed* (the attested config declares which slots), but otherwise the same pattern.
- [xordi-toy-example](../xordi-toy-example/) — `MOCK_API_URL` exfiltration variant.
- [near-ai-private-inference](../near-ai-private-inference/DEVPROOF-REPORT.md) — the inner-boundary / compose-hash gap that Tinfoil's launch-measurement → cmdline → config-hash chain closes.
