# Redpill Federated TEE Inference — Audit Analysis

> [!IMPORTANT]
> **Historical — this subject no longer exists.** `api.red-pill.ai` returns 502 on every
> path as of 2026-08-18, and the per-model `/v1/attestation/report` shapes analysed below
> are gone with it. RedPill's current surface is the ACI gateway at `tee.redpill.ai`,
> audited in [redpill-phala-aci-gateway](../redpill-phala-aci-gateway/), with the protocol
> itself in [aci-protocol](../aci-protocol/).
>
> Two findings from this report carried forward and are worth reading here for the lineage:
> the dev-OS operator root-SSH path (fixed — the current gateway runs the production dstack
> image, verified 2026-08-18), and "a verified quote is not a verified model", which
> reappears on the current deployment's legacy compatibility endpoint as **G1**.
>
> One claim in this report could not be reproduced in 2026-08: that the production dstack
> image "installs no sshd and runs `disable_login()`". The published prod and dev 0.5.9
> archives carry the same `openssh` strings. Treat the prod/dev distinction as resting on
> the cryptographically bound `is_dev` flag, not on a demonstrated absence of sshd.

**Server-side audit:** 2026-04-20 (verifier-shape probe)
**Backdoor audit:** 2026-04-28 (compose-level inspection of all 21 `phala/*` models)
**Domain:** `api.red-pill.ai`
**Core Question:** Does Redpill's `phala/*` catalog, when verified by a client
following the published verifier, give a meaningful guarantee that end-user
queries cannot be leaked or backdoored by the host operator?

---

## Executive Summary

**A client that runs the published verifier and gets `verified: true` on a
`phala/*` model has not ruled out operator access to plaintext queries.**

The headline observation: **every Redpill phala-simple CVM is booted from
`dstack-nvidia-dev-0.5.8` — Phala's *development* OS image, not the
production image.** Comparing the two recipes in
[Dstack-TEE/meta-dstack](https://github.com/Dstack-TEE/meta-dstack):

| | `dstack-rootfs-dev.inc` | `dstack-rootfs-prod.inc` |
|---|---|---|
| openssh server | installed (`packagegroup-core-ssh-openssh`) | not installed |
| `debug-tweaks` Yocto feature | enabled | not enabled |
| `tools-profile` (strace/gdb/tcpdump/gdbserver/vim) | enabled | not enabled |
| `getty`, `agetty`, `/usr/bin/login` | present | postprocess-stripped |
| `IMAGE_FEATURES` | (none added) | `nologin` |

On top of that dev base image, the application compose explicitly enables
the host-injected SSH key path: every compose lists
`DSTACK_AUTHORIZED_KEYS` in `allowed_envs`, and the measured
`pre_launch_script` writes that env var into
`/home/root/.ssh/authorized_keys`. The compose hash measures the *name*
of the env var, not its *value*; the value is host-supplied at boot and
not part of the attested measurement. The two halves wire up: the dev
image ships a real sshd, the compose enables host injection of a real
authorized_keys file. Result: the host operator can SSH in as root
post-attestation, and the verifier still returns `verified: true`. See
[Backdoor finding #1](#1-host-ssh-via-dstack_authorized_keys-injection-on-the-dstack-nvidia-dev-image).

**Reachability scope (2026-04-28 probe).** tcp/22 on the public per-model
domains (e.g. `gpt-oss-20b.use1.phala.com → 134.199.130.191`) is
closed/filtered to the public internet; tcp/80 and tcp/443 are open. So
the SSH backdoor is reachable from the host network namespace only —
i.e. by the host operator, not by arbitrary external attackers. This is
the threat model the audit cares about: a TEE that can be inspected from
inside the host doesn't keep operator-side promises.

The verifier's other checks (TDX quote, GPU NRAS, `compose_hash →
mr_config`, on-chain DCAP) all pass and are sound. The gap is that the
verifier validates the *attestation* without validating the *compose
contents* — it has no `checkComposePolicy` step. So a dev-grade image
plus operator-key injection produces an attestation indistinguishable
from a production-grade deployment.

The original (2026-04-20) framing called this out as "shape dispatch is
undocumented" and concluded *"Privacy posture: competitive with NEAR AI
and Phala direct."* That conclusion is withdrawn. See **Phala-direct
backdoor audit** below.

| Backend shape           | Attestation class | What the verifier must do                          | Probe time (p50) |
|-------------------------|-------------------|----------------------------------------------------|-----------------:|
| `phala-simple`          | Phala TDX + GPU   | Top-level `intel_quote` + NRAS GPU                 | ~3s              |
| `nearai-via-redpill`    | NEAR AI gateway   | `gateway_attestation` + `model_attestations[]` (re-uses NEAR AI verifier) | 3–80s   |
| `chutes`                | Chutes TDX        | `all_attestations[]` × 5 instances, anti-tamper binding, debug-mode check | 35–94s  |
| `tinfoil` (unobserved)  | Tinfoil hw-policy | Sigstore golden values, hw policy attestation     | —                |

**The shape is not in the OpenAPI spec.** The only way to know which
verifier to run is to inspect the response JSON:

```python
if report.get("attestation_type") == "chutes":
    return verify_chutes(report, ...)
if "gateway_attestation" in report:
    return verify_nearai_gateway(report, ...)
if "intel_quote" in report:
    return verify_phala_simple(report, ...)
return fail("Unrecognized attestation response format")
```

This is a documentation gap, not a soundness bug — but it's load-bearing
for anyone building strict client-side verification.

---

## Phala-direct backdoor audit (2026-04-28)

Pulled `app_compose` for every `phala-simple` model out of
`info.tcb_info.app_compose` (the verifier's own data path; same field
checked by `cloud-api.ts:checkCompose`). 21 `phala/*` models in catalog,
8 routed to phala-simple, **5 distinct composes** after deduplication.
Raw composes saved under `composes/`.

| compose_hash (16) | models advertised on Redpill                                                              | served-model-name in compose                                       | OS image                              |
|-------------------|-------------------------------------------------------------------------------------------|--------------------------------------------------------------------|---------------------------------------|
| `c3f19eb2a4d97aa0` | `phala/gpt-oss-20b`, `phala/gemma-3-27b-it`                                              | `openai/gpt-oss-20b`, `google/gemma-3-27b-it`                      | `dstack-nvidia-dev-0.5.8-e3e677dd`    |
| `9683a8f8b3d3e566` | `phala/glm-4.7-flash`                                                                    | `zai-org/GLM-4.7-Flash` (sglang)                                   | `dstack-nvidia-dev-0.5.8-021bf66a`    |
| `b303b44ff3bf49f0` | `phala/qwen-2.5-7b-instruct`, `phala/qwen2.5-vl-72b-instruct`, `phala/qwen3-vl-30b-a3b-instruct` | `qwen/qwen-2.5-7b-instruct`, `qwen/qwen3-vl-30b-a3b-instruct` (no entry for 72b) | `dstack-nvidia-dev-0.5.8-e3e677dd`    |
| `7ac6727adb3fc9a9` | `phala/qwen3.5-27b`                                                                      | `Qwen/Qwen3.5-27B` (sglang `:dev` tag)                             | `dstack-nvidia-dev-0.5.8-f2e62bc7`    |
| `5c809c592b57e6f3` | `phala/uncensored-24b`                                                                   | `phala/uncensored-24b`, `BAAI/bge-reranker-v2-m3`, `Qwen/Qwen3-Embedding-8B` | `dstack-nvidia-dev-0.5.8-021bf66a`    |

All 5 composes share the same operator-control surface: identical
`allowed_envs`, identical `pre_launch_script`, identical KMS/gateway
config. The findings below apply to every passing `phala-simple`
attestation in the catalog.

### 1. Host SSH via `DSTACK_AUTHORIZED_KEYS` injection on the `dstack-nvidia-dev` image

Two pieces wire this up:

**(a) The OS image is the dev variant.** Every phala-simple CVM boots
`dstack-nvidia-dev-0.5.8-*` (visible in `vm_config.image` of every
attestation). The recipe `recipes-core/images/dstack-rootfs-dev.inc` in
[Dstack-TEE/meta-dstack](https://github.com/Dstack-TEE/meta-dstack)
adds:

```
IMAGE_INSTALL += "packagegroup-core-ssh-openssh strace tcpdump gdb gdbserver vim"
EXTRA_IMAGE_FEATURES += "debug-tweaks tools-profile"
```

vs. the production recipe `dstack-rootfs-prod.inc` which sets
`IMAGE_FEATURES += "nologin"` and runs a `disable_login()` postprocess
that explicitly removes `getty`, `agetty`, `/usr/bin/login`,
`/usr/bin/loginctl`, `systemd-tty-ask-password-agent`, and the related
systemd targets. The prod image installs *no* openssh package. The dev
image installs sshd plus standard forensic tooling (strace, gdb,
gdbserver, tcpdump).

`debug-tweaks` is a stock Yocto feature whose effects include allowing
empty root password and disabling other authentication tighteners;
`tools-profile` adds the standard debug toolchain. Neither belongs in a
confidential-inference deployment.

**(b) The compose enables host SSH key injection.** Every compose's
`allowed_envs` contains `DSTACK_AUTHORIZED_KEYS`, and the measured
`pre_launch_script` contains:

```bash
if [[ -n "$DSTACK_AUTHORIZED_KEYS" ]]; then
    echo "$DSTACK_AUTHORIZED_KEYS" > /home/root/.ssh/authorized_keys
    unset $DSTACK_AUTHORIZED_KEYS
    echo "Root authorized_keys set"
fi
```

`allowed_envs` is a list of variable *names* the host is permitted to
set inside the CVM at boot
([dstack-types `AppCompose.allowed_envs`](https://github.com/Dstack-TEE/dstack/blob/main/dstack-types/src/lib.rs)).
The names are measured into the compose hash; the *values* are not. The
host puts any SSH public key into `DSTACK_AUTHORIZED_KEYS` at CVM start,
the boot script writes it into root's authorized_keys, and the dev
image's sshd accepts the connection. The verifier still returns
`verified: true`.

**Reachability.** Public probes against the per-model domains served by
this fleet (`gpt-oss-20b.use1.phala.com`, etc., all resolving to
`134.199.130.191`) show tcp/22 closed/filtered. So the SSH path is not
internet-exposed on these CVMs — it is reachable from the host network
namespace, which is the operator. The threat model is "operator
backdoor", not "public attacker backdoor".

**Fleet scope.** This is not one stray CVM. Probing all 8 phala-simple
models in the Redpill catalog yields 5 distinct CVMs (some serve
multiple models), and **all 5 boot dev images** — three different dev
versions: `dstack-nvidia-dev-0.5.5`, `-0.5.6`, `-0.5.8`. By contrast,
the NEAR AI model fleet that Redpill federates to runs the production
image `dstack-nvidia-0.5.5` (no `-dev`). So Redpill's *own* dstack
deployments are dev across the board, while the only fleet plainly
visible as prod is operated by a different team. Full per-model
inventory and a one-liner you can run yourself:
[`fleet-inventory.md`](./fleet-inventory.md).

**What an operator gets from a root shell inside the CVM:**

- read `/proc/<vllm-pid>/mem` to dump prompts/responses in flight,
- read the ZFS-encrypted persistent volume (KMS-released key is already
  unsealed at this point),
- exfil the per-CVM ECDSA signing key used to sign responses,
- attach to the privileged `vllm-proxy` container (see finding #5).

Severity: **critical**. Present on every phala-simple compose, no
exceptions. The dev-image choice is the load-bearing piece — even with
`DSTACK_AUTHORIZED_KEYS` in `allowed_envs`, the prod image has no sshd
to receive the connection. Switching the OS image to the prod variant
neutralises the path without touching the compose.

### 2. Mutable image tags, no `@sha256:` digest pinning

| Image                           | Used by composes      | Tag form    |
|---------------------------------|-----------------------|-------------|
| `vllm/vllm-openai:latest`       | b303b44, 5c809c5      | floating    |
| `vllm/vllm-openai:v0.10.2`      | c3f19eb, b303b44      | semver tag  |
| `lmsysorg/sglang:dev`           | 7ac6727               | floating    |
| `lmsysorg/sglang:v0.5.10`       | 9683a8f               | semver tag  |
| `dstacktee/vllm-proxy:v0.2.18`  | all five              | semver tag  |
| `dstacktee/dstack-ingress:1.2`  | all five              | semver tag  |
| `haproxy:2.9-alpine`, `redis:7-alpine`, `python:3.10-slim`, `alpine:latest` | all five | tag |

None of the runtime images are pinned by `@sha256:` digest.
`compose_hash` measures the literal text of the compose file, so the tag
*string* is bound — but the bytes the registry returns for that string
can change. Two of these tags (`vllm/vllm-openai:latest`, `lmsysorg/sglang:dev`)
are explicitly mutable. A registry-side republish (or a registry
compromise, or a DNS/CA-level hijack of `docker.io` reachable from the
host) substitutes any container without changing the attested
`compose_hash`. The verifier's Sigstore step (`cloud-api.ts:checkSigstore`)
also runs against `@sha256:` digests inside the compose text — there are
none — so the check is a no-op for every phala-simple model.

Severity: **high**. Compose-hash equality does not establish image
identity for any phala-simple model.

### 3. Model-name routing without attestation binding

`phala/qwen2.5-vl-72b-instruct` is in the Redpill catalog and its
`/v1/attestation/report` returns the `b303b44ff3bf49f0` compose. That
compose has only two vLLM services with `--served-model-name`:
`qwen/qwen-2.5-7b-instruct` and `qwen/qwen3-vl-30b-a3b-instruct`. The
72b name is not present anywhere in the docker-compose. Either Redpill's
gateway silently rewrites the request to one of the two served names, or
the request fails — but the attestation a client receives doesn't say
which.

Compose `c3f19eb2` similarly serves both `phala/gpt-oss-20b` and
`phala/gemma-3-27b-it` from one CVM. The attestation report is identical
for both model names; nothing in the signed payload tells the verifier
which haproxy backend served the user's specific request.

Severity: **high** for the 72b case (model substitution invisible to the
verifier), **medium** for the multi-tenant CVMs (no per-query model
binding).

### 4. Model weights pulled from HuggingFace at boot, no content pinning

Every compose runs a `model-downloader` service:

```yaml
command: >
  sh -c "pip install -U huggingface_hub[cli] && hf download
  RedHatAI/Qwen2.5-7B-Instruct-FP8-dynamic --max-workers 20"
environment:
  - HUGGING_FACE_HUB_TOKEN=${HF_TOKEN}
```

`HF_TOKEN` is in `allowed_envs` (host-supplied). The compose pins the
model *name* (`RedHatAI/Qwen2.5-7B-Instruct-FP8-dynamic`) but not a
content digest of the weight files. Threat paths:

- HF could serve different weights for the same name (HF supports
  versioning but the compose doesn't pin a revision).
- A host-supplied `HF_TOKEN` could grant access to a private mirror that
  the operator controls.
- The CVM resolves `huggingface.co` through the host's network; nothing
  in the measurement prevents host-level interception.

Severity: **high**. Inference outputs are only as trustworthy as the
weights, and the weights are not measured.

Note: several composes load *quantized* variants
(`RedHatAI/...-FP8-dynamic`, `Qwen3-VL-30B-A3B-Instruct-FP8`) and serve
them under a non-quantized name (`qwen/qwen-2.5-7b-instruct`,
`google/gemma-3-27b-it`). This is disclosed in the compose but not in
Redpill's model catalog page.

### 5. Privileged containers with `/var/run/dstack.sock` mounted

`vllm-proxy` (the component that signs responses with the CVM's
attested key) runs `privileged: true` and bind-mounts
`/var/run/dstack.sock`. A bug or compromise in `dstacktee/vllm-proxy:v0.2.18`
becomes full CVM root and full signing-key compromise. Every compose
runs at least one `privileged: true` service (1–3 per compose).

Severity: **medium**. The proxy itself is open source
([Dstack-TEE/vllm-proxy](https://github.com/Dstack-TEE/vllm-proxy)) so
review is possible — but see #2: the running image is not pinned to the
reviewed source.

### 6. `secure_time: false` on every compose

No monotonic time guarantee from the host. Combined with the in-CVM
Redis replay cache (`replay_cache.py:_make_key` keys on
`signing_algo:timestamp:nonce`), a host that controls clock advancement
plus the cache can replay older signed responses. The current verifier
does not check timestamps independently.

Severity: **low–medium**. Affects the response-signature replay model;
does not on its own leak prompts.

### 7. vLLM prompt logging defaults: `--disable-log-requests` set on 1 of 5 composes

Only `c3f19eb2` (gpt-oss-20b / gemma) sets `--disable-log-requests` on
its vLLM args. The other four composes run vLLM with prompt logging at
its default (info-level prompt logging). `public_logs: true` is set on
every compose's app-compose manifest, exposing container logs through
dstack's metadata path. Net effect: on the four affected composes, the
host (and anyone the host shares logs with) plausibly has visibility
into prompt content via standard container logs without any backdoor at
all.

Severity: **high if confirmed**. Worth pulling `/Logs` via the dstack
gateway against one of these CVMs to confirm vLLM's actual log content.

### 8. (folded into finding #1)

The standalone "dev OS image" observation is now part of finding #1
above. The dev-vs-prod image distinction is the mechanism by which the
SSH-key-injection path actually delivers a shell, so the two are one
finding, not two.

### What the verifier *does* check (and is fine)

- `kms_enabled: true`, `local_key_provider_enabled: false` on all 5
  composes → keys are managed by Phala KMS, not derivable from a single
  host.
- `compose_hash` matches `mr_config[1:]` (verified in light mode).
- `nvidia_payload.nonce` matches the request nonce, GPU verdict from
  NRAS is `true`.
- TDX `report_data[0:32]` binds the per-CVM signing address.
- On-chain DCAP succeeds via Automata.

These eight checks pass. None of them rule out findings #1–#8.

---

## Per-model probe results — 2026-04-20

Probed `api.red-pill.ai/v1` with the hermes-cli strict verifier. Four-shape
dispatch, no fallbacks. `max_workers=6`, full probe ~94s (bounded by the
slowest Chutes response).

| Model                                       | Backend              | Verdict | Probe time | Error |
|---------------------------------------------|----------------------|:-------:|-----------:|-------|
| `phala/gpt-oss-20b`                         | phala-simple         | ✅ pass | 2.9s       |       |
| `phala/glm-4.7-flash`                       | phala-simple         | ✅ pass | 2.9s       |       |
| `phala/qwen-2.5-7b-instruct`                | phala-simple         | ✅ pass | 3.2s       |       |
| `phala/qwen2.5-vl-72b-instruct`             | phala-simple         | ✅ pass | 2.6s       |       |
| `phala/qwen3-vl-30b-a3b-instruct`           | phala-simple         | ✅ pass | 2.9s       |       |
| `phala/qwen3.5-27b`                         | phala-simple         | ✅ pass | 2.4s       |       |
| `phala/gemma-3-27b-it`                      | phala-simple         | ✅ pass | 3.4s       |       |
| `phala/uncensored-24b`                      | phala-simple         | ✅ pass | 2.7s       |       |
| `phala/glm-4.7`                             | nearai-via-redpill   | ✅ pass | 5.0s       |       |
| `phala/deepseek-chat-v3.1`                  | nearai-via-redpill   | ✅ pass | 79.1s      |       |
| `phala/deepseek-v3.2`                       | chutes               | ✅ pass | 35.7s      |       |
| `phala/kimi-k2.5`                           | chutes               | ✅ pass | 93.5s      |       |
| `phala/gpt-oss-120b`                        | nearai-via-redpill   | ❌ fail | 3.2s       | TDX quote verification failed: `ppid=ca98bce2d0f6c53afd2a37537fcc3c3a` `tcb_svn=0b010200000000000000000000000000` |
| `phala/glm-5`                               | nearai-via-redpill   | ❌ fail | 3.1s       | Same PPID as `gpt-oss-120b` — co-located on unpatched host |
| `phala/qwen3-30b-a3b-instruct-2507`         | nearai-via-redpill   | ❌ fail | 3.0s       | NVIDIA GPU attestation failed (NRAS `False`) |

**Shape distribution:** 8 Phala-simple, 5 NearAI-via-redpill, 2 Chutes, 0
Tinfoil.

---

## Architecture

```
                                   CLIENT
                                      │
                       ┌──────────────┴────────────────┐
                       │   api.red-pill.ai/v1          │
                       │   unified OpenAI-ish API      │
                       │   /v1/attestation/report      │
                       │   /v1/chat/completions        │
                       └──────────────┬────────────────┘
                                      │
            ┌─────────────────────────┼───────────────────────────┐
            │                         │                           │
            ▼                         ▼                           ▼
     Phala backend            NEAR AI fleet              Chutes backend
     (TDX + NRAS)             (cloud-api.near.ai)        (multi-instance TDX)
     Shape:                   Shape:                     Shape:
       intel_quote              gateway_attestation +     attestation_type=chutes
       nvidia_payload           model_attestations[]      all_attestations[] (×5)
                                                          e2e_pubkey anti-tamper
```

The "NEAR AI via Redpill" path is notable: Redpill's
`/v1/attestation/report?model=phala/X` for these models returns a
`gateway_attestation + model_attestations[]` bundle identical in shape to
`cloud-api.near.ai/v1/attestation/report?model=X`. The content likewise
matches — which is how we know those models are physically backed by NEAR
AI fleet CVMs. A failure on NEAR AI directly reproduces on Redpill. See:

- `phala/qwen3-30b-a3b-instruct-2507` (Redpill) and
  `Qwen/Qwen3-30B-A3B-Instruct-2507` (NEAR AI) — same NRAS `False` verdict.
- `phala/gpt-oss-120b` (Redpill) and `openai/gpt-oss-120b` (NEAR AI) —
  related failures.

Cross-reference: [near-ai-private-inference/DEVPROOF-REPORT.md](../near-ai-private-inference/DEVPROOF-REPORT.md).

---

## Chutes shape — anti-tamper binding

Unique to the Chutes backend: `all_attestations[]` contains N (observed 5)
instances, each with its own TDX quote, `e2e_pubkey`, and `nonce`. The
anti-tamper check binds the E2EE key into the TDX `report_data`:

```
SHA256(nonce || e2e_pubkey)  ==  report_data[0:32]
```

If this binding fails, the E2EE public key isn't hardware-bound and a MitM
could substitute keys. Our verifier rejects on mismatch.

**Debug-mode check:** the TDX `td_attributes & 1` bit indicates debug
enabled. In debug mode, the TEE offers no confidentiality guarantee and
must be rejected. Our verifier does so.

---

## Findings

### Backdoor / privacy findings (phala-direct)

The eight numbered findings in **Phala-direct backdoor audit** above are
the load-bearing ones for the privacy claim. To summarise:

| # | Finding                                                                 | Severity     | Confirmed on |
|---|-------------------------------------------------------------------------|--------------|--------------|
| 1 | Dev OS image (`dstack-nvidia-dev-0.5.8`, ships sshd + debug-tweaks) + `DSTACK_AUTHORIZED_KEYS` host injection — operator root SSH | critical     | 5/5 composes |
| 2 | Mutable image tags, no `@sha256:` digest pinning                        | high         | 5/5 composes |
| 3 | `qwen2.5-vl-72b-instruct` advertised but not in served-model-name       | high         | b303b44      |
| 4 | HF weight pull at boot, no content digest                               | high         | 5/5 composes |
| 5 | Privileged containers with `/var/run/dstack.sock` mounted               | medium       | 5/5 composes |
| 6 | `secure_time: false`                                                    | low–medium   | 5/5 composes |
| 7 | vLLM prompt logging on by default; `public_logs: true`                  | high (TBC)   | 4/5 composes |
| 8 | (folded into #1)                                                        | —            | —            |

### Verifier / API ergonomics (carried over from 2026-04-20 audit)

9. **Four-shape dispatch is undocumented.** Client writers building strict
   verifiers today have to read Redpill's open-source verifier JavaScript
   implementation (`redpill-verifier/js/src/verifiers/{phala,nearai,chutes,tinfoil}.ts`)
   to know what shapes exist. Worth adding to the OpenAPI spec or a
   `backend_type` enum field.

10. **Two Phala-routed models share a broken host.** `phala/gpt-oss-120b`
    and `phala/glm-5` both TDX-fail with the same PPID
    `ca98bce2d0f6c53afd2a37537fcc3c3a` and same `tee_tcb_svn`
    `0b010200000000000000000000000000`. They are evidently co-located on a
    single CVM whose firmware hasn't been patched. Remediation is a fleet
    operation, not a per-model fix.

11. **Chutes attestation bundles are slow.** 35–94s per probe because the
    bundle packs 5 per-instance TDX quotes, each cross-verified via Phala's
    online verifier. Cacheable by the backend but currently isn't. For
    interactive flows (every `/model` selection would not tolerate this),
    strict attestation is an offline check only.

12. **Federated failure transparency.** When a Redpill `phala/*` model is
    actually backed by NEAR AI fleet and fails there, the Redpill error
    surfaces the NEAR AI TDX/GPU failure directly. This is good — the
    failure isn't laundered through an abstraction layer — but users who
    believe "I'm on Phala" may be confused why they see NEAR AI PPIDs in
    error messages.

---

## Recommendations

**Phala/Redpill: switch every phala-simple CVM from `dstack-nvidia-dev-*`
to `dstack-nvidia-*` (the production variant).** This is the single
highest-leverage change. The prod image strips sshd, getty, login, and
the debug-tweaks Yocto features; with no sshd to receive the connection,
the `DSTACK_AUTHORIZED_KEYS` injection path becomes inert even if left
in `allowed_envs`. Without this swap, the rest of the recommendations
below are mitigations on top of a development-grade base.

**Phala (compose authors): drop `DSTACK_AUTHORIZED_KEYS` from `allowed_envs`,
or make its acceptance conditional on a build flag the user can policy-check.**
Operator break-glass access should not be silent inside an attestation
billed as confidential. If ops access is necessary, place it behind a
clearly-named `OPERATOR_BREAK_GLASS` env var so a verifier can refuse on
its presence. (Even with the prod image fix above, leaving this name in
`allowed_envs` invites a future regression if anyone ever swaps an image
back to dev.)

**Phala (compose authors): pin every image by `@sha256:` digest.**
`vllm/vllm-openai@sha256:...`, etc. The verifier's existing Sigstore
check requires this to do anything useful; today it's a no-op. Concretely
replace `vllm/vllm-openai:latest` and `lmsysorg/sglang:dev` immediately;
the floating tags are indefensible.

**Phala (compose authors): pin model weights by HuggingFace revision.**
`hf download <name> --revision <commit>` plus a manifest file inside the
compose listing expected file hashes; verify after download. Without
this, the trust boundary leaks to `huggingface.co` reachable through the
host network.

**Redpill: bind the served-model-name to attestation.** When a client
asks for `phala/qwen2.5-vl-72b-instruct`, the attestation must either
(a) prove that exact model name is in `--served-model-name` of the
attested compose, or (b) refuse to issue a passing attestation. Today
`b303b44` returns a passing attestation for a name it doesn't serve.

**Redpill: extend the verifier to enforce a compose policy.** Verifier
should reject any compose whose `allowed_envs` contains
`DSTACK_AUTHORIZED_KEYS`, whose `secure_time` is `false`, or whose
images use mutable tags. The current verifier validates
`compose_hash → mr_config` but not compose contents. Add a
`checkComposePolicy(appCompose)` step.

**Redpill: document that phala-simple "deep" verification still does not
prove no operator backdoor.** Update the verifier README to note that
TDX/GPU/compose-hash success does not preclude operator SSH or weight
substitution unless the listed compose-policy checks also pass.

**Redpill: document the four shapes.** Add a `backend_type` field or a
separate `/v1/attestation/shape?model=...` endpoint so clients can pick
the verifier without response-shape sniffing.

**Redpill: cache Chutes attestation bundles server-side.** 5× per-instance
TDX re-verification on every client call is wasteful; a short-TTL cache
(60s) with nonce freshness proof would drop p99 probe latency by an order
of magnitude.

**Redpill + NEAR AI: shared fleet health dashboard.** Since some Redpill
models are NEAR AI CVMs, an unpatched firmware node on the NEAR side
surfaces as a broken Redpill model. A shared health/advisory dashboard
would help both teams coordinate remediation.

---

## Stage Assessment

**Verifiability: partial.** Three of four documented shapes have working
reference verifiers. Strict-mode client-side verification is possible
today for 12 of 15 curated `phala/*` models; the 3 failing are upstream
fleet-health issues, not verifier gaps.

**Privacy posture: this is a development-grade deployment serving
production users.** Every phala-simple CVM boots Phala's
`dstack-nvidia-dev` OS image — the variant that ships sshd, debug-tweaks,
and forensic tooling — and the application compose enables host SSH key
injection on top. The combination gives the host operator a documented
root-shell path into a running CVM that the published verifier accepts.
Layered on top of that: mutable image tags (#2), unpinned model weights
(#4), and default-on prompt logging on 4 of 5 composes (#7). The
underlying dstack TDX guarantees are sound; the *deployment* posture
nullifies them.

This is not evidence of bad faith. The most parsimonious read is that
Redpill is running on the dev image because that's what was easiest to
stand up, with the standard Phala Cloud ops scaffolding (which includes
`DSTACK_AUTHORIZED_KEYS` for break-glass access) left enabled. The
audit's point is structural: a verifier that returns `verified: true`
on this configuration cannot distinguish a "break-glass-only operator"
from a hostile one, and cannot distinguish a dev deployment from a
production-hardened one. The fix is a one-line change to the OS image
choice in the deployment manifest, plus the verifier-side compose-policy
checks listed in Recommendations.

**Biggest gap:** the verifier validates the *attestation* but not the
*compose policy*. Until compose policy is part of the verification, a
client should treat passing `phala/*` attestations as evidence of
"running on Phala dstack" rather than "private from the operator".

---

## Source Code

- **Verifier reference:** [redpill-ai/redpill-verifier](https://github.com/redpill-ai/redpill-verifier)
  — `js/src/verifiers/{cloud-api,dstack,onchain,tinfoil,chutes,intel-ita}.ts`.
  Key check: `cloud-api.ts:checkCompose` confirms `compose_hash` matches
  `mr_config[1:]`. There is no `checkComposePolicy` step yet.
- **vllm-proxy (response-signer):** [Dstack-TEE/vllm-proxy](https://github.com/Dstack-TEE/vllm-proxy)
  — open source; `dstacktee/vllm-proxy:v0.2.18` is the image used in every
  phala-simple compose. The compose pins the tag, not the digest.
- **dstack types and KeyProviderKind:** [Dstack-TEE/dstack/dstack-types/src/lib.rs](https://github.com/Dstack-TEE/dstack/blob/main/dstack-types/src/lib.rs)
  — `AppCompose.allowed_envs`, `AppCompose.pre_launch_script`, etc.
- **Compose evidence:** `case-studies/redpill-federated-inference/composes/`
  — five `*.json` files, one per unique compose hash. These are the
  literal `app_compose` strings whose sha256 equals `info.compose_hash`
  in the corresponding attestation report.
- **Probe harness:** `hermes-agent-tee-probe/hermes_cli/attestation.py`
  — `_verify_redpill_attestation`, `_verify_redpill_chutes`,
  `probe_models_for_provider`.
- **Probe notes (raw data):** `hermes-agent-tee-probe/notes/attestation-probe-results.md`.

---

## Prior Art

- [near-ai-private-inference](../near-ai-private-inference/DEVPROOF-REPORT.md)
  — covers the NEAR AI fleet that Redpill partially federates to.
- [confer](../confer/) — another TEE-routing architecture.
