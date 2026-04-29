# Redpill `phala/*` fleet inventory — 2026-04-28

Source data: `/v1/attestation/report?model=<name>` for each of the 21
`phala/*` models in `https://api.red-pill.ai/v1/models`.

## How to check dev/prod yourself (one-liner)

```bash
curl -s "https://api.red-pill.ai/v1/attestation/report?model=phala/gpt-oss-20b" \
  | jq -r '.vm_config | fromjson | .image'
# → dstack-nvidia-dev-0.5.8-e3e677dd
```

`vm_config.image` contains the literal Yocto image name. Anything starting
`dstack-nvidia-dev-` is the dev variant (ships sshd, debug-tweaks, strace,
gdb, tcpdump). Anything starting `dstack-nvidia-` (no `dev`) is the
production variant. This works for the 8 phala-simple models; it does not
work for the chutes-backed models, which only expose the TDX `MRTD` (see
below).

There is no single Redpill endpoint that lists every CVM in the fleet.
The closest reproducible probe is to walk the 21 `phala/*` model names
from `/v1/models` and pull each report.

## Phala-simple CVMs (operated by Redpill on Phala dstack)

5 distinct app_ids serving 8 models. **All 5 run dev images.**

| Models exposed                                                                              | app_id                | OS image                              | dev/prod |
|---|---|---|:-:|
| `phala/gemma-3-27b-it`, `phala/gpt-oss-20b`                                                | `c078255bb2090494…`   | `dstack-nvidia-dev-0.5.8-e3e677dd`    | **DEV**  |
| `phala/glm-4.7-flash`                                                                       | `63145b0513f00f7d…`   | `dstack-nvidia-dev-0.5.5-021bf66a`    | **DEV**  |
| `phala/qwen-2.5-7b-instruct`, `phala/qwen2.5-vl-72b-instruct`, `phala/qwen3-vl-30b-a3b-instruct` | `ce688fe8aa2c63f4…` | `dstack-nvidia-dev-0.5.8-e3e677dd`    | **DEV**  |
| `phala/qwen3.5-27b`                                                                         | `605734ecac32c85b…`   | `dstack-nvidia-dev-0.5.6-f2e62bc7`    | **DEV**  |
| `phala/uncensored-24b`                                                                      | `ab38bad3f3e29fdb…`   | `dstack-nvidia-dev-0.5.5-021bf66a`    | **DEV**  |

## NEAR AI fleet (federated via Redpill)

5 models route to a single NEAR AI gateway + a single NEAR AI model
fleet. The model fleet exposes `vm_config.image` and runs the **prod**
image; the gateway's `vm_config` is null in the attestation report
(only the TDX `MRTD` is published — the gateway image identity would
need MRTD decoding against published golden values).

| Models                                              | gateway app_id          | gateway image | model app_id           | model image           | dev/prod (model) |
|---|---|---|---|---|:-:|
| `phala/deepseek-chat-v3.1`, `phala/glm-4.7`, `phala/glm-5`, `phala/gpt-oss-120b`, `phala/qwen3-30b-a3b-instruct-2507` | `f550fdfb4eb8ad78…` | (opaque) | `2c0a0c96cb6dbd65…` | `dstack-nvidia-0.5.5` | **prod** |

## Chutes fleet

8 chutes-backed models, **28 distinct CVM instance IDs** total. The
chutes attestation shape does not include `info.app_id` or
`info.vm_config` — only `instance_id`, `nonce`, `e2e_pubkey`,
`intel_quote`, and `gpu_evidence` per instance. So the OS image identity
is locked inside the TDX `MRTD` field and you'd need to decode against
[dstack-mr](https://github.com/Dstack-TEE/dstack/tree/main/dstack-mr)
golden values to confirm dev vs prod.

| Model                          | # distinct instance_ids in `all_attestations` |
|---|---:|
| `phala/deepseek-v3.2`          | 5 |
| `phala/glm-5.1`                | 5 |
| `phala/kimi-k2.5`              | 5 |
| `phala/kimi-k2.6`              | 5 |
| `phala/mimo-v2-flash`          | 1 |
| `phala/minimax-m2.5`           | 3 |
| `phala/qwen3-coder-next`       | 1 |
| `phala/qwen3.5-397b-a17b`      | 3 |

## Summary of OS image variants observed across the fleet

| Image string                          | dev/prod | Where seen                                                                  |
|---|:-:|---|
| `dstack-nvidia-dev-0.5.5-021bf66a`    | **DEV**  | Redpill phala-simple: `glm-4.7-flash`, `uncensored-24b`                     |
| `dstack-nvidia-dev-0.5.6-f2e62bc7`    | **DEV**  | Redpill phala-simple: `qwen3.5-27b`                                          |
| `dstack-nvidia-dev-0.5.8-e3e677dd`    | **DEV**  | Redpill phala-simple: `gpt-oss-20b`/`gemma-3-27b-it`, qwen pool              |
| `dstack-nvidia-0.5.5`                 | prod     | NEAR AI model CVM (`2c0a0c96…`)                                              |
| _(opaque — TDX MRTD only)_            | ?        | NEAR AI gateway (`f550fdfb…`), all 28 chutes instances                       |

**Headline:** every CVM Redpill operates directly on Phala dstack runs a
dev image; the one fleet whose image is plainly visible *and* runs prod
(`dstack-nvidia-0.5.5`) is operated by NEAR AI, not Phala/Redpill.

## Reproducing this table

```bash
for m in $(curl -s https://api.red-pill.ai/v1/models \
  | jq -r '.data[].id' | grep '^phala/'); do
  img=$(curl -s "https://api.red-pill.ai/v1/attestation/report?model=$m" \
    | jq -r '.vm_config // "{}" | fromjson | .image // "(opaque)"')
  echo "$m  $img"
done
```

For chutes models the `vm_config` is missing so this prints `(opaque)`;
phala-simple models print the real image name. NEAR AI federated models
print `(opaque)` at the top level too — their image is inside
`.model_attestations[0].info.vm_config`. To unwrap that:

```bash
curl -s "https://api.red-pill.ai/v1/attestation/report?model=phala/glm-4.7" \
  | jq -r '.model_attestations[0].info.vm_config | fromjson | .image'
# → dstack-nvidia-0.5.5
```
