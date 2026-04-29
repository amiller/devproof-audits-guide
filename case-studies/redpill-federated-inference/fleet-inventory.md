# Redpill `phala/*` fleet inventory — 2026-04-28

Every row below has **clickable links** to the live attestation endpoint
(returns JSON in your browser) and to the saved `app_compose` files in
this repo. The OS image is the `vm_config.image` field of the attestation
JSON.

The catalog endpoint: <https://api.red-pill.ai/v1/models> — filter to
ids starting `phala/` to get the 21 models below.

## Phala-simple CVMs (operated by Redpill on Phala dstack)

5 distinct app_ids serving 8 models. **All 5 run dev images.** Click any
model link → look for `"image":"dstack-nvidia-dev-…"` in the
`vm_config` field of the JSON.

| Model | Attestation (click to see JSON) | Saved compose | OS image | dev/prod |
|---|---|---|---|:-:|
| `phala/gpt-oss-20b` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/gpt-oss-20b) | [`c3f19eb…`](composes/c3f19eb2a4d97aa0.json) | `dstack-nvidia-dev-0.5.8-e3e677dd` | **DEV** |
| `phala/gemma-3-27b-it` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/gemma-3-27b-it) | [`c3f19eb…`](composes/c3f19eb2a4d97aa0.json) | `dstack-nvidia-dev-0.5.8-e3e677dd` | **DEV** |
| `phala/glm-4.7-flash` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/glm-4.7-flash) | [`9683a8f…`](composes/9683a8f8b3d3e566.json) | `dstack-nvidia-dev-0.5.5-021bf66a` | **DEV** |
| `phala/qwen-2.5-7b-instruct` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/qwen-2.5-7b-instruct) | [`b303b44…`](composes/b303b44ff3bf49f0.json) | `dstack-nvidia-dev-0.5.8-e3e677dd` | **DEV** |
| `phala/qwen2.5-vl-72b-instruct` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/qwen2.5-vl-72b-instruct) | [`b303b44…`](composes/b303b44ff3bf49f0.json) | `dstack-nvidia-dev-0.5.8-e3e677dd` | **DEV** |
| `phala/qwen3-vl-30b-a3b-instruct` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/qwen3-vl-30b-a3b-instruct) | [`b303b44…`](composes/b303b44ff3bf49f0.json) | `dstack-nvidia-dev-0.5.8-e3e677dd` | **DEV** |
| `phala/qwen3.5-27b` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/qwen3.5-27b) | [`7ac6727…`](composes/7ac6727adb3fc9a9.json) | `dstack-nvidia-dev-0.5.6-f2e62bc7` | **DEV** |
| `phala/uncensored-24b` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/uncensored-24b) | [`5c809c5…`](composes/5c809c592b57e6f3.json) | `dstack-nvidia-dev-0.5.5-021bf66a` | **DEV** |

## NEAR AI fleet (federated via Redpill)

5 models route to a single NEAR AI gateway + a single NEAR AI model
fleet. The model fleet runs **prod** (`dstack-nvidia-0.5.5`); the
gateway's `vm_config` is null in the attestation, so its image identity
needs MRTD decoding.

| Model | Attestation (click to see JSON) | Model image | dev/prod |
|---|---|---|:-:|
| `phala/glm-4.7` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/glm-4.7) | `dstack-nvidia-0.5.5` | **prod** |
| `phala/glm-5` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/glm-5) | `dstack-nvidia-0.5.5` | **prod** |
| `phala/gpt-oss-120b` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/gpt-oss-120b) | `dstack-nvidia-0.5.5` | **prod** |
| `phala/deepseek-chat-v3.1` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/deepseek-chat-v3.1) | `dstack-nvidia-0.5.5` | **prod** |
| `phala/qwen3-30b-a3b-instruct-2507` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/qwen3-30b-a3b-instruct-2507) | `dstack-nvidia-0.5.5` | **prod** |

For these, the image is at `.model_attestations[0].info.vm_config |
fromjson | .image` — not the top-level `.vm_config`.

## Chutes fleet

8 models, 28 distinct CVM instance IDs. The chutes attestation shape
has no `vm_config` at all — only the TDX `MRTD`. Confirming dev vs prod
needs decoding against [dstack-mr](https://github.com/Dstack-TEE/dstack/tree/main/dstack-mr) golden values.

| Model | Attestation (click to see JSON) | # instances |
|---|---|---:|
| `phala/deepseek-v3.2` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/deepseek-v3.2) | 5 |
| `phala/glm-5.1` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/glm-5.1) | 5 |
| `phala/kimi-k2.5` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/kimi-k2.5) | 5 |
| `phala/kimi-k2.6` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/kimi-k2.6) | 5 |
| `phala/minimax-m2.5` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/minimax-m2.5) | 3 |
| `phala/qwen3.5-397b-a17b` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/qwen3.5-397b-a17b) | 3 |
| `phala/mimo-v2-flash` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/mimo-v2-flash) | 1 |
| `phala/qwen3-coder-next` | [report](https://api.red-pill.ai/v1/attestation/report?model=phala/qwen3-coder-next) | 1 |

## Summary of OS image variants observed across the fleet

| Image string                          | dev/prod | Where seen                                                                  |
|---|:-:|---|
| `dstack-nvidia-dev-0.5.5-021bf66a`    | **DEV**  | Redpill phala-simple: `glm-4.7-flash`, `uncensored-24b`                      |
| `dstack-nvidia-dev-0.5.6-f2e62bc7`    | **DEV**  | Redpill phala-simple: `qwen3.5-27b`                                          |
| `dstack-nvidia-dev-0.5.8-e3e677dd`    | **DEV**  | Redpill phala-simple: `gpt-oss-20b`/`gemma-3-27b-it`, qwen pool              |
| `dstack-nvidia-0.5.5`                 | prod     | NEAR AI model CVM                                                            |
| _(opaque — TDX MRTD only)_            | ?        | NEAR AI gateway, all 28 chutes instances                                     |

**Headline:** every CVM Redpill operates directly on Phala dstack runs a
dev image; the one fleet whose image is plainly visible *and* runs prod
(`dstack-nvidia-0.5.5`) is operated by NEAR AI, not Phala/Redpill.

## What to look for in the JSON

When you click a phala-simple link above, the response includes a
top-level `vm_config` field (a JSON-encoded string). Decode it and look
at the `image` field — that's the OS image name. For NEAR AI federated
models, the image is one level deeper, inside
`model_attestations[0].info.vm_config`. Chutes models have no
`vm_config` at all.

The dev-vs-prod recipe difference is in
[`Dstack-TEE/meta-dstack`](https://github.com/Dstack-TEE/meta-dstack) at
[`recipes-core/images/dstack-rootfs-dev.inc`](https://github.com/Dstack-TEE/meta-dstack/blob/main/meta-dstack/recipes-core/images/dstack-rootfs-dev.inc)
vs [`dstack-rootfs-prod.inc`](https://github.com/Dstack-TEE/meta-dstack/blob/main/meta-dstack/recipes-core/images/dstack-rootfs-prod.inc).
The dev recipe adds `packagegroup-core-ssh-openssh strace tcpdump gdb
gdbserver vim` and `debug-tweaks tools-profile`; the prod recipe sets
`nologin` and strips getty/login binaries.

## Reproducing the table programmatically

```bash
for m in $(curl -s https://api.red-pill.ai/v1/models | jq -r '.data[].id' | grep '^phala/'); do
  img=$(curl -s "https://api.red-pill.ai/v1/attestation/report?model=$m" \
    | jq -r '.vm_config // "{}" | fromjson | .image // .model_attestations[0].info.vm_config // "(opaque)"' \
    2>/dev/null)
  # If the result still looks like JSON, it's the nested NEAR AI form — unwrap one more level
  if echo "$img" | grep -q '^{'; then
    img=$(echo "$img" | jq -r 'fromjson? .image // "(opaque)"')
  fi
  echo "$m  $img"
done
```
