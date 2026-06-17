# Chutes Confidential Inference — DevProof Case Study

Audit of [chutes.ai](https://chutes.ai) confidential (`-TEE`) compute — serverless AI on **Bittensor
subnet 64** (Rayon Labs / chutesai), Intel TDX + NVIDIA confidential-compute GPUs, ML-KEM-768 E2E. The
cohort's first **Bittensor-subnet** case and first **non-dstack custom TDX stack** (own attestation
service, measurement registry, LUKS key release).

**The headline.** The cryptographic core is sound and hardware-rooted — verified live. But the chute's
**application code and model run unmeasured inside the enclave**, so a verified quote proves "genuine
TDX+GPU running *a* Chutes-blessed base image," not "*this* model on *this* code." That single fact is a
**confidentiality + identity** gap for a consumer and a **provability** gap for a provider — and it is
demonstrated live (cross-user prompt exfiltration from a `verified=True` enclave). The
miner (host) is *not* the threat — it is contained by a measured admission controller; the residual trust
is in Chutes' control plane and the chute operator.

## Read in this order

| File | What it is |
|---|---|
| [`PLATFORM.md`](./PLATFORM.md) | **Start here.** Shared facts both reports assume: the sound crypto core (verified live), base-image provenance (reachable via `sek8s`), miner containment (the measured admission + TEE-gated LUKS), the root unmeasured-code gap, and lower-tier items. |
| [`REPORT-inference.md`](./REPORT-inference.md) | **Consumer surface** — you call a hosted `-TEE` model you didn't deploy. Can anyone read your prompts; is the model real? (I1 plaintext default · I2 verify-then-encrypt optional · I3 unmeasured operator code → exfil + substitution) |
| [`REPORT-rental.md`](./REPORT-rental.md) | **Provider surface** — you deploy your own chute (cords/jobs) on a rented GPU. Does *my* code run, and can I prove it? (R1 server-side build/sign · R2 admission controller · R3 confidential-vs-miner-not-Chutes · R4 Jobs unaudited) |
| [`OPERATOR-EXFIL-POC.md`](./OPERATOR-EXFIL-POC.md) | Dated live demonstration (2026-06-16/17, self-deployed chute on the author's own account): egress-free cross-user prompt exfiltration from a `verified=True` enclave, the concrete evidence for the unmeasured-code gap. |
| [`ISSUES-DRAFT.md`](./ISSUES-DRAFT.md) | The findings as file-able GitHub issues, framed as verifiability gaps, in priority order. |
| [`verify/verify_chutes.py`](./verify/verify_chutes.py) | ~115-line standalone reproducer. Hits the live `api.chutes.ai` and checks the five crypto-core properties **and** the model-substitution gap (check [6]: two different `-TEE` models, byte-identical quote). ~5s, needs an API key in `/tmp/ck`. This is the runnable evidence behind the reports. |
| `refs/` | Local clones of the four source repos — **gitignored, not committed**; re-fetch commands are in `.gitignore`. |

## Reproduce (~5s)

```bash
# API key in /tmp/ck (Bearer cpk_...)
curl -s -H "Authorization: Bearer $(cat /tmp/ck)" https://api.chutes.ai/servers/tee/measurements | jq 'length'   # 10 configs, 1 MRTD
python3 verify/verify_chutes.py     # [1]-[5] crypto core + [6] model-substitution
```

## Vendor channel

Findings are framed as **verifiability / devproofness gaps** suitable for public issues on the
`chutesai/chutes-api` / `chutesai/chutes` repos (see `ISSUES-DRAFT.md`), not as exploits. The two to lead
with: the **default path is plaintext at the control plane** (so "not even we can see your data" holds only
on the opt-in E2E path), and the **chute's code + model are unmeasured** (so neither a consumer's privacy
nor a provider's "my code ran" is third-party-verifiable). The crypto core, the contained miner, and the
reachable base-image provenance are genuine strengths and are credited as such.
