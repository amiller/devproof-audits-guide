# Chutes — operator-controlled code is unmeasured: live model-swap + prompt-exfil escalation

**Date:** 2026-06-16 · **Method:** hands-on, against a self-deployed `-TEE` chute on
`api.chutes.ai` (account `socrates1024`, 1×RTX PRO 6000 Blackwell) + read of the
pip-installed SDK `chutes==0.6.9` (`~/.local/.../site-packages/chutes`). Line numbers below
are from that wheel; they may differ from the audit's pinned `rayonlabs/chutes 08d79872`.

This extends **F1** ("served model identity is not attested") with two things the
source-only pass didn't have: a **live, operator-side demonstration** that the served model is
in no measured register (so it is silently substitutable), and the observation that the *same
root cause* — operator code running unmeasured inside the TD — is a **prompt-confidentiality**
gap, not just a model-identity gap.

---

## A. Live PoC: a `verified=True` enclave serving a model that contradicts its name

`build_vllm_chute` downloads weights from the `model_name` **closure variable** inside
`@chute.on_startup()` (`chute/template/vllm.py:~335` `snapshot_download(repo_id=model_name,
revision=...)`), and launches vLLM with `--served-model-name {self.name}` — i.e. the served
label is the *chute's* name, set by the operator and decoupled from the actual weights. Because
the model is in **no measured register** (F1), an operator can hold the advertised identity
fixed and point the weights anywhere, undetectably:

```python
chute = build_vllm_chute(model_name="HuggingFaceTB/SmolLM2-1.7B-Instruct", revision=..., ...)
chute.chute._name = "Infermatic/L3.3-70B-Euryale-v2.3-FP8-Dynamic"   # advertised identity, unchanged
```

Done live on `chute_id 0dd7dbaa-1ede-5707-9ec2-5b465ebc2417`:
- Deployed **Qwen2.5-0.5B**, then **SmolLM2-1.7B**, both under the advertised name
  `Infermatic/L3.3-70B-Euryale-v2.3-FP8-Dynamic`.
- `GET /v1/models` reported `id: Infermatic/L3.3-70B-Euryale-v2.3-FP8-Dynamic` while the
  engine actually loaded SmolLM2/Qwen (`--model …SmolLM2…` confirmed in instance pod logs).
- The instance went **`verified=True`** (instance `45243927…`, version `fd2f0ee1`=SmolLM2) —
  TDX/GPU attestation passed for an enclave whose served model contradicts its advertised name.

This is F1's "operator-trust" verdict made concrete: the operator (not a malicious miner)
re-points the **same named, attested** endpoint at arbitrary weights and nothing a client
verifies changes. (Pricing aside, *not* a devproof point: under their fee model these redeploys
also happen to be free — same name + same image = no fee — so the swap is costless, but that is
incidental to the attestation gap.)

### Detection that *does* survive (partial)
Each chat response carries a server-injected `template_sha256` (model-specific chat-template
fingerprint), `prompt_sha256`, and `chutes_verification` — not in the SDK or any `.so`, so
computed by the chutes gateway from the *real* loaded model. A client holding a reference
`template_sha256` for genuine Euryale would see a mismatch. This is a **trust-chutes** signal
(the gateway computes it), and only distinguishes models with different chat templates.

---

## B. Escalation: unmeasured operator code sees E2E plaintext → prompt exfiltration

The decryption boundary is measured (`aegis`), but it hands plaintext to **operator-authored,
unmeasured `serve.py`** in the same process. On the verified-E2E path, inside the TD
(`entrypoint/run.py`, `_dispatch`):

```
:1304  e2e_plaintext = handle.e2e_decrypt_request(e2e_ctx, e2e_raw)
:1312  e2e_plaintext = gzip.decompress(e2e_plaintext)
:1314  e2e_body      = json.loads(e2e_plaintext)     # user's prompt, plaintext dict, in-process
```

`e2e_body` / `request.state.decrypted` is then dispatched to the **cord handler defined in the
operator's `serve.py`** (`@chute.cord`). The operator has full Python execution in this
process — custom cords, `@chute.on_startup` hooks, monkeypatching the passthrough, background
tasks reading process memory. Because `serve.py` is **excluded from CFSV and in no RTMR** (the
F1 root cause), a verifying client **cannot detect** that the running code logs, stashes, or
ships the plaintext out.

Exfil channel is real and often open by construction: `allow_external_egress` is an
operator-set flag (`run.py:~1025,~1739`, surfaced in the NetNanny challenge) and **must be
`True`** for any chute that pulls weights/data from HF at boot — as ours does. With egress on,
operator code can POST decrypted prompts anywhere. Egress-off still leaves covert channels
(response timing/embedding, operator-readable logs).

**Why this matters for the audit's confidentiality conclusion.** DEVPROOF-REPORT.md grades
E2E confidentiality "real — conditional on F3 (verify-then-encrypt)." This adds a **second
condition: conditional on the application code being measured**, which it is not. So even a
client that does everything right (DCAP sig, debug-off, `report_data[0:32]==SHA256(nonce‖
e2e_pubkey)`, golden MRTD) gets confidentiality against the **control plane and miner-host**
(they see ciphertext) but **not against the chute operator**, who authors the in-enclave code
that touches plaintext. On `llm.chutes.ai`, users select a model without knowing or trusting
who deployed it.

### Classification: a devproof gap, not an external exploit
The threat actor is the **operator** (whoever uploads `serve.py`) or **chutes** (via `forge`) —
never a network attacker, and **not a miner**: the measured OPA+cosign admission controller +
TEE-gated LUKS release stop a malicious host from injecting code, and a mere user can't add the
middleware. So this is a **verifiability failure, not a remote exploit** — the TEE+E2E genuinely
protect against the network and the host, but the attestation does **not** let a downstream
consumer verify, *without trusting the operator*, that their prompts stay private. Since removing
operator trust is the entire reason to use a TEE, the gap negates the confidential-inference claim
at the application layer. The exposure is real only where there is a **trust separation** — a chute
offered *as* "private inference" to downstream apps/users (chutes' own `llm.chutes.ai` models, or a
third party reselling a chute as confidential). In self-tenant use you are trusting your own code
and there is no victim. The live exfil demo is **evidence the gap is load-bearing**, not a claim of
external exploitability — and it is a *stronger* devproof finding than model-substitution (F1)
because it bears on **confidentiality**, the headline claim, not just model identity.

In the guide's **Prompt-Path Test** terms (AUDIT-GUIDE.md): the entire chute `serve.py` is an
operator-controlled slot **on the prompt path** (it receives decrypted plaintext) and is
unmeasured → fails Stage 1 §4 (no operator access to secrets) and §7 (no backdoor paths). It
is the maximal prompt-path failure — the operator owns *all* the code that sees plaintext.

### Live confirmation (2026-06-17)

Demonstrated end-to-end on a self-deployed `-TEE` chute (`chute_id 0dd7dbaa…`, `verified=True`,
1×RTX PRO 6000), two ways:

1. **The read.** A deployed `BaseHTTPMiddleware` (added via `_c.add_middleware`, so it runs
   inside the runtime's decrypt layer) keyed on a private constant `EXFIL_DUMP_8c2f`. A
   discriminating probe showed only the *exact* literal branched the request
   (`EXFIL_DUMP_8c2f` → HTTP 500; `EXFIL_DUMP_9999`, `EXFIL_DUMP`, and ordinary prompts → 200,
   repeatably). The only code in the stack matching that constant against request content is the
   operator's unmeasured middleware ⇒ it provably reads the E2E-decrypted plaintext.

2. **The full cross-user exfiltration (egress-free).** The middleware harvested every request's
   plaintext into a process-RAM reservoir, and on the trigger rewrote the attacker's prompt so
   the *model echoes the reservoir verbatim* — riding out inside a normal, properly-encrypted
   completion (a raw custom response is rejected by the runtime's response-encryption contract,
   so the model itself is used as the carrier). Two "victim" callers sent
   `…recovery phrase alpha-bravo-charlie-7` and `…routing 021000021 account 55512345`; a third
   "attacker" caller, holding only an ordinary API key, sent the benign string `EXFIL_DUMP_8c2f`
   and received **both victims' prompts back verbatim** in the completion. No network egress, no
   logs — cross-user plaintext retrieved through the legitimate inference channel of a
   `verified=True` enclave.

Operational note: cold start was provisioning-dominated and capacity-bound (observed 22 min to
97 min on RTX PRO 6000 CC nodes). Caveat on channel choice: the runtime *does* reject a raw
operator-crafted response ("No infrastructure available to serve request"), which blocks the
naïve return path — hence the model-as-carrier technique; with `allow_external_egress=True`
(required to pull weights from HF) a direct network POST is the simpler channel.

### The obvious mitigation is blocked
A self-attesting `/whatami` (or `/source`) cord that reads `/app/chute.py` and binds it to a
nonce does **not route**: custom non-passthrough cords on a `standard_template="vllm"` TEE
chute return gateway `500 "No infrastructure available to serve request"` (the gateway only
routes the template's declared OpenAI paths, though the instance *does* register the cord in
its e2e allow-list, `run.py:~2304`). So operator self-attestation via cords isn't available on
the standard path.

### Exfil channel taxonomy (egress is not the binding constraint)

The chute process is long-lived (warm window + `concurrency=32`), so module globals / `self`
persist across requests — up to 32 users' decrypted prompts coexist in-process. That makes the
strongest channels **egress-free**:

| Channel | Needs egress? | Mechanism |
|---|---|---|
| Network POST to collector | yes (`allow_external_egress=True`, required to pull weights from HF) | operator code POSTs plaintext out |
| **Cross-request RAM harvest → colluding client** | **no** | accumulate prompts in a module global; return the harvest in the response to a trigger prompt the operator sends to their own chute (E2E-encrypted to *the operator*). Defeats full network isolation. |
| Pod-log channel | no | `logger.info(plaintext)` → operator reads `/instances/{id}/logs` (chutes' own observability API). NB: the SDK disables *vLLM's* request logging (`--no-enable-log-requests`) but not operator `serve.py` logging. |
| **Malicious-model steganography** | no | requires Part A (arbitrary weights): a model fine-tuned to encode recently-seen context into low-order token choices / whitespace / timing of responses to a colluding client. |

The stego channel has a consequence for the fix: measuring **only** the code is insufficient —
an unmeasured *model* can still steg-leak. The fix must measure `serve.py` **and**
`model‖weights` (see Fixes).

### Execution-surface coverage (most of the attack surface is unaudited)

The analysis so far covers only the **vLLM TEE inference cord** path. Chutes exposes several
in-TD execution surfaces with different (and mostly unexamined) devproof posture:

| Surface | Audited? | Code-exec risk in-TD |
|---|---|---|
| vLLM / SGLang / diffusion / embedding template cords | partial (vLLM) | handler on the plaintext path |
| custom cords · `@chute.on_startup`/`on_shutdown` · `add_middleware` | this doc (PoC) | arbitrary Python in the chute process |
| **Jobs (`@chute.job`, `ssh=True` or batch)** | **no — `job_quota=0`, untestable** | **full SSH shell / arbitrary batch in the enclave + `output_dir` + egress** |
| non-TEE GraVal path (normal chutes) | n/a | no confidentiality by design |

**Jobs are the largest unaudited surface** — an interactive SSH shell *inside the TEE* is a
far bigger code-exec surface than a cord, yet the job path is quota-gated to 0 (`Daily job
quota exceeded: job_quota=0`), so its attestation behavior (what the validator checks for a
job vs a cord; whether the job binary is measured) is **undocumented and untestable without
Chutes granting quota** — itself a finding.

---

## Fixes (server-side; client-side can't close B)

- **Measure the workload.** Extend `SHA256(image_digest ‖ model ‖ revision ‖ serve.py)` into
  RTMR3 and publish model-keyed golden values — covers both A (which model) and B (which
  code). This is F1's fix, widened to include the application code.
- **Disclose the code.** Even public chutes hide the registered `code` (confirmed: `code:
  null` on a public `-TEE` chute), so a client can't read which model/handler is declared.
  Publish it (or `chutes share` to the verifier) so the measured value has a readable preimage.
- **Pin egress off under a measured NetNanny for confidential chutes** — removes the easy
  exfil channel (does not remove covert channels; weights must then be baked into the measured
  image, not runtime-pulled).

**A client-side workaround exists for A but not B.** Model *substitution* can be caught
without Chutes' cooperation by **logit fingerprinting over the verified-E2E channel**: greedy
(temp=0) challenge prompts with top-k logprobs, compared to a reference for the claimed model;
secret per-session probes prevent precompute (cost: the verifier must run the reference model
live). It distinguishes SmolLM2-vs-Euryale trivially but blurs on close finetunes/quant, and
it does **nothing** for B — exfil requires the code itself measured and auditable, which only
the server-side fixes provide.

---

## Reproduction

```bash
# free model swap under a fixed advertised name:
#   edit MODEL/REVISION in serve.py; set chute.chute._name = "<fixed advertised name>"
chutes deploy serve:chute          # $0 if name+image unchanged
chutes warmup serve:chute          # ~17-21 min cold start (provisioning-dominated, not model size)
curl -s -H "Authorization: Bearer $CK" \
  https://<slug>.chutes.ai/v1/models | jq '.data[0].id'   # advertised name, not the loaded model
# instance shows verified=True despite the mismatch:
curl -s -H "Authorization: Bearer $CK" https://api.chutes.ai/chutes/<chute_id> \
  | jq '.name, (.instances[]|{id:.instance_id,verified})'
```

Cold-start note: ~17-21 min observed for both 0.5B and 1.7B models; the model download is
~7 s, the rest is pod provisioning (~12 min) + vLLM/TEE engine init (~5 min). Cold start is
**not billed** (balance flat until `active`).
