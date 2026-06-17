# Chutes — operator code on the prompt path is unmeasured: live prompt exfiltration from a verified TEE

**Date:** 2026-06-16/17 · **Method:** hands-on against a `-TEE` chute we deployed on our *own*
`api.chutes.ai` account (1×RTX PRO 6000), plus a read of the SDK (`chutes==0.6.9`). Line numbers are from
that wheel and may differ from the pinned `chutes 08d79872`.

A chute's `serve.py` is operator-written code that runs **inside the TEE** and receives every user's prompt
**in plaintext**, immediately after the measured `aegis` library decrypts it. That code is in **no measured
register**, so nothing in the attestation a client checks reveals what it does. A chute can therefore pass
full TDX+GPU attestation — `verified=True` — while reading and exfiltrating the prompts of everyone who uses
it.

We demonstrated this end-to-end on a chute we deployed on our own account: operator-added middleware harvested
other callers' decrypted prompts and returned them verbatim to a colluding client, with no network egress and
nothing in any log.

This is the live evidence behind the lead finding of [`REPORT-inference.md`](./REPORT-inference.md) (I3) and
the unmeasured-code root cause in [`PLATFORM.md §4`](./PLATFORM.md#4-the-root-gap-that-splits-the-two-reports).

---

## The plaintext handoff

The decryption boundary is measured (`aegis`); it then hands plaintext to operator-authored, unmeasured
`serve.py` in the same process. On the verified-E2E path, inside the TD (`entrypoint/run.py`, `_dispatch`):

```
:1304  e2e_plaintext = handle.e2e_decrypt_request(e2e_ctx, e2e_raw)
:1312  e2e_plaintext = gzip.decompress(e2e_plaintext)
:1314  e2e_body      = json.loads(e2e_plaintext)     # user's prompt, plaintext, in-process
```

`e2e_body` is dispatched to the cord handler in the operator's `serve.py` (`@chute.cord`). The operator has
full Python execution here — custom cords, `@chute.on_startup`, `add_middleware`, background tasks reading
process memory. Because `serve.py` is in no RTMR, a verifying client cannot detect that this code logs,
stashes, or ships the plaintext out.

## Live demonstration

On a self-deployed chute (`verified=True`, 1×RTX PRO 6000), two steps:

**1 — Operator code provably reads the decrypted plaintext.** A `BaseHTTPMiddleware` (added via
`_c.add_middleware`, so it runs inside the runtime's decrypt layer) branched on a private constant. Only the
exact literal `EXFIL_DUMP_8c2f` changed the response (→ HTTP 500; `EXFIL_DUMP_9999`, `EXFIL_DUMP`, and
ordinary prompts → 200, repeatably). The only code in the stack that can match that constant against request
*content* is the operator's middleware ⇒ it reads the E2E-decrypted plaintext.

**2 — Cross-user exfiltration, no egress.** The middleware accumulated every request's plaintext in a
process-RAM reservoir. Two "victim" callers sent secrets (`…recovery phrase alpha-bravo-charlie-7` and
`…routing 021000021 account 55512345`). A third caller, holding only an ordinary API key, sent the trigger
`EXFIL_DUMP_8c2f`; the middleware rewrote that prompt so the **model echoes the reservoir verbatim** — riding
out inside a normal, properly-encrypted completion. The attacker received **both victims' prompts back**. No
network egress, no logs: cross-user plaintext pulled through the legitimate inference channel of a
`verified=True` enclave.

The process is long-lived (warm window, `concurrency=32`), so up to 32 users' decrypted prompts coexist in
memory. The model is used as the carrier because the runtime rejects a raw operator-crafted response; with
`allow_external_egress=True` — required to pull weights from HF at boot — a direct network POST is simpler.

## Scope: a verifiability gap, not a remote exploit

The TEE and E2E genuinely protect against the network and the miner host (host-swap is contained —
[PLATFORM §3](./PLATFORM.md#3-the-miner-is-contained-a-malicious-host-cannot-swap-code-or-read-memory)). What
is missing is that attestation does not let a downstream user verify, *without trusting the chute operator*,
that their prompts stay private — and removing operator trust is the entire reason to use a TEE. The exposure
is real wherever a chute is offered *as* private inference to users who did not deploy it (e.g. the models on
`llm.chutes.ai`, where a user picks a model without knowing who deployed it, or a third party reselling a
chute as confidential). In self-tenant use you trust your own code and there is no victim. The threat actor is
the operator (whoever uploads `serve.py`), never a network attacker and not a miner.

## You cannot even self-attest your way out

The obvious mitigation — an operator-published `/whatami` cord that reads `/app/chute.py` and binds it to a
client nonce — does not route: custom non-passthrough cords on a `standard_template="vllm"` TEE chute return
gateway `500 "No infrastructure available to serve request"` (the gateway routes only the template's declared
OpenAI paths, though the instance does register the cord in its e2e allow-list, `run.py:~2304`). So even a
well-meaning operator cannot prove their code to a client on the standard path.

## Why egress controls don't fix it

The strongest channels need no network egress, because decrypted prompts persist in process memory across
requests:

| Channel | Needs egress? | Mechanism |
|---|---|---|
| Network POST to a collector | yes (`allow_external_egress=True`, required to pull weights from HF) | operator code POSTs plaintext out |
| **Cross-request RAM harvest → colluding client** | **no** | accumulate prompts in a module global; return the harvest inside the response to a trigger the operator sends to their own chute. Defeats full network isolation. (This is the demo above.) |
| Pod-log channel | no | `logger.info(plaintext)` → operator reads `/instances/{id}/logs` (Chutes' own observability API). The SDK disables *vLLM's* request logging (`--no-enable-log-requests`) but not operator `serve.py` logging. |
| Model steganography | no | a model fine-tuned to encode recently-seen context into low-order token choices / whitespace / response timing to a colluding client — requires control of the weights, which are likewise unmeasured |

So pinning egress off narrows but does not close the gap; the fix has to be measurement, not network policy.
And because the stego channel rides the *weights*, the fix must measure `serve.py` **and** `model‖weights`.

## Most of the in-TD execution surface is unaudited

This PoC covers only the **vLLM TEE inference cord** path. Chutes exposes several in-TD execution surfaces:

| Surface | Audited? | Code-exec risk in-TD |
|---|---|---|
| vLLM / SGLang / diffusion / embedding template cords | partial (vLLM) | handler on the plaintext path |
| custom cords · `@chute.on_startup`/`on_shutdown` · `add_middleware` | this doc | arbitrary Python in the chute process |
| **Jobs (`@chute.job`, `ssh=True` or batch)** | **no — `job_quota=0`, untestable** | **SSH shell / arbitrary batch in the enclave + `output_dir` + egress** |
| non-TEE GraVal path (normal chutes) | n/a | no confidentiality by design |

**Jobs are the largest unaudited surface** — an interactive SSH shell *inside the TEE* is a far bigger
code-exec surface than a cord, yet the path is quota-gated to 0 (`Daily job quota exceeded: job_quota=0`), so
its attestation behaviour (what the validator checks for a job vs a cord; whether the job binary is measured)
is undocumented and untestable without Chutes granting quota — itself a finding.

---

## Fixes (server-side; a client cannot close this)

- **Measure the workload.** Extend `SHA256(image_digest ‖ model ‖ revision ‖ serve.py)` into RTMR3 and publish
  the expected values, so a client can confirm both which code and which weights ran.
- **Disclose the code.** Even public chutes return `code: null`, so a client cannot read which handler is
  declared. Publish it (or `chutes share` to the verifier) so the measured value has a readable preimage.
- **Pin egress off under a measured NetNanny for confidential chutes** — narrows the exfil surface (does not
  close the egress-free channels above; weights must then be baked into the measured image, not runtime-pulled).

---

## Reproduction

The gap is reproducible by deploying any `-TEE` chute with operator middleware that touches the request body:

```python
# in serve.py, before deploy:
@_c.add_middleware(BaseHTTPMiddleware)   # runs inside the runtime decrypt layer
async def tap(request, call_next):
    body = await request.body()          # E2E-decrypted plaintext, in-process
    ...                                  # read / stash / rewrite
```

Deploy, warm, then send requests as separate API keys: the middleware sees every caller's decrypted prompt,
and the chute reports `verified=True` throughout (`GET /api.chutes.ai/chutes/<chute_id>` →
`instances[].verified`). Nothing a client verifies — DCAP signature, debug-off, `report_data` binding, golden
MRTD — changes whether `serve.py` is benign or not.
