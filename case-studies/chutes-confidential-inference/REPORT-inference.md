# Chutes Consumer Inference — DevProof Report

**Surface:** you call a hosted `-TEE` model on `llm.chutes.ai` that *someone else deployed*. You did
not write the code that runs in the enclave.
**The question:** can anyone — Chutes' control plane, the miner host, or the chute's operator — read
your prompts, and is the model that answers actually the one named?
**Shared facts** (crypto core, base-image provenance, miner containment, lower-tier F4/F5) live in
[`PLATFORM.md`](./PLATFORM.md) and are not restated here.

This is a **devproof** audit: the question is whether Chutes' "not even we can see your data" claim
(`docs/tee-verification.md:5`) is *externally verifiable by a client without trusting Chutes* — not
whether the system is "secure" in the abstract.

---

## Quick status (consumer viewpoint)

| Property | Verifiable today? | Notes |
|---|:--:|---|
| Talking to a genuine non-debug TDX enclave, E2E key hardware-bound, fresh | ✅ | [PLATFORM §1](./PLATFORM.md#1-the-cryptographic-core-is-sound-verified-live) |
| Default `llm.chutes.ai` request kept from Chutes | ❌ | **I1** — plaintext at the control plane |
| Verify-then-encrypt by default on the E2E path | ❌ | **I2** — discovery hands out keys with no quote; no shipped verifier |
| Prompt kept from the **chute operator** (even on a perfect E2E path) | ❌ | **I3** — operator's `serve.py` sees plaintext, unmeasured |
| **Which model** answers | ❌ | **I3** — model identity in no measured register |

**Bottom line:** the hardware root is real and the crypto is correct, but the confidentiality claim
collapses at two points the client cannot close — the default path is plaintext at Chutes (**I1/I2**),
and the in-enclave code that touches plaintext is operator-authored and unmeasured (**I3**, demonstrated
live). "Verify without trusting us" does not hold for the consumer.

---

## I3 — Operator code & model are unmeasured → prompt exfiltration + model substitution (lead finding)

The decryption boundary is measured (`aegis`), but it hands plaintext to **operator-authored, unmeasured
`serve.py`** in the same process. Inside the TD on the verified-E2E path (`entrypoint/run.py`):

```
:1304  e2e_plaintext = handle.e2e_decrypt_request(e2e_ctx, e2e_raw)
:1312  e2e_plaintext = gzip.decompress(e2e_plaintext)
:1314  e2e_body      = json.loads(e2e_plaintext)     # user's prompt, plaintext dict, in-process
```

`e2e_body` is dispatched to the cord handler defined in the operator's `serve.py` (`@chute.cord`). The
operator has full Python execution in this process — custom cords, `@chute.on_startup` hooks,
`add_middleware`, background tasks reading process memory. Because `serve.py` is **excluded from CFSV and
in no RTMR** ([PLATFORM §4](./PLATFORM.md#4-the-root-gap-that-splits-the-two-reports)), a verifying client
**cannot detect** that the running code logs, stashes, or ships the plaintext out.

**Two consequences from the one root cause:**

- **Confidentiality (the headline claim).** Even a client that does everything right (DCAP sig, debug-off,
  `report_data[0:32]` binding, golden MRTD) gets confidentiality against the **control plane and miner host**
  (they see ciphertext) but **not against the chute operator**, who authors the code that touches plaintext.
  On `llm.chutes.ai` users select a model without knowing or trusting who deployed it. **Demonstrated live**
  — cross-user prompt exfiltration on a `verified=True` enclave, egress-free, via the model-as-carrier
  channel. See [`OPERATOR-EXFIL-POC.md`](./OPERATOR-EXFIL-POC.md).
- **Model identity.** Nothing binds `model_name`+`revision` to the quote; the served label is the *chute's*
  name (`--served-model-name {self.name}`), set by the operator and decoupled from the actual weights. The
  operator re-points the same named, `verified=True`, billed endpoint at arbitrary weights — **demonstrated
  live for $0** (SmolLM2-1.7B + Qwen-0.5B served under an `…Euryale-70B…` name; `/v1/models` reports the
  false name).

**Severity: High — the maximal prompt-path failure.** The operator owns *all* the code that sees plaintext,
so this negates the confidential-inference claim at the application layer for any chute offered *as* private
inference to downstream users. It is a **verifiability failure, not a remote exploit**: the TEE+E2E genuinely
protect against the network and the host (miner-swap is refuted —
[PLATFORM §3](./PLATFORM.md#3-the-miner-is-contained-a-malicious-host-cannot-swap-code-or-read-memory)). The
exposure is real only where there is a **trust separation** — a consumer relying on an operator they don't
control. In self-tenant use you trust your own code and there is no victim (that case is
[`REPORT-rental.md`](./REPORT-rental.md)).

**Client-side mitigation exists for substitution, not for exfil.** Model *substitution* can be caught without
Chutes' cooperation by **logit fingerprinting** over the verified-E2E channel (greedy challenge prompts,
top-k logprobs vs a reference for the claimed model; secret per-session probes prevent precompute). It
distinguishes SmolLM2-vs-Euryale trivially but blurs on close finetunes/quant, and does **nothing** for
exfil — closing that requires the code itself measured (see Fix).

**Fix:** [PLATFORM §4](./PLATFORM.md#4-the-root-gap-that-splits-the-two-reports) — measure
`image_digest‖model‖revision‖serve.py` into RTMR3, publish model-keyed values, disclose the chute `code`.
Pin egress off under a measured NetNanny for confidential chutes (removes the easy exfil channel; weights
must then be baked into the measured image, not runtime-pulled).

---

## I1 — The default path is plaintext at the control plane (broadest exposure)

**Claim under test:** chutes.ai markets confidential inference as "not even we can see your data."

The standard OpenAI-compatible path (`llm.chutes.ai` → `chutes-api/api/invocation/router.py`) handles the
prompt **in plaintext at the control plane**: it `await request.json()`s the body, rewrites `payload["model"]`
(alias resolution, incl. mapping plain names to `-TEE` variants — `router.py:902-930`), iterates
`payload["messages"]` (`:933`), and computes `get_prompt_prefix_hashes(request_body)` over
`payload["prompt"]`/`["messages"]` for prefix-cache routing (`:605`, `invocation/util.py:314-322`) before
forwarding to the instance.

**Verdict: EXPLOITABLE / by-design.** For the path the vast majority of API users hit, Chutes **does** see
prompts (and routing/usage). The TEE still protects prompts from the *miner/host* (memory isolation), but
**not from Chutes**. The "not even we" guarantee is true only on the explicit `/e2e/invoke` path with a
verifying client (I2). This is the single most impactful gap between claim and reality, and it isn't a bug —
it's the default architecture. **Priority: highest by exposure** (what most users are actually subject to).

**Fix:** make verified-E2E the default route, or stop marketing default inference as "we can't see your data."

---

## I2 — Verify-then-encrypt is optional; no shipped client verifies

Discovery and attestation are separate endpoints. `GET /e2e/instances/{chute_id}` returns
`{instance_id, e2e_pubkey, nonces}` with **no quote** (`e2e/router.py:144-151`); the `e2e_pubkey` is a
miner-supplied DB field (`instance/router.py:1416`). Nothing in the discovery or `/e2e/invoke` path
cross-checks it against a quote. The only runnable example, `scripts/test_e2e_client.py:120-128`, calls
`build_e2e_blob(instance["e2e_pubkey"], …)` straight from `discover_instances()` — **no `/evidence` call,
no `report_data` check**. The chutes SDK ships **no** consumer-side verifier (only the instance-side
producer `entrypoint/verify.py`).

**Verdict: EXPLOITABLE** by the control plane against any non-verifying E2E client, with no special access:
return an attacker-controlled `e2e_pubkey` and read every prompt — TDX bypassed. The docs describe the
secure pattern and even warn about this MITM (`docs/tee-verification.md:409-411`), but the demonstrated code
contradicts it, and the server cannot enforce client-side verification by construction. **Severity: High** —
the failure is silent and the canonical example is the insecure variant.

**Fix:** fold the `/evidence` fetch + `report_data[0:32]==SHA256(nonce‖e2e_pubkey)` check into the E2E SDK
so verify-then-encrypt is the default, bound to the exact `instance_id`+`e2e_pubkey` the client encrypts to.

---

## Stage assessment

Against the framework's prompt-path / external-verifiability rubric:

- **Confidentiality (operator can't read prompts):** **fails** for the consumer. Default path is plaintext at
  Chutes (I1); the opt-in E2E path is silently MITM-able with no shipped verifier (I2); and even a perfectly
  verified E2E session leaks to the unmeasured operator code that holds the plaintext (I3, demonstrated). In
  the guide's **Prompt-Path Test** terms, the entire chute `serve.py` is an operator-controlled, unmeasured
  slot **on the prompt path** → fails Stage 1 §4 (no operator access to secrets) and §7 (no backdoor paths).
- **Integrity / "right model":** does not reach the dstack cohort's posture — model identity is in no
  measured register (I3). A verified quote proves genuine TDX+GPU running *a* Chutes-blessed base image.

Net: the hardware root is real and the crypto is correct; the verifiability chain breaks at the application
layer, where the operator owns all the code that sees plaintext and the model is unmeasured.

## Recommendations (priority order)

1. **(I1/I2)** Fix the actual confidentiality exposure: make verified-E2E the default and ship a verifying
   client, or stop marketing default inference as private.
2. **(I3)** Measure the workload — `image_digest‖model‖revision‖serve.py` into RTMR3 + model-keyed golden
   values + disclose the chute `code`; pin egress off under a measured NetNanny for confidential chutes.
3. Lower-tier (F4 GPU offline verdict, F5 per-TD LUKS keys): [PLATFORM §5](./PLATFORM.md#5-lower-tier-shared-facts-operator-trust--enforced-server-side).

Cross-references: model-substitution family — [near-ai-private-inference](../near-ai-private-inference/),
[redpill-federated-inference](../redpill-federated-inference/) (which federates to these backends);
verify-then-encrypt / incomplete-easy-path — mirrors the NEAR web-verifier and Darkbloom F5 patterns.
