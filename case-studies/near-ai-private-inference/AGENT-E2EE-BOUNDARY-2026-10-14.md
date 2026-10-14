# NEAR agent E2EE: field coverage and tool disclosure

**Evidence date:** 2026-10-14. **Method:** pinned source inspection and separately scoped live protocol checks; not a complete deployment audit.
This supplement adds an agent-protocol boundary to the [May inference revisit](DEVPROOF-REPORT-revisit-2026-05-02.md).
It does not replace that report's historical observations or change a Stage verdict.
Work is tracked in [research #23](https://github.com/amiller/awesome-private-inference/issues/23)
and [Abalone #73](https://github.com/amiller/abalone/issues/73).

## Source identities

- [inference-proxy efd600a46c4327c8d8d038ab8b01c25a0e74b5bd](https://github.com/nearai/inference-proxy/tree/efd600a46c4327c8d8d038ab8b01c25a0e74b5bd): encryption, chat dispatch, proxy signing and agent loop inspected. No image/compose or model deployment was bound to this revision in this review.
- [nearai-cloud-verifier 94554726fd548676842b7ea603a8173a60c31341](https://github.com/nearai/nearai-cloud-verifier/tree/94554726fd548676842b7ea603a8173a60c31341): encrypted agent-loop example inspected. This is demonstration code, not proof of a verified client.
- Abalone's existing mitigation was inspected at [7c1d9fa](https://github.com/amiller/abalone/tree/7c1d9fa); the ordinary response guard and shared tool boundary are proposed in [PR #74](https://github.com/amiller/abalone/pull/74), not deployed evidence.
- The locally inspected Hermes plugin revision was `7e415c7a2ea7baab99064f3ec887511fdd1c3d99`. Its forwarding code makes the content-only path reachable by incoming chat requests; an active installation has not been established.

## Finding: content encryption is narrower than an agent protocol

A model can reproduce a confidential encrypted prompt in a structured tool argument.
If only message content is encrypted, a gateway terminating HTTPS can read that argument,
a tool schema, or other unprotected fields. Genuine hardware and correct content encryption
do not close this protocol gap.

The current [encryption implementation](https://github.com/nearai/inference-proxy/blob/efd600a46c4327c8d8d038ab8b01c25a0e74b5bd/src/encryption.rs)
has two field-coverage modes. `X-Encrypt-All-Fields` defaults to false. It is parsed
independently from `X-Encryption-Version`: selecting version 2 alone does not enable
expanded field coverage, and the extended field switch is also available with ECDSA.

| Surface | Default encrypted path | Expanded field path |
| --- | --- | --- |
| Message content, reasoning, audio data | Handled | Handled |
| Tool history names/arguments; legacy function-call names/arguments | Outside the default field transform | Handled |
| Tool definitions under tools[].function | Outside the default field transform | Name, description and serialized parameters handled |
| Named tool_choice and legacy function_call selector | Outside the default field transform | Function name handled |
| Refusal and response logprob token/byte data | Outside the default field transform | Handled |
| IDs, roles, type labels, usage and timing | Metadata remains visible | Metadata remains visible |

This is a bounded list derived from code, not a claim that every arbitrary API field is encrypted.
In particular, do not infer coverage of deprecated top-level `functions` definitions from
coverage of `tools[].function`: the inspected definition transformer traverses `tools`.

## Qualification caveat: an opt-in header is not an enforcement proof

Extended request decryption is deliberately permissive: `try_decrypt_field` leaves values
unchanged when decryption fails, and tool parameter objects can pass through unencrypted.
The server therefore supports encrypted fields without requiring that all such fields arrived
encrypted. A client must encrypt them before sending; a wire canary must establish this
without relying on server acceptance as the oracle. Plaintext that already reached a gateway
cannot be made private by rejecting it later inside the enclave.

The [agent-loop example](https://github.com/nearai/nearai-cloud-verifier/blob/94554726fd548676842b7ea603a8173a60c31341/py/encrypted_agent_loop_verifier.py)
sets both the expanded-field header and version 2, but its `fetch_model_signing_pub_key`
reads the key from an attestation report without itself verifying a quote, nonce, approved
measurement or key binding. Successful decryption demonstrates interoperability; it does
not establish verified encryption to approved enclave code. The demo's decryption checks
also do not establish an authenticated complete stream before executing client-side tools.

## Built-in web search differs from ordinary native tools

The inspected [chat dispatcher](https://github.com/nearai/inference-proxy/blob/efd600a46c4327c8d8d038ab8b01c25a0e74b5bd/src/routes/chat.rs)
forces expanded response encryption for the server-side `web_context_search` loop whenever
an encryption context is active. Ordinary chat still honors the client's expanded-field
choice. Search result output is encrypted whenever E2EE is active. Thus the earlier broad
claim that every encrypted search loop requires the client to remember the expanded-field
header is too strong for this source revision.

The [agent loop](https://github.com/nearai/inference-proxy/blob/efd600a46c4327c8d8d038ab8b01c25a0e74b5bd/src/agent_loop.rs)
runs search orchestration inside the CVM and is configured with a search URL/API key.
The configured search service receives the query. The documented destination is Brave;
this review does not independently bind the deployed URL or egress policy. TLS to a search
service is a separate connection and trust boundary from inference E2EE. Even the query alone
can contain a private fact copied from the prompt.

## Client mitigation and next evidence

Abalone describes tool capabilities, requests and results in encrypted message text and
executes tools locally. This closes the native-field exposure without adopting the expanded
protocol, at the cost of a custom parser whose reliability is tracked in [#56](https://github.com/amiller/abalone/issues/56).
Before enabling native tools, qualify:

1. The deployed image/compose, protocol capability and selected model, with client-verified key binding before the first sensitive byte.
2. Both-direction schemas, history, streaming arguments, reasoning and result coverage, including legacy fields, malformed ciphertext and unknown sensitive fields.
3. No plaintext fallback or downgrade: synthetic canaries absent from intermediary-visible bytes, and unsupported replies refused before tool execution.
4. Response authenticity, completeness and anti-splice/replay properties, separately from ciphertext decryptability.
5. Named tool destinations and an explicit local/remote execution and disclosure policy.

Synthetic checks can establish client refusal and ciphertext coverage. They cannot establish
today's deployed service, the host's security, or absence of operator-controlled egress.
No real transcript, live paid query or production configuration was used in this review.


## Live native-tool protocol checks

On 2026-10-14, explicitly budgeted synthetic checks against `z-ai/glm-5.3-flash`
established two consecutive native function calls with encrypted schemas,
names, arguments and result history. A separate call/result/final-answer round
trip passed. Each accepted reply had a genuine `provider_tee` model signature
whose declared request hash matched the client's encrypted wire body and whose
response hash matched the received stream. Six POSTs total gave a catalog-priced
signed-usage estimate of $0.00022808 within a $0.25 authorization. No service-token
attack, external search or real private data was involved.

The model TCB verified as UpToDate. Gateway TCB was OutOfDate with INTEL-SA-01192,
INTEL-SA-01245, INTEL-SA-01312 and INTEL-SA-01313, so strict admission failed before
inference. Protocol-only checks used the existing reported-TCB policy while
retaining quote, freshness, key binding, GPU signature, measured compose,
RPC-trusted Base registry and pinned gateway TLS checks. The observed outer
composes were gateway `41e18f38978b031431dfc8a4fcf6d8c38da62b1b093fd1d0e39e26ee6fad030c`
and model `c82b1a2eaf6996154a5f39ae621643f034b082d5e51edd3d2ba6009273881d86`.
They do not close inner code/weights to this source revision.

[Abalone PR #75](https://github.com/amiller/abalone/pull/75) contains the experimental
codec, persistent bounded-budget harness and fifteen regressions, including actual
Pi native-tool/result history. It authenticates the complete model response before
consolidating fragments for Pi, whose parser expects a complete first function name.
GLM's inline reasoning prefix with thinking disabled required the existing
`</think>` rendering rule; this was separate from successful encryption/signature
checks. Final source checks reverified all six saved live signature proofs. Normal
providers and private-work enablement were not changed.

## Gateway request-hash authority limits action-integrity claims

The reviewed `routes/chat.rs::resolve_request_hash_for_signing` permits trusted
service-token callers (`config.token`) to supply `X-Request-Hash`, including a
hash differing from the body the model backend received. The dispatcher enables
that override only for the trusted path; end-user cloud API keys cannot use it.
The purpose is to preserve client hashes through gateway JSON reserialization.

This is an integrity trust dependency. A genuine model signature matching the
client's hash does not independently prove which body the model consumed: a
privileged gateway can assert that hash while supplying a different encrypted
request. Public-key field encryption does not authenticate its client author.
Reply authenticity, field confidentiality and client-request origin are separate
properties. A synthetic signature-level regression demonstrates this limitation;
it is not a live exploit or evidence of access to deployed service credentials.

Before gateway-independent native-tool execution is qualified, bind the actual
client-authorized request inside the model enclave without a gateway assertion,
or verify a client request signature bound to the response recipient and protocol.
Otherwise explicitly include the gateway, its measured code and privileged
service-credential custody in the trusted boundary and qualify them. The live
protocol checks establish neither resolution. They support field interoperability
and authentic model replies, not a passing private-agent Stage verdict.


## Read-only manager evidence follow-up

A fresh read-only capture on 2026-10-14 independently verified the manager's
Intel quote using PCS collateral. Its TCB was UpToDate; report data bound the
client nonce and digest of 186 actions, and MRTD/RTMR0–3 matched the model quote.
The recorded compose file at commit `46bfd83ec22c179693e06308e40950d540154b4d`
matched SHA-256 `c7c1bf4d82e137b8d2e0788f41cd6637b38bd08fdc74f38e87b4571ce0c8562e`.
These checks authenticate recorded history, not current container/model state.
The fresh report's model outer-compose bytes differ from the earlier native-tool
observations; interoperability results are not transferred to the new capture.

Current [compose-manager source](https://github.com/nearai/compose-manager/blob/aa9de34419c753c432259ecbcc717b6e2a7357c6/src/main.rs#L357)
defines canonical sorted-key compact UTF-8 actions, so reformatting alone does
not prevent verification under that contract. Exact response bytes are now
retained for review and legacy variants. The earlier assertion that original
bytes were always required was too broad. The same source notes that some
compose actions are recorded before success; a signed action is not proof of
an active image. This manager source-to-image relationship remains open.

Public [gateway source](https://github.com/nearai/cloud-api/blob/752e2976a7ee2a8790163974ba4a70dd218bbf3b/crates/inference_providers/src/attested/nearai/mod.rs#L1941)
sets X-Request-Hash while reserializing requests and uses an upstream bearer key
loaded from INFERENCE_API_KEY. The recorded model config supplies TOKEN from
PROXY_TOKEN; equality/custody of deployed secrets is not independently verified.
Source traces explain intended gateway authority, not gateway-independent integrity.

[Abalone PR #75](https://github.com/amiller/abalone/pull/75) adds read-only capture
and manager-quote checks plus seven offline negative/serialization tests.
[Integrity sprint #77](https://github.com/amiller/abalone/issues/77) tracks remaining
active-state/source/artifact evidence and token custody. No new inference POSTs,
configuration changes, release or audit Stage changes resulted from this work.
