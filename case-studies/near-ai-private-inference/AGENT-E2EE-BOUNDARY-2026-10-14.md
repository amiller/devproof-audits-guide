# NEAR agent E2EE: field coverage and tool disclosure

**Evidence date:** 2026-10-14. **Method:** source inspection, not a live deployment audit.
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
