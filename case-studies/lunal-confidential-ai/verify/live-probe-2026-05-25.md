# Live probe — 2026-05-25

## Endpoints
- Inference (demo, **open / no auth**): `https://llama-3b.lunal.dev` — OpenAI-compatible (LiteLLM/`hosted-vllm-server` by AmeanAsad), `server: uvicorn`. Model id: `together_ai/meta-llama/Meta-Llama-3-8B-Instruct-Lite`.
- Product API gateway (auth, **bearer required**): `https://api.confidential.ai/v1/*` — `via: 1.1 Caddy` (the tee-proxy). 401 `{"code":"unauthenticated"}`. `/health` 200.
- Demo SPA: `https://private-inference-demo.confidential.ai` (Next.js/Vercel). WASM verifier: `GET /pkg/lunal_attestation_bg.wasm` (200, `application/wasm`) = compiled `attestation-wasm` crate (`verify_snp`).

## Response headers on llama-3b.lunal.dev (IDENTICAL on /v1/models, /health, and a 404)
- `Attestation-Report:` base64+gzip → **Azure HCLA** binary (9185 B), SNP report + embedded PEM chain. Static across requests.
- `Gpu-Attestation:` HS256 JWT, `iss=LOCAL_GPU_VERIFIER`, `hwmodel=GH100 A01 GSP BROM`, `secboot=true`, `dbgstat=disabled`, fixed `eat_nonce=a96eb3a3…7177`. **iat=2025-08-06 22:52Z, exp=2025-08-06 23:52Z — expired ~9 months before probe.** Served identically every request.

## Demo client verification (page chunk f6a86b75…)
- Endpoint hardcoded: `u="https://llama-3b.lunal.dev"` (not operator-env — good).
- "verified" gate: send button + input `disabled:"verified"!==a`. Chat blocked until verified.
- "verified" = WASM `verify_snp` (SNP cert-chain + sig) **+ report_data == bundled approved-model hash**.
  - Bundled expected: `pR.value="b9bba338f4c1ab7efd0264ec1a77df7232f15de17f1deb527fa55b90f4915a85"`, `maps_to="https://github.com/AmeanAsad/hosted-vllm-server…"`.
  - report_data is thus a **static code-repo label**, NOT a TLS/channel or fresh-nonce binding.
- **GPU attestation never verified client-side** — no reference to the `Gpu-Attestation` header, its `exp`, or nonce anywhere in the bundle. UI string "NVIDIA GPU attestation with hardware-verified integrity" is displayed, not checked.
- No launch-measurement (MRTD/SNP-measurement) comparison — measurement only displayed (consistent with library F1).

## Reproduce
    curl -sS -D - -o /dev/null https://llama-3b.lunal.dev/v1/models | grep -iE 'attestation-report|gpu-attestation'
    # decode GPU token:
    echo "<gpu-attestation payload>" | tr '_-' '/+' | base64 -d | python3 -m json.tool
