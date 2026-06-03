# Targon (SN4 / Manifold Labs) — recon notes

**Repo:** `manifold-inc/targon` @ `46c5e47` ("bump version", 2026-05-21). Published squashed (single commit). Mostly Go.
**Hub repo:** `Manifold-Archive/targon-hub-api` — **404 / deleted** as of 2026-05-25 (the old inference-API product).
**Live services (hardcoded):** `tower.targon.com` (verification + auctions), `tvm.targon.com` (image gateway), `stats.targon.com` (error reporting).
**Whitepaper:** manifold.inc/releases/intel-whitepaper (co-authored w/ Intel) + Intel Community blog.

## What the product actually is now

Not a managed inference API — a **confidential GPU-rental auction marketplace** on Bittensor subnet 4.
- Miners list CVM node IPs + a bid in **cents/hour/GPU** (`docs/miner/miner.md` config.json `nodes:[{ip,price}]`).
- Emissions are split proportionally by **demand auctions** keyed by hardware class
  (`TDX-NVCC-NVIDIA-H200`, `SEV-CPU-AMD-EPYC-V4`, …); unallocated emission is **burned**.
- Stack: **Intel TDX + NVIDIA CC** (Hopper H100/H200, Blackwell B200) and **AMD SEV-SNP** (CPU-only).
- `grep -rniE "completion|chat|inference|openai|prompt|model|/v1/"` over the Go tree → **no inference routing exists in this repo.** The "confidential inference" framing is historical (SN4) / lives in the deleted hub.

## Attestation flow (validator ↔ miner ↔ Tower) — all in this repo

1. Validator hits miner axon `GET /cvm` (`miner/cmd/miner/miner.go:117`). Miner checks the caller has a
   **vpermit** + min stake (`:155`,`:163`), returns its configured CVM node IPs (`:170`).
2. Per node: validator makes a nonce `sha256(vali_ss58)[:16] + uuidv4` (`internal/nonce/nonce.go`) and
   POSTs it to the node's in-CVM agent `http://<ip>:{8080|8980}/api/v1/evidence`
   (`internal/cvm/cvm.go:95`,`:23`) → `{quote, user_data}` (`AttestationResponse`).
3. **Verify** (`cvm.go:175-230`): the *only* local check is `nonce != attestRes.UserData.Nonce`
   (`:184`, a JSON string compare of the **echoed** nonce). It then POSTs the whole blob to
   `tower.targon.com/api/v1/verify-attestation` (`:190`) and trusts the response
   `{valid: bool, error: string}` (`GPUAttestationResponse`, `internal/targon/types.go:32`). If
   `!Valid` → reject (`:227`). **No DCAP / MRTD / RTMR / report_data / JWT parsing client-side.**
4. Passing nodes go into `VerifiedNodes` + a duplicate-`cvm_id` check
   (`internal/callbacks/cvms.go: getPassingAttestations`). Re-run every interval (~72 min / 361 blocks).
5. Emission split + prices come from Tower too: `tower.targon.com/api/v2/auctions`
   (`internal/tower/tower.go:50,56`; consumed in `internal/callbacks/callbacks.go`
   → `TaoPrice`, `Auctions`, `BurnDistribution`).

`grep -rniE "dcap|sgx|report_data|mrtd|rtmr|ita|jwt|x509|ecdsa|measurement" --include=*.go` → **empty.**
The validator treats `quote` as an opaque base64 string. All cryptographic verdict logic is server-side at Tower (which holds the ITA API keys — whitepaper).

## What's in `user_data` (`types.go:54-65`)

`gpu_cards`, `cpu_cards`, `node_type`, `attestation`(=NVCC NRAS tokens), `auction_name`, `nonce`,
`cvm_id`, `quote_type`. **No model / container / code identity of any kind.**

## The closed bits

- **`tvm/install`** — stripped Go ELF (8.2 MB), `BuildID e8f5df5b…`. Embedded module is
  `HostVerification/…`. It is a **host-posture checker + VM provisioner**, NOT a quote verifier:
  - 8 checks: `checker/{bios_info,cpu_cc,cpu_info,cpu_vendor,secureboot,security,os_support,tpm}.go`
    (TDX/SEV enabled, secure boot, IOMMU, microcode, crypto config, TPM). String evidence:
    `crypto_config_check`, `Intel TDX supported`, `seam_loader_enabled`, `Secure Boot is disabled`,
    `kernel_param_autofix`, `MANIFOLD HOST VERIFICATION REPORT`.
  - Flow (`client/attestation_client.go`): `VerificationReport.ToAttestationRequest` → `SubmitReport`
    to the attestation service (`--service-url http://tvm.targon.com`) → receives `attest_token`
    (`json:"attest_token"`) → `GetVMStatus` → `DownloadVM` (`%s/api/cvm/generate`). Report can be
    `Report rejected: %s`. So **initial provisioning is gated on a self-reported, tool-generated host
    report**, not a hardware quote.
- **CVM image** — per-VM **encrypted (LUKS) qcow2**, generated server-side by the Image Gateway and
  bound to the provider IP (whitepaper). The **in-CVM attestation agent** that answers
  `/api/v1/evidence` lives *inside* that encrypted image → in no public repo.
- **Validator** itself also runs inside a Manifold-pulled CVM (`tvm/install --node-type vali-cpu
  --service-url http://tvm.targon.com`, `docs/validator/validator.md`).

## Credit where due (vs the Chutes cohort)

- **Per-VM random disk key** held in ITA-KBS, released only post-attestation, bound to the agent
  (whitepaper) → strictly better than Chutes' single static fleet-wide `LUKS_PASSPHRASE` (their F5).
- **IP-binding anti-clone** (KBS records provider IP on first attest; IP change bricks the VM) → sound
  anti-Sybil for emissions integrity.
- **Unified attestation**: GPU NRAS tokens nested in the TDX quote `user_data` (one machine/session).
- **Uses Intel Trust Authority** (a real DCAP service) rather than a hand-rolled quote parser — the
  verification is plausibly *sound*; the problem is purely that it's locked behind Manifold's Tower
  with no artifact passed back to the relying party.
