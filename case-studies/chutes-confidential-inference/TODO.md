# Chutes case study — open TODOs

Deferred from the 2026-05-25 `sek8s` discovery session. The container-rental report
(`DEVPROOF-REPORT-container-rental.md`) is written; these are the follow-ups.

## 1. Prove the base image is reproducible (the load-bearing TODO)
Turn "claims reproducible" → "verified reproducible." `chutesai/sek8s` ships the recipe.
- Download `https://vm.chutes.ai/tdx-guest.qcow2` (~40.6 GiB, public, no auth) and verify
  `sha256 == 1d53800f1c18e353ce43bbad886f3b38555b7fc38c3362b04af30d11a16f7b46`
  (`sek8s/host-tools/scripts/quick-launch.sh:17-20`).
- Run `guest-tools/scripts/{extract-vm-measurements,extract-acpi,compute-measurements}.sh`
  (Intel `tdx-measure`) and confirm the recomputed MRTD == the live golden `DDC6EFCD…EC38C`
  and RTMR0–2 match per-hardware (`8xRTX_PRO_6000` RTMR0 `4C8263E6…`, `8xh200` `DC2B0C8E…`).
- Harder leg: rebuild the qcow2 from `ansible/guest` and check the *artifacts* (vmlinuz/initrd/
  rootfs) reproduce bit-for-bit, not just that the shipped artifacts measure to the golden value.
- Needs: `guestfish` (libguestfs-tools), TDX-capable QEMU, `tdx-measure` (Intel tdx-tools).

## 2. Poke the image without building
- Production qcow2: rootfs is LUKS → only the **boot chain** is inspectable. Extract the
  **initramfs** (holds the attestation→LUKS-key flow, `rtmr3-measure`, `fetch_key`,
  `fetch_key_and_unlock` — `sek8s/ansible/guest/roles/luks/files/initramfs/`) and read it.
- Full rootfs (admission policy, `cosign.pub`, services) is encrypted in the prod image →
  audit from `sek8s` source, OR get the **debug image** (`tdx-guest-debug.qcow2`:
  "no encryption, SSH enabled", `config.debug.example.yaml`). That URL is **404 today** —
  ask Chutes to publish it, or build it.

## 3. Rekor transparency probe (R5)
`forge` signs chute images with `cosign sign --key …` (no `--tlog-upload=false`, cosign v2.6.3
→ public tlog by default; admission policy also pins `rekor_url`). So signatures *should* be in
`rekor.sigstore.dev`.
- Confirm chute-image entries actually appear in the public Rekor log.
- Querying by key needs Chutes' `cosign.pub`, which is **not published** (baked into LUKS
  rootfs). Worth asking Chutes to publish it — cheap, high-value transparency win.

## 4. Revise the inference report (`DEVPROOF-REPORT.md`) for the sek8s findings
The original F1/F2 were written from the 3 app repos only and are now partly overtaken:
- **F2 (golden = TOFU):** soften — `sek8s` publishes the builder + `tdx-measure` recompute +
  pinned-SHA256 prebuilt qcow2. Provenance is *reachable* (pending TODO #1), not pure TOFU.
- **F1 (workload not measured):** add the **measured OPA+cosign admission controller** (`sek8s`,
  default-deny `"*"`) — substitution requires Chutes' key, not "nothing checked." Reframe as
  key-custody trust, not a silent gap.
- Update repo refs `rayonlabs/* → chutesai/*` (org renamed; 301 redirect).

## 5. ~~Verify the rootfs-integrity sub-claim (R2)~~ — RESOLVED (see EXPLOITABILITY-VALIDATION.md F1)
Answered: rootfs is **dm-crypt LUKS2, no dm-verity**, but integrity holds because the LUKS key is
released **only into measured-guest TEE memory** (quote-gated `fetch_key_and_unlock`) — a miner
can't extract it to tamper offline — and on **v1.3.0** RTMR3 file-measures `/etc/opa/policies`,
`/opt/sek8s/src`, and the admission CA (`tdx-measure.conf`). The admission webhook is fail-closed
(`failurePolicy: Fail`), self-protecting (`webhook.rego`), and gated on `rtmr3-verify.service`.
Residual = operator-trust only (a key-holder, i.e. Chutes, could rewrite the dm-crypt rootfs).
