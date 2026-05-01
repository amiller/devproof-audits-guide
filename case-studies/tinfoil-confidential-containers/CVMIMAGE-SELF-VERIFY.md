# Self-verifying cvmimage from inside a customer container

**Companion to:** [`DEVPROOF-REPORT.md`](DEVPROOF-REPORT.md)
**Date:** 2026-04-30
**Test artifact:** [`amiller/devproof-tinfoil-experiments@v0.6`](https://github.com/amiller/devproof-tinfoil-experiments/releases/tag/v0.6)

A customer-deployed container can independently verify that the cvmimage running underneath it is byte-for-byte the disk Tinfoil's CI signed via Sigstore — without trusting Tinfoil's controlplane, the verification CDN, or the Sigstore signature itself. The technique works today against the production fleet, takes ~30 seconds per probe, and is a useful complement to the standard SDK verification path (which trusts the Sigstore signature on the manifest).

---

## Why this matters

Tinfoil's release flow signs a `tinfoil-deployment.json` manifest containing four content hashes for the disk components:

```json
{
    "version": "v0.7.5",
    "root":   "5c1f3121fb34dbf8b55d35abbd328daaab589f1e2566bc6c99afdc231d705f59",
    "initrd": "1bb89997c15dd48e67b79431079505262da64df0cad11c12f0994fac8d61bd97",
    "kernel": "39cc3d97d415d99523754af0203f3951fa3bfdace5f3387926ccf2a7fd4fc8f0",
    "raw":    "684b5b68b43495f0a4aef1db8bbd79fcd9040852444329c560951455cd55b181"
}
```

Sigstore signs *this manifest*, but Tinfoil does not publish the actual `.raw`/`.initrd`/`.vmlinuz` binaries anywhere I could find — only `manifest.json` and `tinfoil.hash`. To independently verify these hashes there are two paths: (a) `make build` from cvmimage source and check your hashes match (mkosi-based, ~15 min, reproducibility unproven), or (b) **read the disk from inside a running CVM and hash it directly** — which this document demonstrates.

---

## The probe

YAML ([`v0.6 tinfoil-config.yml`](https://github.com/amiller/devproof-tinfoil-experiments/blob/v0.6/tinfoil-config.yml)):

```yaml
cvm-version: 0.7.5
cpus: 2
memory: 8192
containers:
  - name: rootfs-attest
    image: python:3.11-alpine@sha256:8b5bfdb1fd2d78aa94e21c4d61be52487693f54be7f1021647751ff365795703
    devices: [/dev/sda, /dev/sdb, /dev/sdc]
    volumes: ["/proc:/host-proc:ro"]
    command: [python3, -c, "<HTTP server that hashes each device + reads /proc/cmdline>"]
shim: { upstream-port: 8080, paths: [/*] }
```

Key facts:
- `devices: [/dev/sd?]` is passed straight to Docker by [`containers.go:317-322`](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/containers.go#L317-L322) as `hostConfig.Devices` with `CgroupPermissions: "rwm"`. Tinfoil's controlplane accepts this without filtering.
- `volumes: ["/proc:/host-proc:ro"]` is passed straight through as a Docker bind mount.
- The container is just `python:3.11-alpine` running a one-page HTTP server.

Deploy + curl returns:

```
sda: 684b5b68b43495f0a4aef1db8bbd79fcd9040852444329c560951455cd55b181  (10,470,051,840 bytes)
sdb: <2048 bytes — first ~700 are our YAML, rest are zero padding>
sdc: <1024 bytes — controlplane-written external config>
cmdline: ... roothash=5c1f3121... tinfoil-config-hash=<our YAML hash>
```

---

## The four checks that fall out

### 1. Rootfs binary integrity (`/dev/sda` ↔ `manifest.raw`)

```python
sda_hash       = sha256(/dev/sda)                           # = 684b5b68...
manifest_raw   = json.load(release_assets/manifest.json).raw # = 684b5b68...
assert sda_hash == manifest_raw  # ✓
```

Verifies Tinfoil's CI honestly computed the `raw` hash in the signed manifest. The bytes on the running CVM's disk match the bytes Tinfoil's CI signed.

### 2. Rootfs Merkle root (`cmdline.roothash=` ↔ `manifest.root`)

```python
cmdline_root   = parse_kv(/proc/cmdline)["roothash"]        # = 5c1f3121...
manifest_root  = json.load(release_assets/manifest.json).root # = 5c1f3121...
assert cmdline_root == manifest_root  # ✓
```

Independent of #1 — the SEV-launch-measured cmdline carries the dm-verity Merkle root. Combined with the kernel's per-block dm-verity verification (active per `/sys/block/dm-0/dm/uuid: CRYPT-VERITY-...-root`), this proves no block of the rootfs has been tampered post-boot.

### 3. Attested config integrity (`/dev/sdb` ↔ `cmdline.tinfoil-config-hash=`)

```python
sdb_yaml       = strip_nulls(read(/dev/sdb))                # the YAML we sent, null-padded to 2048B
sdb_hash       = sha256(sdb_yaml)                           # = fd091c43...
cmdline_hash   = parse_kv(/proc/cmdline)["tinfoil-config-hash"]  # = fd091c43...
assert sdb_hash == cmdline_hash  # ✓
```

The null-strip step matches cvmimage's [`readDiskAndStripNulls`](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/config.go#L103). Verifies the attested config disk content matches what's bound into the SEV launch measurement.

### 4. External config visibility (`/dev/sdc` — never measured, always observable)

The controlplane writes a small YAML to `/dev/sdc`:

```yaml
env:
    DOMAIN: rootfs-attest.andrew-miller.containers.tinfoil.dev
metadata:
    cpu: amd
    domain: rootfs-attest.andrew-miller.containers.tinfoil.dev
    gpu: 0xh200
    id: ijkdcttjopfhuzfs
    image: amiller/devproof-tinfoil-experiments@v0.6
secrets:
```

Two new findings here that aren't documented anywhere I can find:

1. **Platform-injected `env:` slots.** `DOMAIN` is auto-written by the controlplane regardless of operator input. Per `buildEnv`'s dispatch ([containers.go:401](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/containers.go#L401)), this only takes effect if the YAML declares `env: - DOMAIN`. The model-router from the [sister case study](../tinfoil-confidential-inference/DEVPROOF-REPORT.md) does declare it — that's how it gets its routing-suffix filter without the operator passing anything.
2. **A `metadata:` block** (cpu, gpu, id, image, domain) injected by the controlplane. cvmimage's `getExternalConfig` reads only the `env:` and `secrets:` keys; the `metadata:` block appears to be unread by the boot code I've read. Possibly used by some future code path, possibly debug-only telemetry. Worth a follow-up.

The external config disk is unmeasured (per [config.go:189-204](https://github.com/tinfoilsh/cvmimage/blob/main/tinfoil/cmd/boot/config.go#L189-L204) it's read verbatim with no integrity check) and *also* observable from inside any container that mounts `/dev/sdc`. So a paranoid operator can prove "the controlplane wrote exactly these values to my CVM, and I know which slots in my YAML pull from them."

---

## What this technique buys you

It closes the last gap in the verification chain that existed before this audit:

| Trust step | Before this experiment | After |
|---|---|---|
| `manifest.raw` hash → published binary bytes | trust Tinfoil CI computed it correctly (no other path — binaries unpublished) | self-verify by hashing `/dev/sda` from inside |
| `manifest.root` Merkle root → running rootfs | trust Tinfoil CI computed it; verifier checks SEV measurement chain | independent confirmation via `/proc/cmdline` |
| `tinfoil-config-hash=` cmdline → on-disk YAML | trust the boot script verified it | independent confirmation via `/dev/sdb` |
| External config disk content | inferred from cvmimage source code | observable directly |

A useful adversary scenario this rules out: "Tinfoil's CI publishes a manifest with hash X but actually deploys a different binary with hash Y." Pre-experiment, this was undetectable from outside (you don't have the binary to hash). Post-experiment, any customer container that hashes `/dev/sda` would catch it.

---

## What it doesn't buy you

- **Doesn't verify reproducibility** — you've matched the running disk to the published manifest, but if the manifest is signed for tampered source code, you'd never know without rebuilding from cvmimage source and matching to your own hash.
- **Doesn't verify the boot path** — the kernel reads the rootfs, but verifying the *kernel itself* matches `manifest.kernel` requires reading the kernel image off the disk, which requires either parsing the disk's partition table or finding where the kernel is on the EFI partition.
- **Doesn't help if the controlplane lies about which manifest is current** — you're verifying against the manifest you fetch from Sigstore, but if the controlplane provisions an old/malicious image and the Sigstore service is censored, you might not see the discrepancy. The attestation chain still anchors via the SEV launch measurement (which depends on kernel + initrd + cmdline + OVMF, all signed), but a sufficiently coordinated adversary controlling the controlplane and the verification CDN could mislead — caching proxies are the weak link.
- **Doesn't extend to TDX deployments** without modification — sda/sdb/sdc are SEV-host conventions; TDX hosts may use different device paths.

---

## Proposed: ship this as a verifier feature

A useful primitive for the awesome-private-inference registry: a per-host probe that deploys a tiny "self-verify" container, hashes `/dev/sda`, compares to the manifest, and posts the result to the daily probe matrix. Would catch any divergence between the signed manifest and what's actually running on Tinfoil's fleet — a strictly stronger signal than the current SDK-style "verify the Sigstore signature on the manifest."

Could be integrated as `verifiers/tinfoil_disk_attest.py` in [`amiller/awesome-private-inference`](https://github.com/amiller/awesome-private-inference). Daily probe → deploy `rootfs-attest` → curl → diff against published manifest → emit pass/fail to the dashboard. Cost: one CVM-second per day per Tinfoil deployment we want to monitor.

---

## Reproduction

```bash
# Deploy
tinfoil container create rootfs-attest \
  --repo amiller/devproof-tinfoil-experiments \
  --tag v0.6
# Wait for ready (~90s)

# Hit it
curl -sSk https://rootfs-attest.<your-org>.containers.tinfoil.dev/ > probe.json

# Compare
jq -r '.sda.sha256' probe.json
# 684b5b68b43495f0a4aef1db8bbd79fcd9040852444329c560951455cd55b181

curl -sSL https://github.com/tinfoilsh/cvmimage/releases/download/v0.7.5/tinfoil-inference-v0.7.5-manifest.json | jq -r .raw
# 684b5b68b43495f0a4aef1db8bbd79fcd9040852444329c560951455cd55b181
```

If the two hashes match, the cvmimage running underneath your container is the published v0.7.5 image, byte-for-byte.
