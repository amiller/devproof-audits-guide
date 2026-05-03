# NEAR AI Cloud — End-to-End Trust Chain Analysis

**Goal.** Walk every link from the user's E2EE encrypt action down to the
KMS root key inside a TDX TD, citing both the source line that
implements the link and the live observation that grounds it.
Each link gets a verdict: **VERIFIED** (cryptographically closed
end-to-end), **VERIFIED-BY-AUDIT** (closes only because we read the
source at the pinned commit and confirmed it), or **OPEN** (link
that genuinely doesn't close given the available evidence).

**Sources cloned.** All file paths below are relative to:

```
sources/inference-proxy           = nearai/inference-proxy           (HEAD 99ab8ee)
sources/cloud-api                 = nearai/cloud-api                 (HEAD 0ce5177)
sources/cvm-compose-files         = nearai/cvm-compose-files         (HEAD f3a651c)
sources/compose-manager           = nearai/compose-manager           (HEAD 4f87be3)
sources/nearai-cloud-verifier     = nearai/nearai-cloud-verifier     (HEAD ec30401)
~/projects/dstack/dstack          = Dstack-TEE/dstack                (HEAD recent)
                                    NEAR pins commit 7bf1843a8ddf via
                                    private-ml-sdk submodule
```

**Live observations** captured 2026-05-02/03 from the running
production:

```
GLM-5.1-FP8 model CVM attestation:
  app_id        = 0x2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b
  compose_hash  = 0x700adbf53ad4a14e58d2eae65776d451b914b1f5d377c20c7a4e6cca681446ec
  os_image_hash = 0x9b69bb1698bacbb6985409a2c272bcb892e09cdcea63d5399c6768b67d3ff677
  info.key_provider_info.id (P-256 SPKI):
    3059301306072a8648ce3d020106082a8648ce3d030107034200
    04228f800590a10442cba9d0e6adb2fa9f195eea9e75e23dd35990d52b59dda
    2415a63674c38adebde4ffd4d4b265bf818985933820c8053cee3ce29b5fb0fbcbc

KMS at https://kms.cvm1.near.ai:9201/prpc/KMS.GetMeta:
  bootstrap_info.ca_pubkey   = same 91B SPKI as info.key_provider_info.id ✓
  bootstrap_info.k256_pubkey = 022829d063e6a13dd83f5c8896d0cc680e5a1d32221bda219982dcfe47be3fde6e
  bootstrap_info.quote       = 5006B TDX quote (Intel signed)
  bootstrap_info.eventlog    = 6417B JSON
  is_dev=false, allow_any_upgrade=false
  kms_contract_address = 0x8fa1593fac104C1AA0C59EAa3553f7E3E162d637
  gateway_app_id       = 0x90ba8bc1e9a0bee94ff5651d1f437146d0c1a60a
  app_auth_implementation = 0x7E5192c0aA36E35E003351bfFb8ebb213e7e1BA9

KMS bootstrap quote internals (parsed at offset 48 of the quote bytes):
  MRTD   = f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c93826980
           90d7a4a13e14c536ec6c9c3c8fa87077
  RTMR3  = 01bcf892de13356244dcf00f9295d3efe9a4927c1b40bbeb173553c9900f1ea3
           c5390a39cee18bfbb3a0e72c317b4439
  report_data[0:32] = 30dd5d40583a4cdbf151238925fd1fbca449528a757423a5534a1dab9f1d6429
  report_data[32:64] = 0..0  (no client nonce; bootstrap is one-shot)
  bootstrap eventlog: app-id 0x31350b58…3467cca, key-provider {"name":"local-sgx","id":"1b7a4937…"}

Live RA-TLS quote (port 9205 Worker.Info, OID 1.3.6.1.4.1.62397.1.1):
  MRTD/RTMRs IDENTICAL to bootstrap quote
  → the running KMS is the original genesis instance, not an upgrade

NEAR's KMS contract on Base (chain 8453) at 0x8fa1593f…:
  owner()             = 0x21e6b7eF11185eaa57c56Ea9c74E48aAc6e8AB8d  (EOA)
  kmsInfo()           = (k256: 0B, ca: 0B, quote: 0B, eventlog: 0B)  ← all empty
  registeredApps[GLM/cloud-api/etc.] = true ✓
  allowedOsImages[da9a3d5c…]         = true ✓ (note: gateway/cloud-api OS, not model OS)
  allowedOsImages[9b69bb16…]         = true ✓ (model OS)
  kmsAllowedAggregatedMrs has 5 entries, registered 2025-10-20/21:
    d92b6cbf40475ce6f36e60e0d98a0198a2ce3ca2a225ae068b9fa0aa8ad17ce7  2025-10-20T21:41:03Z
    49ec3123180d875cbd3eec529707b6f5c436d2735ffc9d30adca173b3c8180ae  2025-10-21T00:49:01Z
    cac4b9ada6a855707cf4b91ca1600c272a28b8201a86797422c5e104271d15ed  2025-10-21T01:00:45Z
    21bfc0dcb1ddcaa4ff1319b14738e055a1a0429eda6fb44ef75dbf27b6ae7280  2025-10-21T01:33:45Z (×2)
    2c410b158f594537a292dd8d08ea9f9dd2e4eff22d432ac78e32595eaadf0a35  2025-10-21T01:41:57Z
  kmsAllowedDeviceIds has 2 entries:
    13c1a5dd95b7240433aefc3a955190c811a411044f4997b036bbc800d8b516d3  2025-10-20T21:43:13Z
    388d26036ff4e67fa9e50d05ed4f24ac742b13767e3103c235f48fc74126d9e9  2025-10-21T00:49:25Z
  Live KMS instance's mr_aggregated (5-field):  0xf8b4f08f…322c389f
  Live KMS instance's mr_aggregated (8-field):  0xb448c8d8…b7d387c9
  → Neither is in kmsAllowedAggregatedMrs.
```

---

## The chain, link by link

### Link 1 — User encrypts to X25519 recipient pubkey

**Implementation** — `inference-proxy/src/encryption.rs::nacl::ed25519_public_to_x25519` line 193:

```rust
pub fn ed25519_public_to_x25519(ed25519_pub: &[u8; 32]) -> Result<[u8; 32], String> {
    use ed25519_dalek::VerifyingKey;
    let vk = VerifyingKey::from_bytes(ed25519_pub)
        .map_err(|e| format!("Invalid Ed25519 public key: {e}"))?;
    Ok(vk.to_montgomery().to_bytes())
}
```

The X25519 recipient pubkey is a **deterministic public function** of
the Ed25519 `signing_public_key` returned in the attestation report.
No hidden parameter; the conversion is the standard Edwards-to-Montgomery
birational map.

**Verdict:** VERIFIED. Pure function; nothing to attack here.

### Link 2 — Ed25519 signing key is dstack-derived from the running CVM's app key

**Implementation** — `inference-proxy/src/signing.rs::SigningPair::init` line 136:

```rust
pub async fn init(model_name: &str, dev_mode: bool) -> Result<Self> {
    if dev_mode {
        // random keys (DEV)
        return Ok(...);
    }
    let client = dstack_sdk::dstack_client::DstackClient::new(None);
    let ed25519_path = format!("{model_name}/ed25519-signing-key");
    let ed25519_resp = client
        .get_key(Some(ed25519_path), Some("signing".to_string()))
        .await?;
    let ed25519_key_bytes = ed25519_resp.decode_key()?;
    let ed25519 = Ed25519Context::from_key_bytes(...)?;
    ...
}
```

**Live observation:** The model CVM's outer compose (measured in
RTMR3, hash on chain at
`DstackApp(0x2c0a0c96…).allowedComposeHashes(0x700adbf5…)` = `true`)
contains compose-manager. The *inner* compose deployed by
compose-manager — `GLM-5.1.yaml` at commit
`584ee87484abae8d5fbe05099a8db12be9100a4e` of `cvm-compose-files`,
sha256 `bdc4593…` matching the action log — does NOT set `DEV` in
the proxy-glm51 service environment, and `DEV` is also not in the
outer `allowed_envs`.

So `SigningPair::init` takes the production branch unconditionally.
The 32 bytes coming back from `dstack-sdk::get_key` are reinterpreted
as an Ed25519 seed; the derived Ed25519 keypair is what
`signing_public_key` reports.

**Verdict:** VERIFIED-BY-AUDIT. The "production branch unconditional"
property depends on (a) the outer compose hash being on-chain (it is),
(b) the action log committing to the inner YAML hash (it does), and
(c) the YAML at that commit having no `DEV` env (it doesn't). All
three are checkable.

### Link 3 — The 32-byte seed comes from dstack-guest-agent inside the same TD

**Implementation** — `dstack/guest-agent/src/rpc_service.rs::get_key` line 183:

```rust
async fn get_key(self, request: GetKeyArgs) -> Result<GetKeyResponse> {
    let k256_app_key = &self.state.inner.keys.k256_key;
    let derived_k256_key = derive_ecdsa_key(k256_app_key, &[request.path.as_bytes()], 32)?;
    let derived_k256_key = SigningKey::from_slice(&derived_k256_key)?;
    let derived_k256_pubkey = derived_k256_key.verifying_key();
    let msg_to_sign = format!(
        "{}:{}",
        request.purpose,
        hex::encode(derived_k256_pubkey.to_sec1_bytes())
    );
    let app_signing_key = SigningKey::from_slice(k256_app_key)?;
    let digest = Keccak256::new_with_prefix(msg_to_sign);
    let (signature, recid) = app_signing_key.sign_digest_recoverable(digest)?;
    ...
    Ok(GetKeyResponse {
        key: derived_k256_key.to_bytes().to_vec(),
        signature_chain: vec![signature, self.state.inner.keys.k256_signature.clone()],
    })
}
```

The path `"{model_name}/ed25519-signing-key"` is supplied by the
inference-proxy. The guest-agent derives 32 bytes from
`(app_k256_key, path)` via HKDF-style `derive_ecdsa_key`. The 32-byte
return is then *reinterpreted* by inference-proxy as an Ed25519 seed —
the same seed value, two different curve interpretations.

**Note:** `signature_chain` is computed but **not returned** to the
verifying client by `inference-proxy/src/routes/attestation.rs`. The
chain (app_k256 signs derived k256 pubkey under purpose; KMS root
signed app_k256 at boot) exists inside the TD but never reaches a
public endpoint. So the verifier cannot directly verify Link 3 —
it has to *trust the running compose* to faithfully call get_key.

**Verdict:** VERIFIED-BY-AUDIT only. The derivation is deterministic
and gated by source code that's measured into RTMR3. No
cryptographic chain reaches the verifier from get_key directly. If
the compose-hash check (Link 2) passes, this link is implied; if
not, this link can't independently rescue it.

### Link 4 — app_k256_key was provisioned by KMS at CVM boot, gated by on-chain compose-hash

**Implementation** — `dstack/kms/src/main_service.rs::get_app_key` line 500:

```rust
async fn get_app_key(self, request: GetAppKeyRequest) -> Result<AppKeyResponse> {
    ...
    let app_id = boot_info.app_id;
    let context_data = vec![&app_id[..], &instance_id[..], b"app-disk-crypt-key"];
    ...
    let (k256_app_key, signature) = derive_k256_key(&self.state.k256_key, &app_id)?;
    ...
}
```

KMS receives a `BootInfo` from the booting CVM, calls
`AuthApi::is_app_allowed` (which posts to the auth-eth webhook), the
webhook calls `DstackKms.isAppAllowed(bootInfo)` on chain. Per
`kms/auth-eth/contracts/DstackKms.sol::isAppAllowed` line 238:

```solidity
function isAppAllowed(IAppAuth.AppBootInfo calldata bootInfo) external view returns (...)
{
    if (!registeredApps[bootInfo.appId]) {
        return BootResponse({...is_allowed: false, reason: "App not registered"...});
    }
    if (!allowedOsImages[bootInfo.osImageHash]) {
        return BootResponse({...reason: "OS image hash not allowed"...});
    }
    return DstackApp(bootInfo.appId).isAppAllowed(bootInfo);  // delegates
}
```

`DstackApp.isAppAllowed` then checks
`allowedComposeHashes[bootInfo.composeHash]` and (if `!allowAnyDevice`)
`allowedDeviceIds[bootInfo.deviceId]`.

**Live observations:**
- `registeredApps[0x2c0a0c96cb…]` = `true` ✓
- `allowedOsImages[0x9b69bb16…]` = `true` ✓
- `DstackApp(0x2c0a0c96…).allowedComposeHashes(0x700adbf5…)` = `true` ✓
- `allowAnyDevice` = `true` on the model app (so device_id check skipped)

**Verdict:** VERIFIED. The KMS only handed app_k256 to a CVM whose
compose-hash, app_id, and os_image_hash are all on-chain authorized.
This is the strong link in the whole chain.

### Link 5 — KMS root k256 was generated inside a TD at bootstrap

**Implementation** — `dstack/kms/src/onboard_service.rs::Keys::generate` line 114:

```rust
async fn generate(domain: &str, quote_enabled: bool) -> Result<Self> {
    let tmp_ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let rpc_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let k256_key = SigningKey::random(&mut rand::rngs::OsRng);
    Self::from_keys(tmp_ca_key, ca_key, rpc_key, k256_key, domain, quote_enabled).await
}
```

Then in `bootstrap` (line 53):

```rust
async fn bootstrap(self, request: BootstrapRequest) -> Result<BootstrapResponse> {
    let quote_enabled = self.state.config.onboard.quote_enabled;
    let keys = Keys::generate(&request.domain, quote_enabled).await?;
    let k256_pubkey = keys.k256_key.verifying_key().to_sec1_bytes().to_vec();
    let ca_pubkey = keys.ca_key.public_key_der();
    let (quote, eventlog) = if quote_enabled {
        quote_keys(&ca_pubkey, &k256_pubkey).await?
    } else {
        (vec![], vec![])
    };
    let response = BootstrapResponse { ca_pubkey, k256_pubkey, quote, eventlog };
    safe_write(cfg.bootstrap_info(), serde_json::to_vec(&response)?)?;
    keys.store(cfg)?;
    Ok(response)
}
```

`quote_keys` (line 312) computes the report-data binding:

```rust
async fn quote_keys(p256_pubkey: &[u8], k256_pubkey: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let p256_hex = hex::encode(p256_pubkey);
    let k256_hex = hex::encode(k256_pubkey);
    let content_to_quote = format!("dstack-kms-genereted-keys-v1:{p256_hex};{k256_hex};");
    let hash = keccak256(content_to_quote.as_bytes());
    let report_data = pad64(hash);
    let res = app_quote(report_data).await?;
    Ok((res.quote, res.event_log.into()))
}
```

**Live verification of the binding:** the bootstrap quote returned by
`KMS.GetMeta` has

```
report_data[0:32] = 30dd5d40583a4cdbf151238925fd1fbca449528a757423a5534a1dab9f1d6429
keccak256("dstack-kms-genereted-keys-v1:" + ca_hex + ";" + k256_hex + ";")
                  = 30dd5d40583a4cdbf151238925fd1fbca449528a757423a5534a1dab9f1d6429
                  → MATCH (verified in this report)
```

The bootstrap quote is Intel-signed (TDX QE chain). The eventlog
shows `key-provider = {"name":"local-sgx","id":"1b7a4937…"}`,
indicating the KMS instance was booted with local-sgx as its sealing
root rather than another KMS — consistent with this being the genesis
KMS instance.

`SigningKey::random(&mut OsRng)` inside the TD draws from the
TDX-protected RNG. There is no import path on the bootstrap branch
(only `Keys::onboard` imports keys, and that requires RA-TLS to an
already-attested KMS, which doesn't exist at genesis time).

**Verdict:** VERIFIED. The k256 root pubkey is bound to a TDX TD
whose attestation we have, signed by Intel. The corresponding
private key was generated inside that TD with no import path. Anyone
who wants to dispute this would have to forge an Intel TDX
attestation, which is the reduction the whole TEE story rests on.

### Link 6 — The same TD is still running

**Implementation** — `dstack/guest-agent` exposes a fresh-quote
endpoint indirectly through RA-TLS: every TLS connection to the
guest-agent's `Worker.Info` returns an `app_cert` whose X.509
extension `1.3.6.1.4.1.62397.1.1` carries a freshly generated TDX
quote of the running CVM, with `report_data` binding the cert's
public key.

**Live observation:** Pulling the `app_cert` from
`http://kms.cvm1.near.ai:9205/prpc/Worker.Info` and parsing the
quote in the OID extension yields measurements **identical** to
those in `bootstrap_info.quote`:

```
MRTD   (live)     = f06dfda6…fa87077    same as MRTD (bootstrap)
RTMR0  (live)     = c80cb986…e5e33d3e   same
RTMR1  (live)     = a7b52327…0d26c15    same
RTMR2  (live)     = 24847f5c…c9769bbe   same
RTMR3  (live)     = 01bcf892…317b4439   same
```

The running TD is the same TD that produced the bootstrap quote
(identical measurements). It still holds the same root k256 key
(corollary; the same code that generated the key still runs).

**Verdict:** VERIFIED. The RA-TLS extension gives an offline-verifiable
TDX quote of the running instance; matching measurements close the
"is it still the same instance" question.

### Link 7 — Replica onboarding gates handover of the root key

**Implementation** — `dstack/kms/src/main_service.rs::get_kms_key` (the RPC any
replica calls during `Keys::onboard`):

```rust
async fn get_kms_key(self, request: GetKmsKeyRequest) -> Result<KmsKeyResponse> {
    if self.state.config.onboard.quote_enabled {
        let _info = self.ensure_kms_allowed(&request.vm_config).await?;
    }
    Ok(KmsKeyResponse { temp_ca_key, keys: vec![KmsKeys { ca_key, k256_key }] })
}
```

`ensure_kms_allowed` chains into `is_app_allowed(boot_info, is_kms=true)` →
auth-eth webhook → contract `isKmsAllowed` (DstackKms.sol line 208):

```solidity
function isKmsAllowed(IAppAuth.AppBootInfo calldata bootInfo) external view returns (...)
{
    if (!kmsAllowedAggregatedMrs[bootInfo.mrAggregated]) {
        return BootResponse({...reason: "KMS aggregated MR not allowed"...});
    }
    if (!kmsAllowedDeviceIds[bootInfo.deviceId]) {
        return BootResponse({...reason: "KMS device ID not allowed"...});
    }
    return BootResponse({is_allowed: true, ...});
}
```

**Live test:** A direct unauthenticated call to
`https://kms.cvm1.near.ai:9201/prpc/KMS.GetKmsKey` with no client
RA-TLS cert returned `400 "No attestation provided"`. So
`quote_enabled=true` is in effect on this deployment — the gate is
active.

**Verdict:** VERIFIED. The KMS will only hand the root k256 key over
to a caller whose TDX measurement is in `kmsAllowedAggregatedMrs`
AND whose host device_id is in `kmsAllowedDeviceIds`.

### Link 5b — The compose running inside the KMS TD is auditable

`Worker.Info` on port 9205 returns `tcb_info` containing the literal
`app-compose.json` bytes that, when SHA-256'd, yield the on-chain
`compose_hash`. We confirmed:

```
sha256(app_compose) = 31350b58f63e9d3c07e800e250414f4353467cca30a09df2356f0716cfc70d9a
                   == observed compose_hash ✓
```

So we can audit the literal compose. Highlights of NEAR's running
KMS app-compose:

```yaml
manifest_version: 2
name:             dstack-kms
runner:           docker-compose
kms_enabled:      false        # the KMS itself doesn't have a parent KMS
key_provider:     None          # bootstrapped via local-sgx (per eventlog)
public_logs:      true
public_sysinfo:   true
allowed_envs:     []            # ← NO operator-mutable env vars

services:
  auth-api:
    build inline from Dockerfile:
      FROM node:18-alpine@sha256:06f7bbbc…
      RUN git clone https://github.com/Dstack-TEE/dstack.git && cd dstack && git checkout
      cd kms/auth-eth && npm install && npx tsc && CMD node dist/src/main.js
    environment:
      - ETH_RPC_URL=https://rpc.ankr.com/base/<api-key>
      - KMS_CONTRACT_ADDR=0x8fa1593fac104C1AA0C59EAa3553f7E3E162d637

  kms:
    image: dstacktee/dstack-kms@sha256:56dfd86424a3473dc75a11876687aa62ceee03e031e02a9ab1aad494dcabd19c
    config (kms.toml):
      core.image.verify    = true
      core.image.download_url = "https://dstack-images.phala.network/mr_{OS_IMAGE_HASH}.tar.gz"
      onboard.quote_enabled = ?  (file truncated in our extract; see KMS source for default)
      core.admin_token_hash = 9a60539301f556737c2959fa036bbf30f50d6b05539c1db94d8748687b5cca71
```

Three concrete audit observations:

1. **`allowed_envs: []`** — empty. There is no operator-mutable env
   var on the KMS CVM. Every parameter (`KMS_CONTRACT_ADDR`,
   `ETH_RPC_URL`, image digests) is hardcoded into the measured
   compose. Operator can't switch the KMS to point at a different
   contract or RPC without changing `compose_hash`, which is on-chain
   anchored only via this very `app-compose.json` (it is not in
   `DstackKms.kmsAllowedAggregatedMrs` — see Link 8 — but it is the
   self-attested compose of the running instance).

2. **The `kms` service image** is
   `dstacktee/dstack-kms@sha256:56dfd86424a3473dc75a11876687aa62ceee03e031e02a9ab1aad494dcabd19c`
   — a Phala-published image (`dstacktee/*` is Phala's Docker Hub
   namespace). To complete Link 5's source audit, this image must be
   shown to be a reproducible build of `Dstack-TEE/dstack/kms` at
   some commit, with `Keys::generate` using `OsRng` and `Keys::onboard`
   gated by `quote_enabled=true`. The dstack source at the pinned
   commit (`7bf1843a`) does both. Whether the build maps to this
   exact image digest is the open audit step.

3. **The `auth-api` service is built inline** from a Dockerfile that
   does `git clone https://github.com/Dstack-TEE/dstack.git && cd dstack && git checkout`.
   The trailing `git checkout` has *no commit argument* — so the
   build pins to whatever `main` was at the time the image was first
   built (and once the image is built, the resulting layer SHA is
   fixed by the docker build cache, but the compose says
   `build: { context: ., dockerfile_inline: ... }`, meaning every
   rebuild would re-clone). Since the `app-compose.json` is what's
   measured, and it contains the literal Dockerfile text rather than
   a built image digest, the actual auth-api binary running in the TD
   is determined by whatever `main` was at the moment the CVM
   bootstrapped. We can recover that by timestamp (CVM bootstrap is
   from October 2025 per the on-chain registration window) and pin
   it post-hoc, but it's not directly pinned in the compose.

   **This is a concrete soft finding:** the auth-api code path
   (which decides whether to forward `isAppAllowed` calls to the
   contract or to spoof responses) is not deterministically pinned
   to a known commit by the compose. It is, however, fully
   determined by the running TD's MRTD/RTMRs (any tampering would
   change the measurement). For external verification: anyone who
   rebuilds the auth-api against the running CVM's measurement has
   to pick a candidate commit and check.

### Link 8 — What the 5 measurements in `kmsAllowedAggregatedMrs` actually correspond to (the residual gap)

The chain's last cryptographic anchor is the EOA owner who chooses
which TDX measurements may onboard as KMS replicas. Five entries are
authorized today:

```
d92b6cbf…8ad17ce7   added 2025-10-20T21:41:03Z   tx 0xbfb9a902…
49ec3123…3c8180ae   added 2025-10-21T00:49:01Z   tx 0x40f652c7…
cac4b9ad…271d15ed   added 2025-10-21T01:00:45Z   tx 0x3cfeae15…
21bfc0dc…b6ae7280   added 2025-10-21T01:33:45Z   tx 0x8ccfa25f…  (re-added 01:41:17)
2c410b15…aadf0a35   added 2025-10-21T01:41:57Z   tx 0x5f68cf49…
```

All five were registered in a 4-hour window in October 2025 — a
deploy-time bulk registration, not a sequence of upgrade events.

**The OPEN question:** Does each entry correspond to source code
that, when reproducibly built, produces a TDX measurement equal to
that entry, AND does that source code preserve the in-TD root key
property? The dstack-KMS reference implementation does (Link 5 above),
but the deployer can register *any* 32-byte value.

To audit:

- Reproduce the dstack-KMS image at the pinned `Dstack-TEE/dstack`
  commit `7bf1843a` (which `nearai/private-ml-sdk` references via
  submodule). Compute its TDX `mr_aggregated` via the dstack-mr tool.
- For each registered measurement, confirm there exists a
  reproducibly-buildable dstack-KMS image at a known commit whose
  TDX measurement equals it.
- Confirm that commit's `Keys::onboard` requires `quote_enabled=true`
  RA-TLS gating (Link 5/7's properties carry over).

If any of the 5 entries does not correspond to a known dstack-KMS
build with the in-TD-key property, an attacker who controls the EOA
can stand up a backdoored KMS instance at that measurement, have it
call `Keys::onboard` against the genesis instance to receive the
canonical k256 root, and decrypt every E2EE prompt off-chain.

The genesis instance's own measurement is **not** in the allowlist —
correctly, because bootstrap doesn't go through `isKmsAllowed`. So
the 5 entries are exclusively for replicas; whether any have actually
onboarded since deploy is observable only through traffic to the
genesis KMS endpoint, which we don't have visibility into.

**Verdict:** OPEN. To close: reproducibly build dstack-KMS at one
or more candidate commits and match against each of the 5
on-chain entries. This is the audit work; we have all the source
needed for it.

**An additional observation that further constrains this:** the
running KMS `Worker.Info` reports `mr_aggregated`
=`b448c8d8125b9fb5e133d390862d7278bb6e2f8aa25c79dce30b033bb7d387c9`,
which independently confirms our hand-computation from the bootstrap
quote and confirms the genesis instance's measurement is reliably
not in the on-chain allowlist. None of the 5 entries
(`d92b6cbf…`, `49ec3123…`, `cac4b9ad…`, `21bfc0dc…`, `2c410b15…`)
matches `b448c8d8…`.

**The running image is fully pinned:**

```
docker image:  dstacktee/dstack-kms@sha256:56dfd86424…dcabd19c
image tag:     0.5.4 (created 2025-09-24)
binary embeds: "0.5.4git:b6baa526c4524ec3dc60"
   (extracted via `strings /tmp/dstack-kms-bin`)
source commit: b6baa526c4524ec3dc604a927cb2aea0404bc258
   (Wed Sep 3 09:22:52 2025 — Merge PR #320 "ra-tls: Add KeyCertSign…")
release tag:   kms-v0.5.4 (verified contains b6baa526)
```

The mr_aggregated formula at commit `b6baa526` is byte-identical to
upstream main:

```rust
sha256(mrtd, rtmr0, rtmr1, rtmr2, rtmr3
       [+ mr_config_id, mr_owner, mr_owner_config if any non-zero])
```

So the running instance is reproducibly identifiable. The image is
public on Docker Hub, the source is public on
`Dstack-TEE/dstack`, the version string is embedded in the binary.

**The 5 on-chain entries' timing pattern strongly suggests v0.5.5+
upgrade pre-authorization:**

```
v0.5.4 image released  : 2025-09-24
v0.5.4 commit b6baa526  : 2025-09-03

5 mr_aggregated registrations  : 2025-10-20 21:41 → 2025-10-21 01:41
v0.5.5 image released          : 2025-10-21 00:14
v0.5.5 image first appears     : same day as the registrations
```

Five distinct measurements registered across a 4-hour window the day
v0.5.5 dropped. The shape is consistent with NEAR pre-authorizing
five candidate measurements for v0.5.5 (e.g., variants for different
host configurations or dev/prod images), in case they upgrade. The
running KMS is still v0.5.4 (confirmed by binary version string), so
those forward-looking authorizations have not been activated.

To match each of the 5 entries to a specific dstack-kms build, the
audit step is bounded — and most of it is already done from public
artifacts:

```
dstack-kms image → embedded version string (extracted via `strings` on the binary):

  v0.5.4  image sha256:56dfd86…dcabd19c  →  "0.5.4git:b6baa526c4524ec3dc60"  ← RUNNING
  v0.5.5  image sha256:11ac59f…fab7a62a  →  "0.5.5git:7bf1843a8ddf877fbaeb"
  v0.5.6  image sha256:6f8ae87…71bf4c849  →  "0.5.6git:3a456dd6e332509f97e7"
  v0.5.8  image sha256:9650dcb…817e61a26d  →  "0.5.8git:3cb68c89c57c7e659fcf"
  v0.5.9  image sha256:e959bc5…998e2d871c  →  "0.5.9git:282eeb27d22d8f091ad0"

dstack OS image → metadata.json from dstack-images.phala.network/metadata/<hash>/:

  da9a3d5c…3053fde   v0.5.4  git f7c795b76faa693f218e1c255007e3a68c541d79
                     (used by cloud-api, chat-api, dstack-ingress)
  9b69bb16…3ff677    v0.5.5  git 25c25025c556ab2f797eeda3bab433f38a8ffb7a
                     (used by GLM-5.1 / DeepSeek model CVMs)
```

So for each published `dstacktee/dstack-kms` tag, we have:

- the exact `Dstack-TEE/dstack` commit it was built from (in the binary)
- public source (auditable)
- public Docker image (pullable, reproducible-as-binary)

For each NEAR-deployed dstack OS image hash, we have:

- the exact `Dstack-TEE/dstack` commit it was built from (in metadata.json)
- public Yocto/`meta-dstack` source (auditable)
- public OS image tarball (pullable)

The remaining computation — "what `mr_aggregated` does
(dstack-kms@0.5.5 + dstack-OS-v0.5.5) produce when run as a CVM?" —
is what `dstack-mr` (in the dstack repo at `dstack-mr/cli`) is for.
It takes a kernel + initrd + cmdline + compose and emits expected
MRs without actually booting a TD. Running it across the candidate
combinations and checking against each of the 5 on-chain entries
closes Link 8.

That step doesn't require reproducible builds — every artifact is
already public and pinned to a specific commit. It's the
"computation across known artifacts" leg of the audit, not the
"build everything from source" leg.

### Link 9 — The EOA owner's authority

The KMS contract owner is `0x21e6b7eF11185eaa57c56Ea9c74E48aAc6e8AB8d`,
an externally-owned account (no code on Base). Same EOA owns the six
DstackApp contracts gating the gateway/chat/cloud/postgres/vpc
proxies and the model CVM. There is no on-chain timelock, no
multisig wrapper.

The EOA can:
- Add a new measurement to `kmsAllowedAggregatedMrs` (instantaneous,
  emits `KmsAggregatedMrAdded` — auditable on-chain after the fact).
- Add a new compose hash to any DstackApp's `allowedComposeHashes`
  (emits `ComposeHashAdded`).
- Upgrade the DstackApp UUPS implementation (`_upgradesDisabled = false`
  on every contract).
- Upgrade the KMS contract's UUPS implementation.

Detection of all of these is retroactive via on-chain event logs.
There is no real-time "freeze" mechanism that prevents an
EOA-key-holder from inserting a backdoored KMS measurement.

**Verdict:** OPEN, but bounded. The on-chain event log is the
audit trail; whether the EOA key is well-protected is operational.

---

## Synthesis

The chain from "user's E2EE plaintext" to "TDX-protected KMS root"
closes at every link **except**:

1. **Link 8** (much narrower than I'd thought). The 5 on-chain
   `kmsAllowedAggregatedMrs` entries appear to be forward-looking
   authorizations for v0.5.5+ KMS upgrades, registered on 2025-10-21
   (same day as v0.5.5 release). The running KMS is still v0.5.4 at
   commit `b6baa526` — its measurement is correctly *not* in the
   allowlist (genesis instances don't go through `isKmsAllowed`).
   Matching each of the 5 forward-looking entries to a specific
   reproducible dstack-kms build is bounded audit work — start with
   `kms-v0.5.5` of `Dstack-TEE/dstack` and the GPU/non-GPU OS image
   variants we observe. Anything unmatched is the open finding.

2. **Link 9.** The owner is a 1-of-1 EOA. Its operational security is
   load-bearing for prevention of "EOA adds a backdoored measurement,
   then a v0.5.5-ish replica is stood up and onboards from v0.5.4 to
   receive the keys." On-chain `KmsAggregatedMrAdded` events are the
   audit trail; the EOA key handling is the operational risk.

Everything else closes — including:

- The KMS root k256 was generated inside a TDX TD via `OsRng`
  (verified at commit `b6baa526`, line `kms/src/onboard_service.rs:118`).
- The bootstrap quote binds `(ca_pubkey, k256_pubkey)` via
  `report_data = keccak256("dstack-kms-genereted-keys-v1:" + p256_hex
  + ";" + k256_hex + ";")` (verified bit-exact against the live
  KMS endpoint).
- The same genesis instance is still running, with the same MRTD,
  same RTMRs (verified by pulling a fresh RA-TLS quote from the
  KMS's port-9205 guest-agent).
- `quote_enabled=true` on the running KMS (verified by `GetKmsKey`
  rejecting an unauthenticated call with "No attestation provided").
- The KMS docker compose has `allowed_envs: []` (no operator-mutable
  env vars), `KMS_CONTRACT_ADDR` hardcoded, OS image download URL
  pointing at Phala's signed-image distribution.
- The dstack-kms binary running in the TD embeds version string
  `0.5.4git:b6baa526c4524ec3dc60`, externally verifiable from the
  Docker Hub image (`dstacktee/dstack-kms@sha256:56dfd86…`).

So the trust chain is real and grounded. Going from earlier "I don't
know what's running" to "v0.5.4 at commit `b6baa526`, image
`sha256:56dfd86…`" took fetching `Worker.Info` from port 9205 and
running `strings` on the binary.

## Notes on what I tried in the wrong direction

A few side-paths the user pulled me back from, captured here so the
audit narrative is clean rather than "I changed my mind 6 times":

- "kmsInfo on chain is empty so the trust chain is broken" — wrong,
  because the same data (k256_pubkey + ca_pubkey + quote + eventlog)
  is available via `KMS.GetMeta` over pRPC on port 9201 and is
  cryptographically self-attesting regardless of where it's served
  from.

- "The on-chain registry must be decorative" — wrong, the
  `GetKmsKey` endpoint actively rejects unauthenticated callers.

- "The off-chain-pinned KMS pubkey is a useful fallback" — also
  wrong; you don't need an off-chain pin when the on-chain KMS
  contract has `kmsAllowedAggregatedMrs` entries that the auth-eth
  webhook actively gates on, AND the bootstrap quote with embedded
  `report_data` binding is publicly fetchable.

- Port 8090 is closed on `kms.cvm1.near.ai`. The equivalent
  metadata view is on port 9205 (`Worker.Info` from
  dstack-guest-agent), which is open and gives us the literal
  app-compose, the `mr_aggregated`, the live RA-TLS quote in
  the `app_cert` X.509 extension, and `tcb_info`.

## What to actually do

For the closure work this audit is producing:

- **Reproduce dstack-KMS** at commit `7bf1843a` (and any earlier
  commits that match the registration window in 2025-10) and compute
  the TDX `mr_aggregated`. Match against each of the 5 on-chain
  entries. Anything that doesn't match a known-good build is the
  open finding.
- **Update the on-chain anchoring verifier** (`feat/on-chain-anchoring`
  on `amiller/nearai-cloud-verifier`): the existing checks for
  `registeredApps`, `allowedComposeHashes`, `allowedOsImages` close
  Links 4 & 7 cleanly, no changes needed there. Replace the current
  `kms_provenance` / `kmsInfo`-based "off-chain pinned pubkey"
  framing with: fetch `KMS.GetMeta` from the deployment's KMS RPC
  endpoint, verify the bootstrap quote (Link 5), verify the live
  RA-TLS quote matches (Link 6), then confirm the live measurement
  is either the bootstrap measurement OR is in the on-chain
  `kmsAllowedAggregatedMrs` (Link 8).
- The verifier doesn't need to consume `kmsInfo` from the contract
  — that field is a *redundant* anchor when the KMS RPC publishes
  the same data. NEAR's `kmsInfo` being empty is not a verifier-side
  problem.

## Source-code verification status

A note on the "is the source code verified?" question, since it has
shifted as the analysis progressed:

- **Source code is auditable.** Every component has a public github
  repo and we audit at specific pinned commits (see appendix below).
  `Dstack-TEE/dstack` at `b6baa526` is what the running KMS *claims*
  to be — that commit is where `Keys::generate` calls
  `SigningKey::random(&mut OsRng)` inside the TD, and where
  `Keys::onboard` requires `quote_enabled=true`.

- **The image-to-source link is established by embedded version
  strings, not by a reproducible build.** `dstacktee/dstack-kms@sha256:56dfd86…`
  contains the literal string `0.5.4git:b6baa526c4524ec3dc60` in its
  binary (extracted via `strings`). A malicious build could embed a
  false version string, so this is correlation, not proof.

- **The cryptographic close for image-to-source is `mr_aggregated`.**
  Run `dstack-mr` against (dstack-kms@b6baa526 + dstack-OS v0.5.4)
  and the result must equal `b448c8d8125b9fb5e133d390862d7278bb6e2f8aa25c79dce30b033bb7d387c9`
  (live `Worker.Info`). Same exercise against each of the 5 on-chain
  `kmsAllowedAggregatedMrs` entries closes Link 8. That work is
  bounded — every artifact is public and pinned (image digests, OS
  metadata commits, source commits) — it just hasn't been run yet.

- **One soft open finding remains in source.** The auth-eth `auth-api`
  service is built from an inline Dockerfile that does
  `git clone Dstack-TEE/dstack && git checkout` with no commit
  argument. The actual code running is therefore "whatever main was
  when the image was first built" rather than a deterministic
  source-pinned commit (see Link 5b observation 3). The TD's RTMRs
  measure the running binary, so any tampering is detectable, but
  the audit reader has to pick a candidate commit by timestamp
  rather than reading the literal compose.

So: source code IS verified at the commit level; the remaining work is
running `dstack-mr` to close the image-to-source binary mapping. The
"complaining about source code not verified" earlier in this session
referred to that final mapping step — which is bounded audit work
across already-public artifacts, not a structural gap.

## Appendix — Reference values index

Consolidated lookup of every binding value cited in the analysis.

### On-chain contracts (Base mainnet, chain 8453)

| Role | Address |
|---|---|
| `DstackKms` (root registry) | `0x8fa1593fac104C1AA0C59EAa3553f7E3E162d637` |
| `DstackApp` UUPS implementation | `0x7E5192c0aA36E35E003351bfFb8ebb213e7e1BA9` |
| Owner EOA (1-of-1) | `0x21e6b7eF11185eaa57c56Ea9c74E48aAc6e8AB8d` |
| Model DstackApp (GLM-5.1 / DeepSeek) | `0x2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b` |
| Gateway DstackApp | `0x90ba8bc1e9a0bee94ff5651d1f437146d0c1a60a` |

The owner EOA additionally controls four other DstackApp proxy
contracts (chat, cloud, postgres, vpc) per Link 9; their addresses
are recoverable from the EOA's `deployAndRegisterApp` transaction
history on Blockscout.

### Docker images (Docker Hub, namespace `dstacktee/`)

| Tag | Image digest | Embedded version string |
|---|---|---|
| `dstack-kms:0.5.4` | `sha256:56dfd86424a3473dc75a11876687aa62ceee03e031e02a9ab1aad494dcabd19c` | `0.5.4git:b6baa526c4524ec3dc60` ← **RUNNING on NEAR's KMS** |
| `dstack-kms:0.5.5` | `sha256:11ac59f…fab7a62a` | `0.5.5git:7bf1843a8ddf877fbaeb` |
| `dstack-kms:0.5.6` | `sha256:6f8ae87…71bf4c849` | `0.5.6git:3a456dd6e332509f97e7` |
| `dstack-kms:0.5.8` | `sha256:9650dcb…817e61a26d` | `0.5.8git:3cb68c89c57c7e659fcf` |
| `dstack-kms:0.5.9` | `sha256:e959bc5…998e2d871c` | `0.5.9git:282eeb27d22d8f091ad0` |

The model-CVM compose runs additional images (compose-manager,
inference-proxy, model serving image, datadog, certbot) anchored
collectively via `compose_hash=0x700adbf5…`, but we did not enumerate
each image's digest individually — they are pinned by the on-chain
compose-hash check (Link 4).

### OS images (Phala signed-image distribution)

URL pattern: `https://dstack-images.phala.network/metadata/<os_image_hash>/`
serves `metadata.json` containing the `Dstack-TEE/dstack` commit and
build inputs.

| OS image hash (mr-style) | Version | dstack source commit | Used by |
|---|---|---|---|
| `da9a3d5c…3053fde` | v0.5.4 | `f7c795b76faa693f218e1c255007e3a68c541d79` | cloud-api, chat-api, dstack-ingress |
| `9b69bb16…3ff677` | v0.5.5 | `25c25025c556ab2f797eeda3bab433f38a8ffb7a` | GLM-5.1 / DeepSeek model CVMs |

### Source code commits we audited at

| Repo | Commit / pin | Role |
|---|---|---|
| `Dstack-TEE/dstack` | `b6baa526c4524ec3dc604a927cb2aea0404bc258` | running KMS source (binary embeds this) |
| `Dstack-TEE/dstack` | `7bf1843a8ddf877fbaeb…` | NEAR's `private-ml-sdk` git-submodule pin (= v0.5.5) |
| `nearai/inference-proxy` | `99ab8ee` | E2EE encrypt + Ed25519→X25519 + signing-key derivation |
| `nearai/cloud-api` | `0ce5177` | gateway / attestation-report endpoint |
| `nearai/cvm-compose-files` | `f3a651c` | inner per-model YAMLs (GLM-5.1, DeepSeek, etc.) |
| `nearai/compose-manager` | `4f87be3` | runtime compose deployer |
| `nearai/nearai-cloud-verifier` | `ec30401` | reference verifier client |

### Live RPC endpoints (NEAR's KMS deployment)

| URL | Purpose |
|---|---|
| `https://kms.cvm1.near.ai:9201/prpc/KMS.GetMeta` | bootstrap_info (k256/ca pubkey + bootstrap quote + eventlog) |
| `https://kms.cvm1.near.ai:9201/prpc/KMS.GetKmsKey` | replica onboarding gate (returns "No attestation provided" on unauth) |
| `http://kms.cvm1.near.ai:9205/prpc/Worker.Info` | live RA-TLS quote in `app_cert` ext, `mr_aggregated`, literal `app-compose.json` |
| `https://cloud-api.near.ai/v1/attestation/report` | per-request gateway + model attestation (Phala-style bundle) |

### External verifiers

| URL | Purpose |
|---|---|
| `https://cloud-api.phala.network/api/v1/attestations/verify` | Intel TDX quote verification (used by `nearai-cloud-verifier`) |
| `https://nras.attestation.nvidia.com/v3/attest/gpu` | NVIDIA NRAS GPU attestation |
| `https://base.blockscout.com/address/0x8fa1593f…` | DstackKms contract event log + tx history |
