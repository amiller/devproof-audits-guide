# Deployment History

Deployment log for [App Name]. Each entry represents a verified deployment to Phala Cloud.

## Requirements for This Log

1. **Use Base KMS** - On-chain transparency logging
2. **Record every deployment** - Before marking complete
3. **Link to on-chain TX** - Proof that deployment was logged

---

## Active Deployments

| Timestamp | Version | Cluster | Compose Hash | On-Chain TX | Status |
|-----------|---------|---------|--------------|-------------|--------|
| YYYY-MM-DDTHH:MM:SSZ | X.X.X | prod9 | `<hash>` | [View](https://basescan.org/tx/...) | Active |

---

## How to Add an Entry

After running `phala cvms upgrade`:

1. Get compose hash from 8090:
   ```bash
   curl https://<app-id>-8090.<cluster>.phala.network/compose-hash
   ```

2. Get TX hash from phala CLI output or query on-chain

3. Add row to table above

4. **Deployment is NOT complete until this file is updated**

---

## Verification

To verify any deployment:

1. **Check compose hash matches attestation:**
   ```bash
   curl https://<app-id>-8090.<cluster>.phala.network/compose-hash
   ```

2. **Verify on-chain record:**
   - Click TX link → view on BaseScan
   - Logged hash should match compose hash

3. **Compare to source:**
   ```bash
   git checkout <commit>
   sha256sum docker-compose.yml
   ```

---

## On-Chain Contracts

| Cluster | Contract Address |
|---------|------------------|
| prod9 | [`0x...`](https://basescan.org/address/0x...) |

---

## Why This Matters

Without this log, users cannot answer: "What version was running on [date]?"

With Pha KMS: Trust Center shows current state only. No history.

With Base KMS + this log: Full audit trail. Every upgrade recorded on-chain.
