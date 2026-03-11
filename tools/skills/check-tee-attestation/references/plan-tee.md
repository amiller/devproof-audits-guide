# TEE / DevProof 审计最佳方案（综合 hermes + is-this-real-tea + devproof-audits-guide）

本方案面向第三方审计：验证 TEE 应用是否真的让开发者或运营方“不能作恶”，而不仅是“跑在 TEE 里”。核心目标是证明 operator gap 是否被关闭：运营方是否还能通过配置、升级或后门悄悄窃取用户数据。

---

## 一、目标与原则

- 目标：给出可验证、可复现的结论，回答“运营方能否偷数据、偷密钥、无通知升级”。
- 原则：
- 只信硬证据链：源码 -> 构建产物 -> 部署配置 -> 硬件证明。
- 不信自述：应用自带 /attestation 仅作参考，关键证据必须来自 8090、Trust Center 或链上。
- 以 operator gap 为中心：能否通过 allowed_envs、变量镜像、配置 URL 实现数据外流。
- 审计当前 + 可追溯历史：不仅验证“现在安全”，还要能回答“过去是否安全”。

---

## 二、输入与证据清单

- 必需：
- GitHub URL 或本地源码路径
- 部署 URL（或 app_id + cluster）
- 可选但强烈建议：
- 8090 端点快照：https://{app_id}-8090.{cluster}.phala.network/
- Trust Center 链接：https://trust.phala.com/app/{app_id}
- Cloud API attestation：https://cloud-api.phala.network/api/v1/apps/{app_id}/attestations
- 应用 /attestation 返回（用于 TLS 绑定）
- 证据快照（quote.json、metadata、证书 PEM、sha256sum）

---

## 三、快速分流（5 分钟）

满足以下任何一条，直接判定 Stage 0（可作恶）并进入深度审计：

1. 8090 无 TDX quote（--dev-os）
2. docker_compose_file 中存在 ${VAR} 控制 URL 或镜像
3. 镜像未使用 @sha256: 固定
4. KMS 是 Pha KMS 且无链上 AppAuth 或 Timelock
5. TLS 不是 passthrough（443s），无法做端到端绑定

---

## 四、完整审计流程（推荐 7 阶段）

### Phase 0：威胁模型与范围锁定

- 明确应用的安全承诺（例如“运营方看不到私钥或未发布内容”）
- 明确用户数据路径与保密边界（TEE 内 / TEE 外）
- 明确是否为自托管或平台托管（Phala/dstack）

### Phase 1：独立获取 Attestation 证据

1. 从部署 URL 解析 app_id + cluster
2. 拉取 8090 元数据，解析 app_compose（关键真相来源）
3. 计算 compose_hash（SHA256 of canonical JSON）
4. 拉取 Cloud API 补充 quote / event_log / vm_config
5. 拉取 Trust Center 作为硬件 attestation 旁证

关键输出：
- app_compose（含 docker_compose_file、allowed_envs、kms_enabled、pre_launch_script）
- compose_hash
- quote_hex + RTMR / MR* 相关字段

### Phase 2：硬件证明验证

- 使用 dcap-qvl 验证 TDX quote 签名
- 如无法使用，退化为手动解析 quote（只提取字段，不做签名验证）
- 校验 compose_hash 是否匹配 mr_config_id
- 若有 report_data，验证其绑定内容（例如 TLS cert 指纹）
- 若可用，调用 dstack-verifier 进行 event log replay

### Phase 3：TLS 绑定与域名信任模型

- 判断 URL 是否为 TLS passthrough（443s）
- 若 passthrough：
- 获取实时 TLS 证书指纹
- 对比 /attestation 的 certFingerprint
- 若为自定义域名：
- 获取 _dstack-app-address TXT 记录
- 建议启用 CT 监控（Certspotter / crt.sh）
- 解释信任层级：浏览器依赖 CT 可检测，SDK 应做 attested TLS

### Phase 4：源码审计（operator gap 核心）

必须逐行追踪数据流：

- 配置性 URL：
- 在 docker-compose.yml / app_compose 中搜索 ${VAR}
- 对照 allowed_envs，定位可被运营方替换的 URL
- 若 URL 处理用户数据 -> 高危

- 外部网络调用：
- 查 fetch/axios/requests 等
- 确认每个外部请求携带的用户数据

- attestation 使用是否“强制执行”：
- 是否只是 log 而不中断
- 是否存在 known issue / mismatch ignore

- 密钥与 KMS：
- 是否使用 TEE 内 deriveKey
- 是否存在硬编码 fallback
- 是否允许环境变量注入密钥

- 构建可复现性：
- Dockerfile 是否 pin base digest
- 是否 SOURCE_DATE_EPOCH / rewrite-timestamp
- 锁文件是否完整

- 升级与治理：
- 是否接入 AppAuth / on-chain compose registry
- 是否 timelock
- 是否有 DEPLOYMENTS.md 或 on-chain 记录

### Phase 5：部署配置与源码交叉验证

- 比对 8090 docker_compose_file 与仓库中 compose
- 镜像是否为 digest 固定
- 是否存在 ${IMAGE_VAR} + allowed_envs 盲区
- 从镜像 tag 找出真实部署 commit（不要审计 branch HEAD）

### Phase 6：DevProof 阶段判定（ERC-733）

Stage 0 触发条件（任意即失败）：
- 无 TDX quote
- 允许运营方配置数据通道（URL/endpoint）
- 镜像未固定 digest
- 无链上透明升级

Stage 1 必须全部满足：
- on-chain KMS + AppAuth
- 镜像 digest 固定
- no exfiltration vector
- TLS 绑定验证通过
- 可复现构建
- 升级 timelock

### Phase 7：报告与证据归档

- 报告必须包含：
- Executive Summary
- 关键问题表格（operator gap / attestation / reproducibility / data flow / upgrades）
- Critical Findings（含 file:line 与可复现步骤）
- Trust Boundary 图
- “能保证什么 / 不能保证什么”
- 未能验证的部分（原因）

- 证据快照建议：
- evidences/YYYY-MM-DD/metadata.json
- quote.json, cert.pem, sha256sum.txt, deploy-info.json
- 保存在 git 中以构建历史可追溯性

---

## 五、最佳实践总结（来自三仓库的结论融合）

- operator gap 是 1 号风险：任何可配置 URL 都可能变成数据外流通道。
- 8090 是第三方审计唯一可信来源：应用自身 /attestation 不足。
- 链上透明日志是 DevProof 的核心：Pha KMS 只能证明“现在”，不能证明“过去”。
- 镜像 digest 固定是最小要求：tag 仍可被覆盖。
- 可复现构建决定“源码可审计”是否成立。
- 自定义域名不是漏洞，但需要 CT 监控 + attested TLS。
- 证据应持久化：/evidences 覆写是常见盲区。

---

## 六、可复用检查清单（精简版）

1. 8090 拿到 app_compose + quote
2. compose_hash 匹配 mr_config_id
3. docker_compose_file 中无 ${VAR} 控制 URL 或镜像
4. 镜像使用 @sha256: 固定
5. KMS 为 Base/on-chain，AppAuth + timelock
6. TLS 证书指纹与 attestation 匹配
7. 构建可复现（pin base + SOURCE_DATE_EPOCH + lockfile）
8. 无 dev fallback / known issue bypass
9. 数据流不出 TEE 或出 TEE 前已加密
10. 有升级历史记录（链上或 DEPLOYMENTS.md）

---

## 七、建议输出格式（模板）

审计完最终生成的报告必须是英文版。

### 通俗易懂版（不使用 Stage 术语）

用“一眼判定卡”替代 Stage 结论，强调结论与原因：

一句话结论：运营方能否偷数据（能/不能/部分能）+ 关键原因 1 条。

可视化模板（打勾矩阵 + 红黄绿信号）：

```
一眼判定：能/不能/部分能 + 关键原因

| 关键问题 | 状态 | 信号 | 证据摘要 |
|---|---|---|---|
| 运营方能否偷数据 | PASS / FAIL / PARTIAL | GREEN / RED / YELLOW | 例如：allowed_envs 可改 URL |
| 硬件是否真的在证明 | PASS / FAIL / PARTIAL | GREEN / RED / YELLOW | 例如：TDX quote 已验证 |
| 部署是否可复现 | PASS / FAIL / PARTIAL | GREEN / RED / YELLOW | 例如：镜像 digest 固定 |
| 数据是否离开 TEE | PASS / FAIL / PARTIAL | GREEN / RED / YELLOW | 例如：外部 DB/LLM |
| 升级是否可追溯 | PASS / FAIL / PARTIAL | GREEN / RED / YELLOW | 例如：Base KMS + timelock |

信号说明：GREEN=关键项闭合；YELLOW=部分满足或关键空白；RED=存在可作恶路径
```

```markdown
## Executive Summary

## Key Questions
| Question | Answer | Evidence |

## Critical Issues
- [Issue] (file:line)
- Exploit steps
- Impact
- Fix

## Architecture & Data Flow

## Attestation Analysis

## Build Reproducibility

## Upgrade Transparency

## Trust Boundaries

## What’s Done Well

## Verification Checklist

## Security Guarantees
### What’s protected
### What’s still possible
### What can’t be verified
```

---

## 八、与现有工具的对接建议

- 使用 is-this-real-tea 的 6-phase pipeline 作为自动化基线
- 用 devproof 的 Stage 1 checklist 做最终判定
- 用 hermes 的“证据链闭环”方法：
- 源码 commit -> CI digest -> compose_hash -> TDX quote -> Trust Center
- 将每次部署证据归档到 evidences/

---

## 九、最终结论标准

只有当以下证据链全部闭合，才可宣称“开发者不能作恶”：

1. 代码可审计 + 可复现构建
2. 镜像 digest 固定 + compose_hash 与 quote 匹配
3. on-chain 透明升级 + timelock
4. 无 operator-configurable 数据通道
5. TLS 端到端绑定到 TEE
6. 证据可追溯（历史可审计）

否则默认结论：Stage 0（可作恶）。

