# 通信模块依赖与安全核对（0.2.11）

## 选择与边界

| 依赖 | 版本/用途 | 许可证与兼容性 | 结论 |
|---|---|---|---|
| Tokio | 最低 1.54.1；异步 TCP/UDP、超时 | MIT；Rust 2024 workspace 实测 | 升级消除 AsyncFd 安全公告涉及的旧版本 |
| reqwest | 本地解析 0.13.4；复用已有 HTTP 栈 | MIT/Apache-2.0 | 禁用隐式代理、重定向、重试、解压；受限响应 |
| rustls | 最低 0.23.46；TCP/HTTP TLS | Apache-2.0/ISC/MIT | 显式 aws-lc provider；修复握手与证书相关公告 |
| rumqttc | 0.25.1；MQTT 两版本 | Apache-2.0；声明 MSRV 1.64 | 使用官方 `use-native-tls` feature；不使用其携带旧 webpki 的默认 Rustls 后端 |
| native-tls | 最低 0.2.18；MQTT TLS | MIT/Apache-2.0；MSRV 1.80 | 显式根证书、TLS >=1.2、主机名校验；私钥 PKCS#8 |
| tokio-modbus | 0.17.0；TCP/RTU 帧与事务 | MIT/Apache-2.0；MSRV 1.76 | 公共层增加请求范围/响应回显校验和取消后关闭 |
| tokio-serial | 5.5.0；串口接入 | MIT；upstream 未声明 MSRV | macOS PTY 实测；Linux CI 包含 libudev 开发库 |
| object_store | 0.14.2；原有对象存储 | MIT/Apache-2.0；MSRV 1.85 | 为 quick-xml >=0.41 安全修复升级，并适配其签名后移除 Host 的正式行为 |

本库验证使用 Rust 1.97.0，edition 2024；没有声明“所有依赖的最小 MSRV 已组合验证”。MQTT/Linux 的系统 OpenSSL 仍由部署环境负责安装、更新，cargo-audit 不扫描操作系统动态库。

## 扫描结果与处置

首次完整 Cargo.lock 扫描有 22 条漏洞报告。升级实际依赖中的 anyhow、Tokio、h2、quinn-proto、rustls、rustls-webpki、webpki-roots/root-certs、event-listener、object_store/quick-xml；更新已撤回的 chacha20/spin；移除直接 rustls-pemfile 使用，以 rustls-pki-types PEM API 取代。MQTT 改用官方平台 TLS 后端，依赖树不再包含 rustls-webpki 0.102.8 或 rustls-pemfile。

最终 **原始 `cargo audit` 仍返回非零**，因为 Cargo.lock 包含以下未启用的可选包；不能把原始扫描称为零漏洞或完全通过：

| 包 | 公告 | 当前实际构建范围 |
|---|---|---|
| rkyv 0.7.46 | RUSTSEC-2026-0235 | rust_decimal 可选归档依赖；macOS/Linux all-features Cargo 构建树没有此包 |
| rsa 0.9.10 | RUSTSEC-2023-0071 | SQLx MySQL 可选依赖；本库当前 PostgreSQL 构建树没有此包 |

`proc-macro-error2 2.0.1` 有停止维护提示 RUSTSEC-2026-0173，并产生 future-incompatibility 提示，来自现有宏依赖；这是持续维护风险，未将其描述为已修复。

新增 `scripts/check-protocol-security.py` 不设置公告忽略列表、不改写 Cargo.lock，不忽略新报告。它对完整扫描逐条输出，并以 `cargo tree --workspace --all-features --target ... --edges normal,build,dev` 的实际构建范围判定：任何启用依赖的漏洞、unsound 或 yanked 报告都失败。不可直接使用 cargo metadata 所列的全部 node 判断启用状态，它会包含 SQLx 可选特性解析节点。

本机分别核对 `aarch64-apple-darwin`（351 包）和 `x86_64-unknown-linux-gnu`（356 包）构建树，阻断项均为 0。这是依赖范围检查，**不等于已在 Linux 执行测试**。未来启用 MySQL/rkyv、改 feature 或升级依赖时必须重新运行；脚本会将届时启用的漏洞包判为失败。

在线数据库抓取曾因 GitHub IO 失败；最终本地验证显式使用 `--no-fetch` 和本轮已经成功获取的 RustSec 数据库（提交 `40f5be6fb12ed93fc591bf4ab23b7d793b3f2239`）。CI 默认在线更新数据库，抓取失败即失败，绝不静默使用缓存或忽略结果。

## S3 兼容性

object_store 0.14.2 按 URL authority 签名 Host，签名后移除 header，交由 HTTP 客户端生成。原固定 0.14.0 的适配器因此不能原样升级。现在先验证 URL 与预期目标完全一致，再在传输边界把该 authority（含非默认端口）明确写入 Host，随后仍执行原严格签名形状校验。已有显式 Host 必须精确匹配；冲突 Host、错误摘要/路径、缺失绑定、伪造 KMS/header 均继续拒绝。真实 object_store 请求形状与伪造请求回归测试覆盖此变化；没有允许自动重定向。

## 依据

- [rumqttc 0.25.1 配置与 feature](https://docs.rs/crate/rumqttc/0.25.1/features)
- [native-tls TlsConnectorBuilder](https://docs.rs/native-tls/0.2.18/native_tls/struct.TlsConnectorBuilder.html)
- [object_store 0.14.2](https://docs.rs/object_store/0.14.2/object_store/)
- [RustSec 公告数据库](https://rustsec.org/advisories/)
- [Modbus 官方规格入口](https://www.modbus.org/modbus-specifications)

依赖许可证/MSRV 信息来自本轮 `cargo info`；安全证据来自实际 lockfile、Cargo 构建树、RustSec 扫描与源码调用路径，不能外推为现场设备已验收。
