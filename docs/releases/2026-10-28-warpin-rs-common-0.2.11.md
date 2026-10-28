# warpin-rs-common 0.2.11：公共通信能力

状态：18 个 crate 已统一发布到 crates.io `0.2.11`，发布源码已推送 main；注册表包核验和独立消费者测试完成。不升级业务仓，不包含厂商协议或进出舱业务实现。

发布源码：`de0d097ea1d22d4f03bda8a2a92093d4c59c13f1`。[Linux/macOS CI](https://github.com/time-origin/warpin-rs-common/actions/runs/40678988485) 两项均通过；后续发布记录提交只补充文档，不改变已发布源码。

18 个包均经过正常 `cargo publish --locked` 的打包/构建验证；逐包下载 crates.io 归档，验证注册表 SHA-256、包版本、内部依赖版本、未撤回状态和 `.cargo_vcs_info.json` 源码提交。详见[机器可读发布证据](2026-10-28-warpin-rs-common-0.2.11-evidence.json)。首次读取注册表时遇到 HTTP 500，有限重试后全部核验成功，没有重新发布。

## 使用入口

- `warpin-http::transport`：HTTP 方法、认证、有界 bytes/JSON/流读取、HTTPS/mTLS。
- `warpin-transport`：TCP 客户端/监听、连接数限制、定长/分隔符/长度前缀分帧、TLS/mTLS；UDP 完整数据报与来源规则。
- `warpin-mqtt`：3.1.1/5.0、QoS 0/1/2、订阅、遗嘱、手动确认、有限重连与会话配置、平台 TLS。
- `warpin-modbus`：TCP/RTU、标准读写、范围/回显/异常校验、显式寄存器顺序。
- `warpin-errors::protocol`：稳定的错误分类、操作阶段和 ServiceError 转换；敏感 source 不进入 Debug/Display。

每个模块的 README/TRANSPORT.md 包含生命周期、边界和运行示例。调用者拥有连接/事件循环，公共库不启动无监督任务。任何网络写入都不自动重试；TCP/Modbus 中途取消后不能继续复用原连接。MQTT 的协议重投递与业务操作重试明确区分。

## 错误边界

| Kind | code | msg 语义 |
|---|---|---|
| Configuration | 400 | 配置非法 |
| Authentication | 401 | 认证失败 |
| Rejected | 422 | 远端拒绝 |
| Capacity | 429 | 资源上限 |
| Protocol | 502 | 响应非法 |
| Connection / Closed | 503 | 连接失败/已关闭 |
| OutcomeUnknown | 503 | 执行结果未知，禁止自动重试 |
| Timeout | 504 | 总截止时间超限 |

不同 kind 在公共模块中保留，即使 HTTP code 相同也不混淆。Modbus 标准异常还保留 ExceptionCode；MQTT 拒绝原因/metadata 保留在原生事件。业务服务仍用现有 ApiError/ServiceResult，不另建响应壳。

## 验证证据

本机：macOS arm64，Apple M1，16 GiB RAM，Rust 1.97.0。使用 CommandLineTools toolchain；Bash 5.3/GNU coreutils 9.7 运行原有 shell 测试。

- 全 workspace/all-features 测试：334 通过、16 忽略、0 失败。16 项中包括 4 个需要 Broker 的新测试，已另行显式执行且全部通过；其余 12 项为既有忽略项。
- 全 workspace 默认 feature 测试：270 通过、13 忽略、0 失败；默认 feature 构建通过。
- `cargo fmt --all -- --check`、全 workspace/all-targets/all-features Clippy（`-D warnings`）、全 workspace/all-features build 通过。
- 四个协议 crate 的 Rustdoc（`-D warnings`）通过；修正了原 HTTP 文档到私有常量的链接。
- 实际 Mosquitto 2.0.23：两个 MQTT 版本、QoS 0/1/2、手动确认、重复确认拒绝、QoS1 断线重投递、跨会话确认拒绝、持久会话恢复、V5 过期、TLS/mTLS、认证拒绝、正常关闭通过。测试 Broker 仅监听 loopback，不启动系统服务。
- Modbus：全部 10 种开放功能码的 TCP/RTU 请求及响应、TCP 响应、异常、错误事务 ID/回显、取消，以及 macOS 虚拟串口 RTU/CRC 通过。
- HTTP/TCP/UDP：正常与异常载荷、超时、容量、分帧、截断、来源拒绝、TLS 名称校验/mTLS 等通过。
- 单连接 TCP loopback 负载检查：10000 帧、每帧 64 字节，debug 构建下总计 420 ms，p50 38 μs、p99 116 μs，配置接收缓冲上限 1024 字节。此数值只描述本机该次运行，不是吞吐 SLA 或现场性能承诺。
- `cargo tree -d` 已检查；全部 warpin crate 单一 0.2.11 版本线，其他重复版本来自原有依赖/API 代际差异。
- 安全处置及原始 audit 的两条未启用可选依赖报告，详见[安全记录](../security/2026-10-28-protocol-dependencies.md)。原始 audit **不能声明全通过**；两种目标的实际构建范围检查无阻断项。
- Linux/macOS CI 的四个协议 crate 格式、Clippy、测试、真实 Broker 测试、loopback 示例及在线依赖安全检查通过；全 workspace 验证以以上本机记录为准。
- 仓库外独立消费者仅声明 crates.io `=0.2.11` 依赖，构建和 API smoke test（1 项）通过；6 个直接及间接公共 crate 全部来自 crates.io、版本一致，没有 path/Git 覆盖。覆盖 HTTP 客户端构造、传输限制、MQTT 版本类型、Modbus 寄存器解码与未知结果错误转换。

升级必要的安全依赖，同时适配 object_store 0.14.2 的 Host 传输语义；原有 S3 拒绝伪造请求的回归测试继续通过。原 DingTalk 一项测试调整为先读完请求再响应，避免抢先响应的时序竞态，并等待取消的测试任务退出。

## 尚未执行的外部资格验证

物理 RS-485/串口设备、现场 Broker/私有 CA、真实传感器、PLC、MinIO/KES live gate、PostgreSQL 集成未在本轮连接验证。公共库接口和 CI 协议测试完成不代表现场验收完成。`warpin-workspace` 随统一版本分发，仍是开发候选组件，不代表其生产部署资格已经完成；其归档 README 中原有“not published”属于过时发布状态，开发候选和部署限制仍然有效。

公共库原规则忽略 Cargo.lock，本轮验证锁文件 SHA-256：`fbc5f7df68af5b547d8b1aa8f53a41045f92c85d9d8702e9251faba1c2a58ba6`。业务仓必须保留自己的 lockfile，等新版协议明确后再依计划引入实际用到的 crate。

## 迁移

已有 HTTP 模型客户端与服务启动 API 保持兼容。所有 crate 统一升级版本；新通信能力按需引入，不要求业务服务依赖全套 crate。新库有明确资源/超时要求，不能用默认值掩盖未知协议参数。MQTT 原生后端在 Linux 要求系统 OpenSSL，测试要求 Mosquitto 和 openssl CLI。

控制命令、测点编码/映射、回执内容、设备量纲、落库、告警和大屏 DTO 都留在业务仓，等待最新版现场协议。公共库不会自行认定现场使用 UDP。
