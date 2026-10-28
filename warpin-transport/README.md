# warpin-transport

通用 TCP/UDP 和 TLS，不解释设备业务报文。Rust 2024，使用 Tokio runtime。

```toml
[dependencies]
warpin-transport = "0.2.11"
```

运行无设备示例：`cargo run -p warpin-transport --example loopback`。

- `Limits`：单次操作总超时（1 ns–24 h）和最大完整帧长度（1–16 MiB），零值拒绝。UDP 上限为 65507 字节。
- `tcp::Connection::connect` 显式创建明文连接；目的地是已解析 `SocketAddr`。DNS/目标网络授权由应用承担。
- `tcp::Listener::bind` 指定连接上限；`accept` 满额立即报错。连接和 TLS 握手持续持有许可，Drop 释放。不启动后台任务。
- `read_chunk` 返回受限读取块，不承诺报文边界；`read_frame` 使用 `Fixed`、`Delimited`、`LengthPrefixed` 或自定义 `FrameDecoder`。返回值包含线上的完整头部/分隔符。不要混用两种读取方式。
- `write_frame` 完成只表示本机流写入完成。没有业务 ACK、自动重连或重发。错误或取消之后整个连接停止接收新操作，调用方应关闭/丢弃并按设备协议恢复。
- `close().await` 有界关闭写半边，不等价于对端已经处理数据；Drop 是本地取消。
- `tls::{ClientTls,ServerTls,Identity}` 校验 PEM、证书链、服务器名称；可要求双向认证。CA/identity 在构造时校验，证书有效期在握手时校验。使用 `Connection::{connect_tls,accept_tls}` 升级并保留连接许可。没有禁用证书验证选项。
- `udp::Socket` 以 `Sources::{Any,Only}` 显式配置接收规则。`recv` 返回 payload、来源、本机接收时间。拒绝超限数据报，重复和乱序原样交给应用。来源过滤不提供身份认证。`send` 成功不保证远端收到，UDP 也不保证无丢包。

连接缓冲区不超过 `max_frame_bytes`；UDP 每次接收分配 65536 字节以检测超限，返回长度仍受配置限制。应用必须自行限制创建的 socket/连接实例总数。错误采用 `warpin_errors::protocol::ProtocolError`，`kind/phase` 可用于结构化日志，`ServiceError` 转换保留稳定 code/msg。任何原始 `source()` 只供内部诊断，不得直接输出给外部用户。

测试：`cargo test -p warpin-transport`。测试目录证书及私钥是公开、专用于 loopback 的夹具，绝不能用于部署。
