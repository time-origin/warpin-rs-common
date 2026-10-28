# warpin-mqtt

MQTT 3.1.1 / 5.0 客户端，基于 rumqttc。版本、认证、TLS、会话和所有容量均显式配置；不包含 Broker、Topic 业务规则或数据库。

```toml
[dependencies]
warpin-mqtt = "0.2.11"
```

示例：`cargo run -p warpin-mqtt --example subscribe -- 127.0.0.1 1883 example/topic`。这是显式明文测试连接；生产应使用 `Security::Tls(tls::MqttTls::new(...))` 和可信 CA。MQTT 使用 rumqttc 官方 `use-native-tls` 后端，最低 TLS 1.2；与 TCP/HTTP 共用 PEM/身份输入校验，握手由系统 TLS 执行。Linux 需 OpenSSL 开发/运行库，macOS 使用系统 Security Framework；没有关闭校验的选项。

`Client::new(Config)` 仅创建本地状态，调用者必须持续执行 `poll(deadline)` 才能连接、收发和保活。每次返回一个原生协议事件；原生 `Packet` 保留 QoS、retain、dup、packet ID、原因码及 MQTT 5 属性。库没有隐式后台任务，不会漏掉后台退出错误。

`publish/subscribe/unsubscribe/acknowledge` 成功只表示入队，满队列立即返回 Capacity。必须检查 `Outgoing` 以及收到的 ACK/拒绝原因，不能把入队当作设备已执行。QoS 0 无发布确认；QoS 1/2 也不是数据库事务确认。按调用顺序跟踪 outgoing packet ID，不把复用的 packet ID 作为长期业务标识。

所有入站发布使用手动确认。`acknowledge(&mut Event)` 只接受同一客户端、同一连接代次的发布事件，拒绝重复调用和 QoS 0。跨重连应等待重新投递；保留消息需要由应用持久化，库不把内存队列当作持久会话。QoS 2 的后续握手由 rumqttc 驱动。

`Version::V311{clean_session}` 与 `Version::V5{clean_start,session_expiry_seconds}` 分别配置会话。每次 ConnAck 都必须检查 `session_present`；会话丢失时由应用明确重新订阅，库不猜测订阅清单。协议重投递可能发生，应用仍需幂等。MQTT 5 扩展属性可读；本版本发送端只封装标准发布/订阅和会话设置，不提供任意属性注入。

`max_reconnects` 是整个实例生命周期的重连次数上限，0 禁止重连。每次网络错误先返回调用者，下次 `poll` 才等待固定 `reconnect_delay` 后连接；认证/协议/拒绝错误停止恢复。不会自动重新执行应用层写操作，但底层 MQTT 会按 QoS 会话语义重投在途消息。

`poll` 的总截止时间包括退避；超时或取消使实例不可复用，需 abort/drop，并由应用决定恢复未确认消息。`close(deadline)` 等待 DISCONNECT 写出后销毁连接；不保证所有已排队发布已确认。要保证交付，先消费相应确认事件再关闭。`abort` 立即本地停止，无交付保证。

容量：队列 `1..65536`、packet `128..16 MiB`、in-flight `1..65535`、保活 `5..65535 s`、连接超时 `1..3600 s`（整秒使用）、退避 `>0..3600 s`。应按 `(queue_capacity + max_in_flight) × max_packet_bytes` 预算出站载荷内存，再计入入站与底层开销。应用保存 Event 的队列仍需自行设上限。

验证：`cargo test -p warpin-mqtt`；真实 Broker 套件需 `MOSQUITTO_BIN=/path/to/mosquitto cargo test -p warpin-mqtt --test broker -- --ignored`。测试自行创建 loopback Broker、清理进程，不连接生产服务。

Linux 的发行版 Mosquitto 若受 AppArmor 约束，可显式设置 `MOSQUITTO_TEST_ROOT` 为系统策略允许且当前用户拥有的测试目录（CI 使用 `/etc/mosquitto/certs/warpin-ci`）。测试在其中创建独立临时子目录并清理；不修改生产配置或关闭系统策略。配置错误及 Broker stderr 会明确显示。
