# warpin-modbus

Modbus TCP/RTU 通用客户端。没有设备寄存器表、单位换算、轮询计划或 PLC 控制业务。

```toml
[dependencies]
warpin-modbus = "0.2.11"
```

只读示例：`cargo run -p warpin-modbus --example read_tcp -- 127.0.0.1:502 1 0 2`，参数依次为 TCP 地址、unit、**零基**地址、数量。

- `connect_tcp_plaintext` 显式建立明文 TCP；`attach_tcp` 接入调用方建立的普通/TLS 流。unit 0（广播）拒绝。
- `open_rtu(SerialSettings,unit,deadline)` 同步打开串口，应用在启动阶段或自己监督的阻塞任务中调用；不要阻塞 async handler。所有串口参数必须显式给定。也可 `attach_rtu` 接入已配置流/虚拟串口；unit 限定 1..247。
- `call(Request)` 支持功能码 1、2、3、4、5、6、15、16、22、23。读 bit 最大 2000，读 register 最大 125，多写 coil 最大 1968，多写 register 最大 123，读写组合最多写 121。地址跨越 65535、零数量、未知/自定义操作均在发送前拒绝。
- 读响应检查长度并裁剪 bit 填充；写响应检查地址、数量或值的回显。远端异常保留 `ExceptionCode`，与网络错误区分。
- 每个实例串行执行；调用方对同一 RTU 物理总线必须只持有一个所有者。TCP 不自动重连，所有操作不自动重试。
- 超时/取消/协议损坏会销毁内部连接上下文，`is_closed` 返回 true。写请求在可能发出后的错误返回 OutcomeUnknown。严禁直接重发；先按设备协议查询实际结果。RTU 重新打开前由现场集成层完成总线静默、缓冲清理等恢复，不把晚到帧当作下一请求响应。
- `registers::Layout` 显式指定 word/byte 顺序，解码 i32/u32/f32/i64/u64/f64。输入寄存器数必须匹配；NaN/Infinity 保留，上层决定物理量是否有效。单个 u16 的 wire 字节序由 Modbus 实现处理。

错误 `Error::Exception` 保留标准异常；`Error::Transport` 保留公共错误分类。转换到 ServiceError 时不暴露原始响应。`close` 有截止时间；没有后台任务。

测试：`cargo test -p warpin-modbus`，含 TCP MBAP/异常/错误回显/取消及 Unix PTY RTU/CRC。虚拟串口通过不等于 RS-485 实机资格认证；操作系统串口驱动与总线时序必须由部署方另行验证。
