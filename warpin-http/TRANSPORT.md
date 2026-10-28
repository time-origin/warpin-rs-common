# 通用 HTTP transport

`warpin_http::transport` 与现有模型 `EndpointClient` 独立。它不注入业务参数，不解析厂商响应壳，不切换 endpoint。

`HttpTransport::new(base, security, authentication, limits)` 校验配置并复用连接池。base 必须是可信配置、无用户信息/query/fragment、以 `/` 结尾；相对 path 不允许绝对地址、dot segment、反斜线、fragment 或百分号编码歧义。面向不可信目标时，应用仍须限制目标网络/DNS；本组件不提供任意 URL 代理。

`Security::Https` 使用系统根证书；`CustomTls(ClientTls)` 使用明确 CA 和可选双向身份；明文需 `PlaintextAllowed`。凭据用 `Authentication::{None,Bearer,Header}`，自定义认证 header 标为 sensitive，不能覆盖 Host、长度或传输控制 header。没有跳过证书验证的开关。

`request(Method,path,HeaderMap,Vec<u8>)` 返回有界 `Response`。配置 `connect_timeout/read_timeout/total_timeout` 和请求/响应字节数、最大并发数；容量满立即报错，不排无限队列。HTTP 状态原样提供，4xx/5xx 不会伪装成业务成功；调用方必须检查 `status()` 后按厂商协议处理。JSON 请求可用 serde_json 显式编码，响应可用 `json::<T>()`。

响应 `chunk/bytes/json` 共享请求开始时的总截止时间；逐块累计限长，不信任 Content-Length。持有 Response 期间占用并发许可，读取完成并释放/Drop 后归还。读取失败或被取消后该 Response 不可复用。默认禁用重定向、环境代理、自动重试和自动解压；压缩载荷作为原始有界字节返回，调用方若再解压必须设置解压后限制。

POST/PUT/PATCH/DELETE 等可能改变状态的方法在发送期间超时/断连返回 OutcomeUnknown；不自动重发。收到状态/响应不代表设备动作完成。外部错误使用稳定 `ProtocolError.kind/phase`，转换成 ServiceError 后由现有 ApiError 边界展示 code/msg，原始 source 仅供内部诊断。

运行示例：`cargo run -p warpin-http --example http_get -- https://host/api/ relative/path`。
测试：`cargo test -p warpin-http --test transport`。示例不提供现场地址、厂商密钥和业务字段。
