# Spec: sslvpn-auth

## Objective

实现 H3C iNode SSL VPN 的认证层，兼容已恢复的 V3 表单流程和 V7 XML 流程，包括参数发现、重定向、密码/客户端证书、图形验证码、二次认证、会话 Cookie 和注销。该模块只负责认证，不创建 TUN；成功后向 `sslvpn-tunnel` 提供经过校验的会话与网关参数。

当前网关已实测为 V7，支持密码认证，登录路径为 `/_xml/login.cgi`。V3、证书和二次认证在没有对应真实服务器时，只能通过协议样例与离线测试标注为“样例验证”，不得宣称已实况兼容。

## Tech Stack

- Rust stable，依赖 `app-core` 的配置、敏感值、状态、取消和错误模型。
- Tokio 异步 TCP；OpenSSL/`tokio-openssl` 处理旧网关 TLS 和客户端证书。
- `quick-xml` 解析和生成 V7 XML；`base64` 处理客户端版本私有字段；HTTP/1.1 解析限制响应大小并支持 Content-Length、chunked 和连接关闭。
- 不使用原 iNode 动态库，不调用原包的 `openssl` 命令，不通过 shell 转换 PKCS#12。

## Commands

- 模块测试：`cargo test -p happyworking-vpn-sslvpn`
- 全部测试：`cargo test --workspace`
- 静态检查：`cargo clippy --workspace --all-targets -- -D warnings`
- 格式检查：`cargo fmt --all --check`
- 应用构建：`npm run build`

## Project Structure

- `crates/sslvpn/src/auth/mod.rs`：认证状态与流程编排。
- `crates/sslvpn/src/auth/v3.rs`：V3 表单认证、域和验证码。
- `crates/sslvpn/src/auth/v7.rs`：V7 XML 认证、挑战和二次认证。
- `crates/sslvpn/src/http.rs`：有界 HTTP/1.1 请求与响应。
- `crates/sslvpn/src/tls.rs`：证书校验、旧网关兼容和客户端证书。
- `crates/sslvpn/src/codec.rs`：URL 编码、私有字段、Cookie 和参数解析。
- `crates/sslvpn/tests/`：V3/V7 样例、HTTP 边界和认证流程测试。
- `tasks/sslvpn-auth-plan.md` 与 `tasks/sslvpn-auth-todo.md`：本模块实施计划和任务。

## Code Style

```rust
pub async fn authenticate(
    &self,
    credentials: Credentials,
    cancellation: CancellationToken,
) -> Result<AuthSession, VpnError> {
    let capabilities = self.discover().await?;
    self.login(capabilities, credentials, cancellation).await
}
```

- 所有网关响应视为不可信输入，限制行数、响应大小、XML 深度和字段长度。
- 认证请求构造与网络发送分离，测试直接验证字节格式。
- 密码、Cookie、私钥和挑战响应不得进入 Debug、日志或持久化配置。
- 协议常量集中管理；不从字符串名称推断协议行为，恢复结论需关联 `.analysis` 中的证据。

## Testing Strategy

- 使用实际未认证 V7 响应的脱敏样例验证 Server 识别、重定向和能力解析。
- 使用确定性请求样例验证 V3/V7 编码、Content-Length、Cookie、注销和二次认证。
- 使用本地 TLS/HTTP 测试服务验证重定向、chunked 响应、响应上限、取消和证书校验。
- 验证 PEM/PKCS#12 客户端证书加载，不执行外部 shell 命令。
- 当前网关只执行不带凭据的发现流程作为实况检查；登录验证由用户在本机输入凭据后进行。
- 所有宣称支持的认证分支至少具有离线样例；没有真实环境的分支明确保留验证缺口。

## Boundaries

- Always：校验证书或要求显式指纹确认；验证响应；限制资源；取消等待；错误脱敏。
- Ask first：持久化密码或会话 Cookie、安装系统服务、扩大旧 TLS 兼容到全局、增加原客户端二进制依赖。
- Never：默认关闭证书验证；发送真实测试密码；将秘密写入 `.analysis`、测试或日志；以“登录失败”冒充连接成功。

## Success Criteria

1. 能从 `/svpn/index.cgi` 识别 V3/V7，跟随受控重定向并解析 V7 网关能力和 URL。
2. 能构造符合恢复证据的 V3 表单与 V7 `request=<URL 编码 XML>` 请求，正确处理 Cookie、Content-Length 和响应结果。
3. 支持密码、PEM/PKCS#12 客户端证书、图形验证码和 V7 Challenge 二次认证的流程接口。
4. 旧 TLS 兼容仅在配置档启用；当前网关的 1024 位 RSA、TLS 1.2/AES256-SHA 可通过显式证书信任与兼容模式访问。
5. 注销使用网关提供的 V7 URL 或恢复的 V3 路径；网络失败和取消均返回结构化错误。
6. 当前网关的无凭据参数发现实况通过；所有离线测试、clippy 和应用构建通过。

## 可选记住密码

- 默认不保存；只有用户显式勾选且认证成功后才写入 Linux Secret Service。
- 密钥按网关主机、端口和用户名区分；取消勾选后的成功登录会删除对应旧凭据。
- 密钥环不可用时不影响认证结果，但界面必须显示单独警告。
- 不把密码写入配置文件、日志、前端持久化存储或命令行参数。

## Open Questions

- 用户凭据只在运行界面输入；实际登录成功与否需用户配合验证。
- 802.1X、Portal 不属于本模块。
- V3 与特定短信供应商若无真实环境，只能完成样例级验证。
