# Spec: app-core

## Objective

为 HappyWorking VPN 提供所有协议共享的核心：连接配置、会话状态机、异步任务与取消、结构化错误、敏感数据保护、证书信任和特权网络操作边界。用户是需要在桌面系统连接公司网络的用户，后续平台包括 macOS 和 Windows。成功意味着后续 SSL VPN、802.1X 和 Portal 能复用同一套核心，而不各自保存密码或直接修改系统网络。

## Tech Stack

- Rust stable（当前工具链 1.98.1），Cargo workspace。
- Tauri 2 作为桌面壳；TypeScript + Vite 作为轻量前端，不引入大型 UI 框架。
- Tokio 用于异步 I/O、任务、定时器和有界通道；Serde 用于跨边界数据结构。
- OpenSSL 通过 Rust 绑定用于需要旧网关兼容的 TLS；仅在对应配置档显式启用旧协议/弱密钥兼容，不作为全局默认。
- `zeroize` 用于敏感缓冲区清理，`tracing` 用于默认脱敏的结构化日志。

## Commands

- 安装前端依赖：`npm install`
- 开发：`npm run dev`
- 构建：`npm run build`
- Rust 测试：`cargo test --workspace`
- Rust 格式：`cargo fmt --all --check`
- Rust 静态检查：`cargo clippy --workspace --all-targets -- -D warnings`
- 前端类型检查：`npm run check`

## Project Structure

- `Cargo.toml`：workspace 与共享依赖版本。
- `crates/core/`：配置、状态机、错误、取消、敏感值与证书信任模型。
- `crates/netops/`：TUN、路由、DNS 的抽象和 Linux 实现；特权操作集中于此。
- `crates/sslvpn/`：SSL VPN 协议模块（后续规格）。
- `crates/x1/`：802.1X 模块（后续规格）。
- `crates/portal/`：Portal 模块（后续规格）。
- `src-tauri/`：Tauri 命令、事件和进程生命周期。
- `src/`：TypeScript 前端。
- `tasks/`：经确认的实施计划与任务。
- `.analysis/`：本地逆向证据和工具，不进入发布包，也不提交到版本控制。

## Code Style

```rust
pub async fn connect(
    &self,
    profile: VpnProfile,
    cancellation: CancellationToken,
) -> Result<ConnectionGuard, VpnError> {
    profile.validate()?;
    let session = Session::new(profile, cancellation);
    session.run().await
}
```

- 模块和 crate 使用 kebab-case，Rust 类型使用 UpperCamelCase，函数和配置字段使用 snake_case/lowerCamelCase 的各自语言惯例。
- 公共边界返回结构化 `Result`，库代码不直接弹窗、不打印密码、不退出进程。
- 网络输入有长度上限和完整解析错误；异步等待必须可取消，禁止忙等。
- 默认不写注释；只有协议约束、安全边界或非显然原因需要简短中文注释。

## Testing Strategy

- Rust 内置测试和 Tokio 测试放在对应 crate 的单元测试及 `tests/` 集成测试中。
- 配置校验覆盖空值、非法地址/端口、过长字段和非法路径。
- 状态机覆盖合法转换、重复连接、取消、失败清理和断开幂等性。
- 断线恢复有自动化测试：意外中断进入“正在重连”，恢复成功回到“已连接”，重试耗尽转为失败并交回手动处理。
- 日志与持久化测试确保密码、Cookie、私钥及会话令牌不出现。
- 网络操作先通过抽象的假实现验证计划与回滚，再以 Linux 实际接口做明确标注的集成验证。
- 每次交付运行上述格式、测试、clippy 和前端类型检查；性能声明必须有测量依据。

## Boundaries

- Always：验证输入；默认脱敏；为异步任务设置取消与上限；断开后回滚本程序添加的网络配置；运行测试。
- Ask first：引入额外原生 SDK、安装系统服务、持久化保存密码、修改用户全局安全策略、扩大目标平台范围。
- Never：提交 `.analysis`、原客户端二进制、账号密码、Cookie、私钥或真实网络配置；默认跳过证书验证；删除失败测试来制造通过。

## Success Criteria

1. 所有协议共享统一的配置、会话状态、错误、取消和清理接口。
2. 密码仅以受控敏感值进入认证流程，默认不持久化，日志与错误自动脱敏；用户显式勾选“记住密码”时，仅允许在认证成功后写入系统密钥环，并支持读取与删除。
3. 自签名证书以 SHA-256 指纹和明确用户决定管理，不把全局 `danger_accept_invalid_certs` 作为实现。
4. 网络修改通过可测试的事务/回滚边界执行，异常路径不会遗留本程序新增的路由或 DNS 配置。
5. 核心测试、格式检查和 clippy 通过，Tauri 能调用核心并接收状态事件。

## Open Questions

- 802.1X 和 Portal 的真实验证环境及所需认证变种待后续确认。
- 各桌面平台的特权 helper 安装方式需结合对应打包、签名与系统授权机制分别验证。
