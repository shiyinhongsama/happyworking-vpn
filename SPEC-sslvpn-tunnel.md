# Spec: sslvpn-tunnel

## Objective

在 SSL VPN 认证成功后建立真正的 TUN 数据通道。覆盖 V3/V7 `NET_EXTEND`、网关网络参数、IP 帧、心跳、动态配置、断开和重连。认证成功本身不算隧道成功；只有参数协商、网络事务和数据转发均就绪才进入 Connected。

## Tech Stack

- Rust stable + Tokio，复用 `app-core`、`sslvpn-auth` 和 `netops`。
- OpenSSL/Tokio TLS 流，复用固定证书与客户端身份。
- Linux `/dev/net/tun` 和 netlink；GUI 不直接持有系统级网络权限。
- 特权 helper 使用独立进程、最小命令集和结构化标准输入/输出；不通过 shell 拼接网络命令。

## Commands

- `cargo test -p happyworking-vpn-sslvpn`
- `cargo test -p happyworking-vpn-netops`
- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo fmt --all --check`
- `npm run build`

## Project Structure

- `crates/sslvpn/src/tunnel/mod.rs`：隧道生命周期、连接和重连。
- `crates/sslvpn/src/tunnel/frame.rs`：帧编解码、半包/粘包和限制。
- `crates/sslvpn/src/tunnel/config.rs`：网络参数解析与校验。
- `crates/netops/src/linux.rs`：Linux TUN、地址、路由和 DNS 后端。
- `src-tauri/`：认证到隧道的状态事件及特权 helper 生命周期。
- `tasks/sslvpn-tunnel-*.md`：实施计划与任务。

## Code Style

```rust
let frame = Frame::ip(packet)?;
stream.write_all(frame.as_ref()).await?;
```

- 帧长度使用大端 `u16`，IP 包最大 65,535 字节，接收缓冲区有界。
- 网络更新先解析并完整校验，再提交事务；失败逆序回滚。
- 任一 I/O 循环失败或取消都触发同一清理路径。
- 不在日志中记录 IP 包内容、会话 Cookie 或凭据。

## Testing Strategy

- 帧测试覆盖空包、最大包、非法类型、半包、粘包、心跳和动态配置。
- 参数测试覆盖 CIDR、排除路由、DNS、RESTRICT、KEEPALIVETIME 和非法字段。
- 使用本地 TLS 服务和内存 TUN 假后端验证协商、双向转发、取消和回滚。
- Linux 实际网络测试需明确授权，只创建专用接口并验证清理，不运行全局破坏性命令。
- 当前网关实况验收依次是：登录、协商、接口/路由存在、公司地址可用、断开后清理。

## Boundaries

- Always：限制输入；保留网关物理路由；验证权限；失败回滚；取消所有任务。
- Ask first：安装 helper、修改 polkit、设置系统默认路由、覆盖既有 DNS 或路由。
- Never：以 root 运行整个 Tauri GUI；关闭证书校验；记录数据包；遗留测试接口。

## Success Criteria

1. V3/V7 能构造正确 NET_EXTEND 请求并解析网络配置。
2. IP 数据包按恢复帧格式双向转发，心跳和配置更新不会误判为 IP 包。
3. Linux 网络后端只管理本事务资源，异常和断开均清理。
4. 认证后只有数据通道就绪才进入 Connected；断线重连受退避、取消和用户控制。
5. 当前网关完成真实连接与内网访问验证；无法验证的步骤明确列出。
6. 全部测试、clippy、格式和 release 构建通过。

## Open Questions

- 特权 helper 的安装与 polkit 方式需在 Omarchy 上实测。
- 当前网关是否下发默认路由和 DNS 需登录后确认。
- 真实登录和内网访问需要用户在本机提供凭据及验收地址。
