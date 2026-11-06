# Tasks: sslvpn-tunnel

## 当前状态

- 已完成：帧、配置解析、V3/V7 本地 TLS 协商、Linux 网络后端、双向数据面、心跳、动态差异、退避、helper 与 Tauri 接入。
- 已通过：全部离线/本地测试、clippy、格式检查和 release 构建。
- 待验证：真实凭据登录、helper 权限提示、专用接口创建、公司地址访问、断开和异常清理。

## Task 1: 帧与网络参数解析

**Description:** 实现隧道帧编解码器和 NET_EXTEND 网络参数解析，严格限制长度和字段格式。

**Acceptance criteria:**
- [x] IP 帧使用类型 1、扩展 0、大端长度；心跳为 `02 01 00 00`。
- [x] 半包、粘包、非法类型、超长包和类型 3 配置更新有确定处理。
- [x] IP、CIDR 路由、排除路由、DNS、RESTRICT 和 KEEPALIVETIME 均被验证。

**Verification:**
- [x] `cargo test -p happyworking-vpn-sslvpn --test tunnel_frame`
- [x] `cargo test -p happyworking-vpn-sslvpn --test tunnel_config`

**Dependencies:** sslvpn-auth Task 2

**Files likely touched:** `crates/sslvpn/src/tunnel/mod.rs`, `crates/sslvpn/src/tunnel/frame.rs`, `crates/sslvpn/src/tunnel/config.rs`, `crates/sslvpn/tests/tunnel_frame.rs`, `crates/sslvpn/tests/tunnel_config.rs`

**Estimated scope:** Medium

## Task 2: V3/V7 NET_EXTEND 协商

**Description:** 构造恢复的握手请求，在新 TLS 连接上读取并解析网关配置，返回可用于网络事务的参数。

**Acceptance criteria:**
- [x] V7 请求包含 Host、SSLVPN-Client/7.0 和 svpnginfo；V3 使用恢复的 Cookie 形式。
- [x] 本地 TLS 测试能完成握手和参数读取，非 200 与非法配置会失败。
- [x] 认证成功但协商失败不会进入 Connected。

**Verification:**
- [x] `cargo test -p happyworking-vpn-sslvpn --test tunnel_negotiation`
- [x] `cargo clippy -p happyworking-vpn-sslvpn --all-targets -- -D warnings`

**Dependencies:** Task 1

**Files likely touched:** `crates/sslvpn/src/tunnel/mod.rs`, `crates/sslvpn/src/tunnel/negotiate.rs`, `crates/sslvpn/tests/tunnel_negotiation.rs`

**Estimated scope:** Medium

## Task 3: Linux 网络后端

**Description:** 在 netops 实现专用 TUN 创建、地址、路由和 DNS 操作，并接入现有事务回滚。

**Acceptance criteria:**
- [ ] 不通过 shell 拼接命令，不修改事务外资源。
- [ ] 失败和 Drop 只清理已成功创建/修改的资源。
- [ ] 权限不足返回结构化错误；实际测试不遗留接口。

**Verification:**
- [ ] `cargo test -p happyworking-vpn-netops`
- [ ] 经用户确认后执行专用接口集成检查并确认清理。

**Dependencies:** app-core Task 4 and Task 1

**Files likely touched:** `crates/netops/Cargo.toml`, `crates/netops/src/linux.rs`, `crates/netops/src/lib.rs`, `crates/netops/tests/linux.rs`

**Estimated scope:** Medium

### Checkpoint: 协议与系统边界

- [ ] 帧、参数、协商和网络事务测试通过。
- [ ] 真实系统测试范围已确认且无遗留资源。

## Task 4: 双向数据面与重连

**Description:** 实现 TLS 与 TUN 双向转发、心跳、动态网络更新、断线检测和有界退避重连。

**Acceptance criteria:**
- [ ] 两个方向均可转发多个包，读半包不会丢数据。
- [ ] 心跳遵循网关间隔，配置更新通过事务提交。
- [ ] 取消、I/O 错误和重连失败都执行同一清理。

**Verification:**
- [ ] `cargo test -p happyworking-vpn-sslvpn --test tunnel_data`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`

**Dependencies:** Tasks 2 and 3

**Files likely touched:** `crates/sslvpn/src/tunnel/mod.rs`, `crates/sslvpn/src/tunnel/data.rs`, `crates/sslvpn/src/tunnel/reconnect.rs`, `crates/sslvpn/tests/tunnel_data.rs`

**Estimated scope:** Medium

## Task 5: Tauri 隧道接入与真实验收

**Description:** 认证成功后按用户操作建立隧道，展示接口、地址和连接状态，断开/退出时注销并清理。

**Acceptance criteria:**
- [ ] 只有数据面就绪才显示已连接；认证和隧道失败分别展示。
- [ ] 断开、取消和应用退出均停止任务并清理网络。
- [ ] 当前网关真实登录、公司地址访问和断开清理由用户确认。

**Verification:**
- [ ] `cargo test --workspace`、`npm run check`、`npm run build`
- [ ] 真实登录、接口/路由检查、内网验收地址访问、断开检查。

**Dependencies:** Tasks 1-4

**Files likely touched:** `src-tauri/src/lib.rs`, `src/main.ts`, `index.html`, `src/style.css`

**Estimated scope:** Medium

### Checkpoint: sslvpn-tunnel 完成

- [ ] 所有离线/本地测试和构建通过。
- [ ] 真实网关各验收步骤有结果；未完成项明确列出。
