# Tasks: app-core

## Task 1: 建立 workspace 与配置校验

**Description:** 创建 Cargo workspace、核心 crate 和最小前端工程，定义通用网关配置、协议类型与校验错误。

**Acceptance criteria:**
- [x] 空主机、非法端口、过长字段和非法配置返回明确错误。
- [x] workspace 能构建，前端能执行类型检查。
- [x] `.analysis` 和凭据文件被版本控制排除。

**Verification:**
- [x] `cargo test -p happyworking-vpn-core`
- [x] `cargo check --workspace`
- [x] `npm run check`

**Dependencies:** None

**Files likely touched:** `Cargo.toml`, `crates/core/Cargo.toml`, `crates/core/src/lib.rs`, `crates/core/src/config.rs`, `package.json`

**Estimated scope:** Medium

## Task 2: 敏感值、证书信任与错误脱敏

**Description:** 实现密码/会话令牌的敏感值包装、SHA-256 证书指纹模型和跨层结构化错误，确保 Debug 与日志不泄露秘密。

**Acceptance criteria:**
- [x] 敏感值 Drop 时清零，Debug/Display 不暴露内容。
- [x] 证书指纹只接受规范十六进制格式，错误不包含 Cookie、密码或私钥。
- [x] 测试覆盖序列化边界和脱敏。

**Verification:**
- [x] `cargo test -p happyworking-vpn-core`
- [x] `cargo clippy -p happyworking-vpn-core --all-targets -- -D warnings`

**Dependencies:** Task 1

**Files likely touched:** `crates/core/src/secret.rs`, `crates/core/src/trust.rs`, `crates/core/src/error.rs`, `crates/core/src/lib.rs`

**Estimated scope:** Medium

## Task 3: 会话状态机、取消与有界事件

**Description:** 实现 Disconnected/Connecting/Connected/Disconnecting/Failed 状态、合法转换、异步取消和有界状态事件，不让协议层直接管理 UI 生命周期。

**Acceptance criteria:**
- [x] 重复连接、重复断开和非法转换有确定行为。
- [x] 连接中和隧道运行中都可取消，取消后进入正确终态。
- [x] 事件通道有界，无忙等；测试覆盖状态与取消。

**Verification:**
- [x] `cargo test -p happyworking-vpn-core`
- [x] `cargo clippy -p happyworking-vpn-core --all-targets -- -D warnings`

**Dependencies:** Task 2

**Files likely touched:** `crates/core/src/session.rs`, `crates/core/src/event.rs`, `crates/core/src/lib.rs`, `crates/core/tests/session.rs`

**Estimated scope:** Medium

### Checkpoint: 核心模型

- [x] `cargo test --workspace`、`cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings` 和 `npm run check` 全部通过。
- [x] 人工确认配置、敏感值和会话接口足以承载三种协议。

## Task 4: 网络配置事务与回滚

**Description:** 在独立 netops crate 定义 TUN、路由和 DNS 操作接口，用假后端实现操作日志、失败逆序回滚和断开幂等性。

**Acceptance criteria:**
- [x] 每一步失败只回滚本事务已成功执行的操作。
- [x] 多次清理不会重复删除，也不删除事务外配置。
- [x] 测试覆盖 TUN 创建、路由/DNS 失败和部分回滚。

**Verification:**
- [x] `cargo test -p happyworking-vpn-netops`
- [x] `cargo clippy -p happyworking-vpn-netops --all-targets -- -D warnings`

**Dependencies:** Task 2

**Files likely touched:** `crates/netops/Cargo.toml`, `crates/netops/src/lib.rs`, `crates/netops/src/transaction.rs`, `crates/netops/tests/transaction.rs`

**Estimated scope:** Medium

## Task 5: Tauri 命令/事件与最小状态界面

**Description:** 创建 Tauri 2 壳，将会话状态通过类型化命令和事件连接到可访问的中文界面；此步只演示核心状态，不伪装成 VPN 已连通。

**Acceptance criteria:**
- [x] 前端能读取配置校验错误和实时状态，连接按钮不会重复启动会话。
- [x] 界面明确标注“核心验证/尚未建立 VPN”，具备键盘焦点与可读错误。
- [x] 应用退出会取消会话并调用清理。

**Verification:**
- [x] `cargo test --workspace`
- [x] `npm run check`
- [x] `npm run build`
- [x] 手动检查窗口状态、错误展示和退出清理。

**Dependencies:** Tasks 3 and 4

**Files likely touched:** `src-tauri/Cargo.toml`, `src-tauri/src/lib.rs`, `src-tauri/tauri.conf.json`, `src/main.ts`, `index.html`

**Estimated scope:** Medium

### Checkpoint: app-core 完成

- [x] `SPEC-app-core.md` 的五项成功标准均有实现或明确验证结果。
- [x] 全部标准检查和应用构建通过。
- [x] 审核后再进入 `sslvpn-auth` 的规格、计划与任务。
