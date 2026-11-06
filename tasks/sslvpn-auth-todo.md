# Tasks: sslvpn-auth

## 当前状态

- 已完成：TLS/HTTP、真实无凭据发现、V7/V3 编解码与请求流程、证书/验证码/二次认证接口、Tauri 流程和构建。
- 待验证：用户本机真实登录、Challenge 和注销；V3 与特定认证供应商尚无真实环境。

## Task 1: TLS/HTTP 与 V7 参数发现

**Description:** 新建 SSL VPN crate，实现旧网关 TLS 配置、显式证书指纹、HTTP 响应上限、重定向和 V7 能力 XML 解析。

**Acceptance criteria:**
- [x] 当前网关可在不关闭证书验证的情况下完成无凭据发现。
- [x] Content-Length、chunked、超长响应和非法 XML 有确定处理。
- [x] 实测解析出密码认证及登录/注销/challenge URL。

**Verification:**
- [x] `cargo test -p happyworking-vpn-sslvpn`
- [x] 使用固定证书执行一次无凭据发现命令，结果与已保存证据一致。

**Dependencies:** app-core complete

**Files likely touched:** `crates/sslvpn/Cargo.toml`, `crates/sslvpn/src/tls.rs`, `crates/sslvpn/src/http.rs`, `crates/sslvpn/src/auth/discovery.rs`, `crates/sslvpn/tests/discovery.rs`

**Estimated scope:** Medium

## Task 2: V7 密码认证与注销

**Description:** 实现 V7 XML 登录、URL 编码、私有客户端字段、Cookie 解析、Success/Challenge/错误结果和注销请求。

**Acceptance criteria:**
- [x] 请求样例逐字节匹配恢复的字段顺序与双重编码规则。
- [x] 密码和 Cookie 不出现在 Debug/日志，响应大小与字段长度受限。
- [x] 登录失败、需二次认证、成功和注销都有明确结果。

**Verification:**
- [x] `cargo test -p happyworking-vpn-sslvpn --test v7`
- [x] `cargo clippy -p happyworking-vpn-sslvpn --all-targets -- -D warnings`

**Dependencies:** Task 1

**Files likely touched:** `crates/sslvpn/src/auth/v7.rs`, `crates/sslvpn/src/auth/mod.rs`, `crates/sslvpn/src/codec.rs`, `crates/sslvpn/tests/v7.rs`

**Estimated scope:** Medium

### Checkpoint: 当前网关认证

- [ ] V7 发现实况通过，V7 登录样例和注销测试通过。
- [ ] 用户在本机输入真实凭据后确认登录结果；失败则保留脱敏错误并修复协议差异。

## Task 3: V3 表单认证

**Description:** 实现 V3 参数数组、域/认证方式、图形验证码 Cookie 和表单登录，复用统一认证结果。

**Acceptance criteria:**
- [x] V3 表单包含恢复的 MAC、语言、用户、密码、域、认证方式和验证码字段。
- [x] 能解析成功、错误和旧登录冲突响应，支持注销路径。
- [x] 样例测试覆盖可选字段与 URL 编码。

**Verification:**
- [x] `cargo test -p happyworking-vpn-sslvpn --test v3`
- [x] `cargo clippy -p happyworking-vpn-sslvpn --all-targets -- -D warnings`

**Dependencies:** Task 2

**Files likely touched:** `crates/sslvpn/src/auth/v3.rs`, `crates/sslvpn/src/auth/mod.rs`, `crates/sslvpn/src/codec.rs`, `crates/sslvpn/tests/v3.rs`

**Estimated scope:** Medium

## Task 4: 客户端证书、验证码与二次认证

**Description:** 支持 PEM 和 PKCS#12 客户端证书、V7 图形验证码、Challenge 响应及 SMS/SMS-IMC 二次登录，不调用 shell。

**Acceptance criteria:**
- [x] 证书和密码只通过安全 API 使用，错误不泄露私钥。
- [x] Challenge 能驱动二次输入并完成请求；不支持供应商返回明确错误。
- [x] 本地样例覆盖证书、图片和二次认证流程。

**Verification:**
- [x] `cargo test -p happyworking-vpn-sslvpn --test extended_auth`
- [x] `cargo clippy -p happyworking-vpn-sslvpn --all-targets -- -D warnings`

**Dependencies:** Task 2

**Files likely touched:** `crates/sslvpn/src/tls.rs`, `crates/sslvpn/src/auth/v7.rs`, `crates/sslvpn/src/auth/mod.rs`, `crates/sslvpn/tests/extended_auth.rs`

**Estimated scope:** Medium

## Task 5: Tauri 认证流程与实况验证

**Description:** 将发现、证书确认、登录、二次输入和注销接入 Tauri，使用核心状态机并清楚区分认证与隧道状态。

**Acceptance criteria:**
- [ ] 用户可在本机输入密码，前端不记录或持久化它。
- [ ] 自签名证书显示 SHA-256 指纹并需显式确认。
- [ ] 界面区分“发现完成”“认证成功”“隧道未建立”，取消和错误可用。

**Verification:**
- [ ] `cargo test --workspace`、`npm run check`、`npm run build`
- [ ] 用户执行一次真实登录和注销，确认服务器结果。

**Dependencies:** Tasks 1-4

**Files likely touched:** `src-tauri/src/lib.rs`, `src/main.ts`, `index.html`, `src/style.css`, `src-tauri/capabilities/default.json`

**Estimated scope:** Medium

### Checkpoint: sslvpn-auth 完成

- [ ] 所有离线测试和构建通过，真实认证结果已记录。
- [ ] 未获真实环境的分支明确标注为样例验证。
- [ ] 审核后进入 `sslvpn-tunnel` 规格与任务。
