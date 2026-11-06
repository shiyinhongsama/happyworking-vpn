# Plan: 记住密码

## Approach

使用 `keyring 4.2.0` 的 Linux Secret Service 后端。保存操作只在认证成功后发生；读取按主机、端口和用户名匹配；取消勾选后的成功登录删除旧凭据。密钥环错误与认证结果分离。

## Tasks

- [x] 实现 `CredentialKey`、`CredentialStore` 和 `KeyringStore`，覆盖校验、读取、保存、删除及密钥环往返测试。
- [x] 增加 Tauri 读取命令和认证成功后的保存/删除，二次认证期间只在内存保留待保存凭据。
- [x] 增加“记住密码”选项、自动载入和保存失败警告。

## Verification

- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo fmt --all --check`
- `npm run check`
- `npm run build`
- 使用虚构账号执行一次显式密钥环往返测试并确认删除。
