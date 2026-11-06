# Capability Map: HappyWorking VPN

## 目标与假设

- 当前实测平台为 Linux x86_64，使用 Rust + Tauri 2；后续扩展 macOS 和 Windows，厂商客户端及其动态库不作为运行时依赖。
- 默认只在内存中保存密码；自签名网关必须经用户确认证书指纹后才可连接。
- 当前提供的网关可用于 V7 密码认证的实况验证。其他协议与认证方式若缺少对应网络环境，只能分别标注为静态恢复、样例验证或实况验证，不能混为已兼容。
- 网络接口、路由和 DNS 修改集中在最小权限边界，失败或断开时必须回滚本客户端添加的配置。

| Module id | 责任 | 依赖 |
|---|---|---|
| app-core | 配置模型、连接状态机、异步任务、错误模型、密钥与证书信任边界 | — |
| sslvpn-auth | SSL VPN V3/V7 参数发现、重定向、密码/证书、验证码、二次认证、注销 | app-core |
| sslvpn-tunnel | NET_EXTEND、TLS 数据通道、帧编解码、TUN、路由/DNS、心跳与重连 | app-core, sslvpn-auth |
| x1-access | 802.1X/EAPOL 认证、客户端休眠/唤醒与重认证 | app-core |
| portal-access | Portal 发现、认证、在线保持与注销 | app-core |
| desktop-ui | Tauri 界面、命令与事件、证书确认、连接状态及诊断 | app-core；随各协议垂直切片接入 |

## 构建顺序

1. `app-core`，随后以当前网关打通 `sslvpn-auth` → `sslvpn-tunnel` → `desktop-ui`。
2. `x1-access` 与 `portal-access` 可独立分析、实现和验证，再接入同一状态机与界面。
3. 每个模块分别经过规格确认、计划、任务拆分、实现和验证；未获实况环境的项目保持明确的验证缺口。

## 完成定义

不仅要求程序能构建，还要求每种宣称支持的协议都有对应测试和实际流程证据。性能目标通过异步 I/O、有界缓冲区、零拷贝/少拷贝数据路径及无忙等重连实现，并以基准或测量结果验证，不使用无依据的“更快”结论。
