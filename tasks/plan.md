# Implementation Plan: app-core

## Overview

实现已批准的 `SPEC-app-core.md`，先形成可构建、可测试的 Rust workspace 与最小 Tauri 壳，再逐步加入敏感信息保护、连接状态机和网络配置回滚。SSL VPN、802.1X、Portal 的协议代码不在本计划内，它们通过稳定接口接入。

## Architecture Decisions

- 使用 Cargo workspace 分离核心、网络操作和桌面壳，协议 crate 不依赖 Tauri。
- 公共 API 使用结构化配置、状态和错误；敏感值采用专用包装，调试输出默认脱敏。
- 网络修改采用事务记录和逆序回滚；核心测试使用假后端，不让单元测试修改真实系统。
- Tauri 仅负责命令/事件和进程生命周期，异步核心可独立测试。

## Task List

1. Workspace 与配置校验。
2. 敏感值、证书指纹和结构化错误。
3. 会话状态机、取消与有界事件。
4. 网络配置事务及回滚。
5. Tauri 命令/事件与最小状态界面。

## Risks and Mitigations

| 风险 | 影响 | 缓解 |
|---|---|---|
| 旧网关要求 TLS 1.2、AES256-SHA 和 1024 位 RSA 兼容 | 现代 TLS 默认拒绝 | 只对显式旧配置使用 OpenSSL 安全级别 0，同时保持证书指纹/CN 校验 |
| GUI 无 CAP_NET_ADMIN | 无法直接创建 TUN 或改路由 | 核心先抽象网络后端，特权 helper 方案单独验证，不在测试中修改真实网络 |
| 其他协议缺少真实环境 | 无法宣称端到端兼容 | 分别记录静态、样例和实况验证状态 |

## Open Questions

- 特权 helper 的打包和 polkit 安装在 SSL VPN 隧道任务中确定。
- 802.1X/Portal 的实际服务器与认证变种待用户提供环境后验证。
