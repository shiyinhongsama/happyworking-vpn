# Implementation Plan: sslvpn-tunnel

## Overview

按已批准规格实现 SSL VPN 数据通道。协议解析与真实系统副作用分离，先用离线/本地测试证明，再在用户提供的凭据和验收地址下做真实连接。

## Architecture Decisions

- 帧编解码器不依赖 TLS/TUN，支持跨 read 的半包和一次 read 的多帧。
- NET_EXTEND 复用认证后的 Cookie 与 TLS 配置，使用独立连接。
- Linux 网络后端实现 `NetworkBackend`，由事务统一回滚。
- Tokio 双向数据面使用 split 流和有界读写，取消统一进入清理。
- 自动重连使用指数退避和上限，不在认证信息失效时静默反复登录。

## Task List

1. 帧与网络参数解析。
2. V3/V7 NET_EXTEND 协商。
3. Linux TUN/地址/路由/DNS 后端。
4. 双向数据面、心跳、配置更新和重连。
5. Tauri 接入与真实网络验收。

## Risks and Mitigations

| 风险 | 影响 | 缓解 |
|---|---|---|
| 半包或恶意长度导致解析错误 | 丢包/内存消耗 | 流式编解码测试和固定上限 |
| 默认路由/DNS 覆盖影响其他网络 | 系统断网风险 | 显式事务、保留网关物理路由、逆序回滚 |
| GUI 权限不足 | TUN 创建失败 | 独立 helper，不提升整个 GUI |
| 重连风暴 | 服务器压力 | 有界指数退避、取消和状态事件 |
