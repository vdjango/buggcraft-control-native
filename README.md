<div align="center">

# Buggcraft 统一服务

### 一个入口，管理登录授权、好友和联机节点

[![C++20](https://img.shields.io/badge/服务端-C%2B%2B20-00599C)](CMakeLists.txt) [![HTTPS](https://img.shields.io/badge/API-HTTPS%20%2B%20WSS-2563eb)](docs/08-构建运行与接口.md) [![数据库](https://img.shields.io/badge/存储-PostgreSQL-4169e1)](docs/08-构建运行与接口.md)

[官网](https://bugg.icu) · [统一服务](https://node.bugg.icu) · [问题反馈](https://node.bugg.icu/feedback)

</div>

统一服务负责账号登录授权、设备管理、在线状态、好友邀请、房间归属和节点分配。游戏连接仍通过 P2P 或联机节点中继；玩家游戏数据不会经过控制服务。

## 玩家体验

- 启动器通过统一服务登录；联机节点不提供账号登录入口。
- 可撤销的设备授权和统一好友邀请流程。
- 按节点地区、健康状态与容量选择联机节点，并保持房间归属。
- 节点运营者可以部署自己的服务，并在节点配置中指定服务地址。

## 架构

服务端使用 C++20、HTTPS/WSS、PostgreSQL、OpenSSL、Boost.Asio/Beast 与 simdjson。依赖库负责 TLS、密码学、网络 I/O 和 JSON 的运行时 CPU 优化；服务没有全局强制 AVX 指令的要求。已测硬件、指令集对照与未覆盖的平台列于[开发验收与性能报告](docs/09-开发验收与性能报告.md)。

长期节点接入凭证只授权节点注册，支持撤销和轮换。不要将运维管理员凭据放入公开客户端或发给工作节点。

## 自建

构建、配置、接口和数据要求见[构建运行与接口](docs/08-构建运行与接口.md)。部署历史与当前节点状态见[部署记录](docs/10-IP部署与受管接入.md)。

Buggcraft 与 Mojang、Microsoft 无隶属关系。Minecraft 是 Mojang Studios 的商标。
