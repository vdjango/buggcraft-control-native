# 复用与方法/DOM 清单

2026-11-11 目录：检索 Placement/list/locate/reserve、rooms/reservations 与节点确认流程后扩展同一 Service::placement，增加 publish/resolve 分支。容量目录缺少公开描述和秘密，因此复用原事务、设备身份、epoch、SHA-256 和 host reservation 补齐，不新增调度器。ControlClient::publish、Rpc::publish_listing 只适配接口并缓存成功描述，复用 describe 轮询；QML/节点不复制策略。清单已更新，实测见 [13](13-大厅房间目录修正.md)。

当前已实现 C++ 服务、验证脚本和 AST 生成器，没有网页或 DOM。实际清单：[methods.json](90-代码清单/methods.json)、[sources.json](90-代码清单/sources.json)、[dom.json](90-代码清单/dom.json)。下表仍是领域职责，不保证每个规划方法已实现；实际类与调用见 08 和源码。

## 规划所有者与方法契约

| 领域／规划入口 | 输入 → 结果 | 失败与资源／执行约束 |
| --- | --- | --- |
| Enrollment：register / prove | 长期凭证、节点公钥/挑战、幂等键 → 独立 node_id/运行身份 | 无效/撤销/限流分开；写入事务完成才确认；不返回中心密钥 |
| NodeRegistry：announce / isolate | 节点身份、能力、入口、观测 → 注册版本/健康状态 | 节点通道 strand；旧版本不得覆盖新版本；隔离不删除审计 |
| Identity：verify / renew / revoke | 用户证明、用途、设备 → 限权运行授权 | 复用密码库；按 audience/epoch 撤销；不持有用户私钥 |
| Presence：refresh / close / view | account/device/session/epoch/seq → 租期/三态 | 活跃会话分片拥有；迟到事件不复活；租期失效 unknown |
| Social：apply / acknowledge / replay | 签名事件、游标/回执 → 持久事件/投递状态 | 唯一键和 Outbox 同事务；重复幂等；到期/拒绝不继续重试 |
| Placement：candidates / reserve / confirm / release | 意图、地区、探测、容量、幂等键 → 签名分配 | 03 是唯一分配规则；最终预留必须原子，超额明确失败 |
| RoomDirectory：locate / assign / recover | room_id/epoch、所有者授权 → 唯一 owner | 和容量提交协调；旧 epoch 不覆盖；不承诺 TCP 迁移 |
| Transport：HTTPS / node channel / deadlines | 已鉴权请求/通道 → 域操作/有界响应 | 只处理传输/解析，不复制业务；关闭统一取消和释放 |
| Storage：transaction / outbox / lease cache | 域操作和截止时间 → 持久结果/暂时失败 | 有界连接池、可重试分类、提交不明的幂等恢复 |
| Observability：metrics / audit / redaction | 分类事件与资源采样 → 指标/脱敏审计 | 无凭据和载荷；异步有界写入，截断/丢弃可观察 |

HTTP、CLI、WSS 管理和未来网页都是这些所有者的调用方，不再实现账号查重、区域评分、容量额度或社交重试规则。领域方法名在实现时可调整，需同步契约和调用方，不把所有业务硬塞进一个通用 dispatcher。

## 可复用与禁止复制的边界

现有原生桥/C ABI 的调用入口、游戏转发核心、P2P、EOF 与负载校验夹具可通过现有公开接口复用。旧源码跨仓带入前确认许可和作者授权；已有 AGPL 包装层不能仅改命名就放进拟闭源服务。

TLS/密码/摘要用成熟库；CPU 分派、JSON 解析、异步网络、数据库连接和常用日志能力先查依赖，避免再次手写。自有适配代码按职责归 transport/storage/crypto 等唯一模块。只有出现真实多个消费者时才抽独立共享库，不先搭建空的“万能 common”框架。

每次变更说明写清检索到的相似实现、实际复用入口、新增理由与唯一所有者。相同代码行不一定语义重复，不同认证域也不能为了复用而合并权限。

## 索引与 CI 计划

受管接入扩展原所有者：crypto::verify_delegation 统一公开证书/设备委托校验，enrollment 消费其结果，service::authenticate 校验设备租期，placement 负责固定预留恢复与新入场撤销检查，social 统一好友快照与批量 ACK。账号适配、节点验票和桥在各自公开项目；复用已有设备授权、HTTPS、签名、Session 和集成夹具，不复制中心分配规则。接口见 08，部署见 10。

已实现 `scripts/inventory.py`：C++ 使用 tree-sitter-cpp，Python 使用 ast，扫描 include/src/tests/benchmarks/scripts 的方法、类、声明/定义、lambda、回调及源码摘要，输出 methods/sources；有前端时再加入 Vue/HTML DOM 和选择器引用。新增、删除、改名或函数体变化使清单过期，CI 执行 `--check`。脚本独立实现，没有复制相邻 AGPL 索引器。

实际复用：Boost.Asio/Beast 管传输，OpenSSL EVP 管密码与 CPU 分派，libpq 管参数化 SQL，simdjson 管 JSON 解析/CPU 分派，nlohmann 管拥有型结果。SQL 容量操作仅 placement.cpp；HTTP/WSS 统一 dispatch，不另写领域方法。测试脚本由 Environment/Client/NodeProof 拥有夹具，性能脚本调用这些入口，不复制服务实现；synthetic SQL 仅创建测试目录行，不充当业务逻辑。

原生账号新增所有者见 [11](11-原生账号与迁移.md)：browser.cpp 持有账号协议与迁移，browser_transport.cpp 复用 libcurl SMTP/TLS；State::submit 统一有界任务与 worker 数据库连接，Database::lock 统一 advisory 锁。签名复用 crypto；设备批准/撤销调用既有 admin 域，不复制权限逻辑。前端源码仍只有相邻项目的一份，此仓库仅服务构建资产，不维护第二套 DOM。

AST 清单辅助检索，不证明没有语义重复，也不代替编译、测试或浏览器操作。当前 DOM 状态为“不适用”，不是通过了不存在的页面测试。将来有界面时，组件、异步 scope、导航和选择器成对维护，并实际查看截图。

玩家足迹只归 activity.cpp 的 Service::record_activity、record_companions、activity：输入既有鉴权账号、活动类型/租期或 room/epoch，输出账号累计、北京时间日明细及已接受好友的共同连接摘要。presence 与 placement 复用同一所有者，不在浏览器或桥复制计时规则；已有数据库事务、参数查询、行锁与 worker 执行归属继续复用。关闭、到期、多设备、跨房及读取权限见第 12 号；浏览器 DOM 仍只有相邻节点仓库一份。
