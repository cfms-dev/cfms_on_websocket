# CFMS 测试重整验收记录

实施范围：测试、测试支持设施、运行配置、CI 与文档。生产协议、模型、业务实现、Python 版本及锁定依赖未修改。

## 结果与准则

全套保留领域目录，现有 **122 个测试模块、1,266 个测试函数定义、1,830 个参数化展开节点**。函数数不能替代实际节点数。

| 层级 | 节点数 | 风险边界 |
| --- | ---: | --- |
| unit | 649 | 决策、验证、序列化、内存算法及已有边界的替身 |
| component | 869 | 进程内真实数据库、文件、存储及 handler 组合 |
| integration | 312 | 真实进程、协议连接、CLI 与外部后端 |

采用以下准则：验证业务契约；独立构造预期并检查完整结果；在数据库与事务风险上使用真实依赖；资源创建者负责关闭；内部等待有期限且工作线程异常可见；按真实风险分层；共享生命周期，不隐藏关键输入和预期。依据见 [测试指南](README.md) 中的 pytest、Google 与 Python 官方资料链接。

[逐节点索引](contract_inventory.csv) 记录契约标签、参数场景、层级、断言表达式与源码位置。契约标签来自测试名称或说明；无异常即接受的场景与委托检查明确标注。索引是本次审查快照，不能替代独立的需求确认或充当测试的预期算法。

## 实施内容

1. 修复 `pytest.ini` 配置节，启用严格配置、严格标记、strict asyncio 与 function fixture loop；120 秒 watchdog 使用平台默认方法。客户端 `response_timeout=10.0` 覆盖普通、原始、文件帧与默认事件等待。服务器就绪后客户端仅连接一次；三处容量竞争改用有期限的 Barrier 和 Future。
2. 收集时检查唯一层级和真实服务器 fixture 的传递依赖。共享 SQLite factory 复用生产外键、WAL 和锁等待配置，创建即注册 engine 清理；保留闭合的小 schema、完整 metadata、事务及每线程独立 Session。共享 fixture/fake 移出被收集的测试模块，删除无效配置复制、cwd 变更和局部全局 watcher 关闭。
3. 搜索检查 3+2 分页、完整 ID 集合、页间互斥及结束 cursor，排序检查完整明确顺序。备用码检查新 Session 中的持久化消耗和协议重用拒绝。OIDC callback 使用真实缓存、SQLite、RSA JWT、PyJWT 与 OAuth2Session，仅替换 HTTP/JWKS 获取边界，覆盖 30 个 callback 场景。用户名保留请求模型边界和 ORM 列长度检查。
4. 主 CI 分三层执行，排除真实 stress 执行，输出 JUnit 与耗时报告；Redis、MySQL 8.4/9.7、PostgreSQL 通道要求非空配置、至少一个用例和零跳过。外部数据库引擎也立即注册清理，覆盖建表及清库失败；原 DDL、seed 和清库逻辑保留。Windows 文件行为、发布包 smoke 与独立性能工作流保留。更新测试和工作流指南，添加 Towncrier fragment。

## 设施移动、删除与覆盖去向

| 原位置或删除内容 | 去向／仍保护的契约 |
| --- | --- |
| `documents/test_file_task_lifecycle.py` 的共享 fixture、流／存储替身、任务构造 | `documents/support.py` 与领域 `conftest.py`；原生命周期、I/O、续传、上传完成场景保留 |
| access 测试模块中的 fixture、用户构造 | `access/support.py` 与 `conftest.py`；规则匹配、查询与同步场景保留 |
| migration 测试内脚本目录和 runtime seed | `maintenance/database/support.py`；SQLite clone 与 MySQL migration 共用，原场景保留 |
| 调度中手动创建而未释放的 engine | `scheduling/conftest.py` 和共享 factory；持久化、租约、竞争、删除与 hook 场景保留 |
| 用户名源码子串断言 | 请求模型长度边界、ORM 列长度的真实 subprocess 检查；等价源码写法不再误报 |
| `test_verify_2fa_login_with_backup_code` 名称 | 改为 `test_verify_2fa_login_consumes_backup_code_once`，原成功场景保留，增加数量 10→9→9 与第二次 401 |
| 两个下载客户端的过时 FakeStream 与不必要的真实登录 | 原节点保留，改用实际 AsyncStream、明确的协议帧和 unit 层；中止、空文件及完成确认断言保留 |
| 已失效的配置复制／cwd／跨所有权 watcher 清理 | 删除设施，保留业务断言；实际相对路径、subprocess 和启动配置检查继续保留 |

没有删除既有行为用例。唯一既有节点改名是备用码协议测试。生产外键开启后，修正了 fixture 中父节点、issuer、引用表、调度 actor 的插入顺序。调度 race 的管理事务改在 shortlist 后、reservation 加锁前执行；旧 StaticPool 复用同一连接不能代表两个真实事务。未关闭外键或放宽业务断言。

## 验证

环境：Windows、Python 3.15.0rc2、pytest 9.1.1、pytest-asyncio 1.4.0、pytest-timeout 2.4.0；使用 `uv run --locked`。Ruff 仅通过 pre-commit hooks 执行。

首次 pytest 前已运行仓库快照脚本。开发数据库在实施前后 SHA256 均为：

```text
5BC7DD0F2B41AD441A31A004B5C07813B80C88D0B8AF4F924BE3C3C7A82C4F10
```

| 检查 | 结果 | pytest 报告耗时 |
| --- | --- | ---: |
| 修复前代表性基线：入场控制、内存限流、配置隔离生命周期 | 15 passed | 0.52s |
| 新客户端期限、入场控制、配置隔离及配置读取 | 25 passed | 1.51s |
| 搜索、服务器失败清理、严格收集规则单独组合 | 29 passed | 9.08s |
| 最终 unit 选择器 | 649 passed | 5.68s |
| 最终 component 选择器 | 868 passed、1 skipped、2 warnings | 48.98s |
| 最终 integration 选择器 | 271 passed、41 skipped | 139.40s |
| 完整套件 | 1,788 passed、42 skipped、2 warnings | 174.44s |
| OIDC／备用码 component 与 start unit 反转执行顺序 | 42 passed，未启动服务器 | 1.29s |

未测量修复前完整套件，不能由窄基线推断总耗时改善；也没有声称覆盖率或长期偶发失败率已改善。各层与完整结果的 JUnit 见本地 `test-results/`。这些运行产物被忽略，不作为源码提交。

最后的后端 engine 清理收尾后，五个受影响模块再次验证：56 passed、27 因未配置服务 URL 而 skipped。九个创建点均立即登记清理，无重复 dispose；17 个生命周期故障探针再次通过。此收尾涉及的外部 SQL 场景仍需要真实服务验证。

严格控制回归验证了有效三层选择，以及缺失／冲突层级、unit/component 间接依赖服务器、未知标记和未知配置的失败退出。文件传输最初两个过时替身不接受新 `timeout` 参数，已改用真实 AsyncStream；该文件单独 11 项通过，随后完整套件通过。

| 仅在内存中的故障注入 | 实际失败位置与结果 |
| --- | --- |
| 第二页删除为零项 | 搜索尾页 `len(items) == 2` 失败；原实际返回两项 |
| 排序删除一项，剩余结果仍有序 | 完整 A/B/C 名称顺序断言失败 |
| 省略 OIDC nonce 拒绝 | wrong-nonce 场景因 200 != 401 失败 |
| 省略备用码 commit | 首次 verify 仍成功，新 Session 的剩余 hash 数量断言失败 |
| 三处容量竞争工作线程抛异常 | Future 在 call 阶段传播原 RuntimeError，三个探针 0.26s 结束 |
| 外部数据库测试的 setup／清库失败，使用实际 pytest finalizer 与临时 SQLite | 17 个回收探针验证 dispose 与 DBAPI 连接关闭；仅验证生命周期，不替代真实后端 SQL 测试 |

探针均恢复内存补丁。两个搜索探针的客户端已断开、服务进程已结束、临时目录已删除；反转顺序运行捕获的 32 个 SQLite engine 均已释放。既有启动失败、日志线程启动失败、配置隔离及开发文件保护测试继续通过。

## 外部验证边界

42 个 skip 明确包括：MySQL 17、PostgreSQL 10、Redis 13、S3 1，以及 Windows 上的非 Windows 文件行为分支 1。两条 warning 是既有 Alembic 对表达式索引反射的 SQLAlchemy 警告，未被过滤。

本机没有配置外部服务 URL。尝试启动已安装的 Docker Desktop 时，Docker 自身在 `dockerInference` socket 初始化报文件访问错误，Linux engine 没有启动；本次启动的进程已结束，Docker 服务仍为原来的 stopped 状态。没有重置或修改 Docker 安装。

因此真实 Redis、MySQL、PostgreSQL、S3 及 Linux 发布包 smoke **尚未在本机验收**。必需 Redis/MySQL/PostgreSQL 和平台发布包通道已保留并加强，需在提供对应服务的 CI 上执行；不能将本机可选 skip 当作这些后端已经通过。未执行压力／性能负载，相关工作流继续独立运行。

## 分阶段提交

- `c41679f`：运行配置与客户端期限。
- `9804380`：全量分层、fixture 与资源归属。
- `62c50f9`：搜索、备用码与 OIDC 覆盖；删除用户名源码拼写断言。
- 第四阶段：CI、指南、逐节点索引和本验收记录。
