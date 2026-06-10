# ASys 协议规范
## Agentic System Interface — Specification

> 本文档是 ASys 协议的权威规范。修改任何实现代码前必须先阅读本文档。
> 协议版本：v1.0（`0x0100`）| 最后更新：2026-06-01
> 标注 *(planned)* 的章节已在规范中定义，但不计入协议 v1.0 的承诺范围。

---

## 目录

1. [指令集规范（ISA）](#1-指令集规范isa)
2. [安全模型](#2-安全模型)
3. [协议规范（ASys-APDU）](#3-协议规范asys-apdu)

---

## 1. 指令集规范（Core ISA Specification）

### 1.1 编码空间划分（ISA Addressing）

ASys 以 INS 字节的高位半字节（High Nibble）作为逻辑页索引，严格按 16 条指令为一组进行逻辑隔离，确保协议在数十年演进中保持结构清晰：

| High Nibble | 编码范围 | 分组 | 状态 |
|-------------|----------|------|------|
| `0x0` | `0x00-0x0F` | Core ISA | 已定义指令永久锁定 |
| `0x1` | `0x10-0x1F` | Protocol Control | 协议保留，禁止业务占用（`0x10`=续传帧，`0x11`=TASK_QUERY，`0x12`=TASK_CANCEL） |
| `0x2` | `0x20-0x2F` | Process Control | Standard，写死 |
| `0x3` | `0x30-0x3F` | Network Control | Standard，写死 |
| `0x4` | `0x40-0x4F` | Diagnostics | Standard，写死 |
| `0x5` | `0x50-0x5F` | Storage & Filesystem | Standard，写死 |
| `0x6` | `0x60-0x6F` | Security & Auth | Standard，写死 |
| `0x7` | `0x70-0x7F` | Runtime & Container | Standard，写死 |
| `0x8` | `0x80-0x8F` | Hardware & Energy | Standard，写死 |
| `0x9-0xB` | `0x90-0xBF` | Standard ISA 预留 | 协议组保留，未来新增标准指令组时使用，无需 Major Version |
| `0xC-0xF` | `0xC0-0xFF` | Vendor Extensions | 通过 `Vendor_ID` 无限扩展（4页64槽，Vendor_ID 提供无限命名空间） |

**设计原则**：Core ISA 已定义指令永久锁定。Standard ISA 7页已定义指令语义锁定，空槽可由协议组按需扩充——任何人看到 `0x3x` 永远知道这是 Network Control。需要新标准组时走 Major Version，这是一个值得郑重对待的决定。Standard ISA 预留 `0x90-0xBF` 共 3 页 48 条槽位，供协议组未来扩展新标准指令组，无需 Major Version。Vendor Extensions 占用 `0xC0-0xFF` 共 4 页 64 条指令槽——槽位数量不是瓶颈，因为 `Vendor_ID`（4字节）提供了理论上无限的命名空间，不同厂商可以复用同一 INS 槽，通过 Vendor_ID 区分，互不冲突。

### 1.2 指令集设计原则

- 指令是**动词语义**，不是技术术语（`SVC_RESTART` 而非 `EXEC_SYSTEMCTL`）
- 每条指令映射且仅映射一个原子操作，没有副作用组合
- 所有响应采用**大端序（Big-Endian）**字节流，确保跨平台一致性
- 协议内**严禁浮点数**，所有百分比与负载值通过整数放大表示，由消费端还原
- Vendor Extensions 由各领域管理员自由定义，必须经过 Capability Map 注册方可生效；Standard ISA 由 ASys 协议组定义，语义永久锁定
- **平台中立原则**：ASys 协议的语义指令描述操作意图，不绑定具体实现机制。`asyd` 负责将语义指令映射到宿主平台的原生能力。当前参考实现以 Linux 为目标平台，但协议本身对任何 POSIX 兼容系统开放。当目标平台缺乏实现指令所需的原子原语时，`asyd` 严禁进行模糊模拟，必须返回 `0x6D00`（Instruction Not Supported），将决策权交还给 Agent。

### 1.3 Core ISA 详细定义

Core ISA 是 ASys 协议的宪法级存在。其设计目标是提供 50 年不变的确定性感知原语。`0x00-0x0F` 的指令只读、零副作用，Noise IK 握手完成后即可调用，无需指令级签名。

#### 1.3.1 `0x00 SYS_CAPS`（能力与环境发现）

Agent 的"启蒙"指令——定义了 Agent 能做什么（指令集位图），以及它所处的物理环境边界（静态描述符）。

**调用约定**：连接建立后必须首先调用。Agent 侧应缓存响应结果。若节点能力发生变更或需重新同步权限位图，可随时重新调用以刷新本地缓存。

**响应布局（36 字节）**：

| 字节 | 字段 | 说明 |
|------|------|------|
| `0-7` | Instruction Bitmap | 前 4B 为 Core 位图，后 4B 为 Extended 位图。位为 0 表示该指令在 Agent 视角下物理不存在 |
| `8-9` | Protocol_Version | 如 `0x0100` 表示 v1.0 |
| `10-13` | Kernel_Hash | 4 字节内核版本摘要，用于特性兼容性快速索引 |
| `14-17` | CPU_Static | `[2B 核数] + [2B 架构码]` |
| `18-25` | Memory_Static | `[4B Total_RAM_MB] + [4B Total_Swap_MB]` |
| `26-31` | Storage_Static | `[4B Root_Size_MB] + [2B FS_Type_Code]` |
| `32` | RPI_Type | 压力感知类型：`0x01`=NATIVE_KERNEL（内核原生采样，PSI 级精度），`0x02`=USER_SIMULATED（用户态模拟，Load Average 推算），`0xFF`=NOT_AVAILABLE |
| `33` | Reserved | 预留对齐字节 |
| `34-35` | SW | `0x9000` |

#### 1.3.2 `0x01 SYS_HELLO`（会话建立与对表）

极简的会话建立原语，解决"你是谁"与"现在几点"两个问题。

**响应布局（18 字节）**：

| 字节 | 字段 | 说明 |
|------|------|------|
| `0-3` | Magic | `0x41535953`（ASCII: "ASYS"） |
| `4-7` | Node_UID | 物理机唯一指纹 |
| `8-15` | Server_Timestamp | 纳秒级 Unix Epoch，用于计算 RTT 与时钟偏移 |
| `16-17` | SW | `0x9000` |

#### 1.3.3 `0x02 SYS_STATUS`（实时体征快照）

高频调用（10Hz+）的系统瞬时体征数据，仅包含动态变化的物理量。

**依赖声明**：`Mem_Dyn` 字段仅提供可用值。Agent 必须持有 `SYS_CAPS` 的 `Memory_Static` 基准数据，方可计算准确的内存使用率。

**响应布局（23 字节）**：

| 字节 | 字段 | 说明 |
|------|------|------|
| `0-2` | CPU_Dyn | `[1B 1min负载×10] + [1B 5min负载×10] + [1B 总使用率%]` |
| `3-6` | Mem_Dyn | `[4B Available_MB]` |
| `7-11` | Store_Dyn | `[1B 根分区使用率%] + [4B IO_Wait_ms]` |
| `12-15` | Net_Dyn | `[2B Inbound_Mbps] + [2B Outbound_Mbps]` |
| `16` | RPI | Resource Pressure Index，跨平台归一化压力指数。`0x00`=无压力，`0x64`=资源已导致任务完全阻塞（归一化上限，所有平台统一语义），`0x65-0xFE` 预留，`0xFF`=NOT_SUPPORTED（仅当 `SYS_CAPS.RPI_Type=0xFF` 时出现）。`NATIVE_KERNEL` 和 `USER_SIMULATED` 两种类型均保证返回 `0x00-0x64` 范围内的数值，Agent 应结合 `SYS_CAPS.RPI_Type` 决定触发阈值精度 |
| `17-20` | Reserve | 4 字节对齐填充，预留给未来压力感知扩展字段 |
| `21-22` | SW | `0x9000` |

#### 1.3.4 `0x03 SYS_PROCS`（进程摘要）

用于在系统压力异常时快速定位高负载目标进程。

**响应布局（44 字节）**：

| 字节 | 字段 | 说明 |
|------|------|------|
| `0-1` | Total_Procs | 系统当前总进程数 |
| `2-41` | Top 5 Slots | 5 个进程快照，每个 8 字节（见下表） |
| `42-43` | SW | `0x9000` |

**单个 Slot 内部结构（8 字节）**：

| 字节 | 字段 | 说明 |
|------|------|------|
| `0-3` | PID | 进程 ID。`0x00000000` 表示空 Slot |
| `4-5` | CPU_Usage | 放大 100 倍，精度 0.01% |
| `6` | MEM_Usage | 整数百分比 |
| `7` | Status_Flag | `Bit0`=Zombie，`Bit1`=Unresponsive，`Bit2`=Privileged |

**填充规则**：活跃进程不满 5 个时，空 Slot 的 PID 字段固定填充 `0x00000000`。

### 1.4 Standard ISA 与 Vendor Extensions 概览

**指令层级说明：**

- **Protocol Control**（`0x10-0x1F`）：协议内部控制指令，由 ASys 协议组保留，禁止业务占用；无需指令级签名（`CLA.Sec=00`）
- **Standard ISA**（`0x20-0x8F`）：由 ASys 协议组定义，语义永久锁定，覆盖通用运维场景；需指令级签名（`CLA.Sec=01`）
- **Vendor Extensions**（`0xC0-0xFF`）：由各领域管理员自由定义，通过 Capability Map 注册后生效

**已定义 Standard ISA 指令（有副作用，需指令级签名鉴权）：**

| 指令码 | 名称 | 语义 | 场景 |
|--------|------|------|------|
| `0x20` | `PROC_THROTTLE` | 限制目标进程的资源消耗，实现由平台 `asyd` 决定 | 应急自愈 |
| `0x21` | `NET_ISOLATE` | 隔离目标进程的网络访问，实现由平台 `asyd` 决定 | 应急自愈 |
| `0x22` | `SVC_RESTART` | 重启指定命名服务，实现由平台 `asyd` 决定 | 应急自愈 |
| `0x40` | `LOG_SUMMARY` | 返回高优先级系统事件摘要 | 诊断 |
| `0x41` | `LOG_DETAIL` | 根据 Event_ID 调取具体上下文 | 诊断 |
| `0x42` | `PROC_TREE` | 获取特定进程的父子关系 | 诊断 |
| `0x60` | `AGENT_ADD` | 注册新 Agent 公钥到白名单，能力子集继承（`CLA.Sec=10`） | 身份管理 |
| `0x61` | `AGENT_REMOVE` | 从白名单移除 Agent 公钥（`CLA.Sec=10`） | 身份管理 |
| `0x62` | `AGENT_LIST` | 查询当前白名单摘要（需 `CAP_DELEGATE`） | 身份管理 |

**分类说明**：`NET_ISOLATE`（`0x21`）归入 Process Control 分组而非 Network Control（`0x3x`），原因是其操作对象是**进程**（隔离某进程的网络访问），而非网络基础设施本身。Network Control 分组保留给以网络为操作对象的指令（如防火墙规则、路由操作、端口管理）。

`AGENT_ADD` / `AGENT_REMOVE` / `AGENT_LIST`（`0x60-0x62`）归入 Security & Auth 分组。三条指令共同构成 ASys 的**协议内身份管理体系**——让 Agent 通过协议自主管理其他 Agent 的注册和权限，彻底切断对 SSH 带外操作的依赖。详细设计见 `docs/proposals/agent-auth-model.md`，完整 APDU 布局在后续版本补充。

### 1.4.1 `0x20 PROC_THROTTLE`（进程限速）

暂停或恢复目标进程的执行，执行模式为**同步**（`execution: sync`）——`0x9000` 代表操作已完成，不返回 Task_Handle。

**请求布局：**

| 字段 | 值 | 说明 |
|------|-----|------|
| `CLA` | `0x04` | `Sec=01`（Signed），Standard ISA 强制要求 |
| `INS` | `0x20` | PROC_THROTTLE |
| `P1` | `0x00` | STOP：暂停目标进程（发送 SIGSTOP） |
|      | `0x01` | CONT：恢复目标进程（发送 SIGCONT） |
| `P2` | `0x00` | 保留 |
| `Lc` | `0x08` | Seq(4B) + PID(4B) |
| `Data` | `[Seq(4B BE)][PID(4B BE)]` | Auth_Tag 由 APDU parser 在物理层剥离，不计入 Lc |
| `Le` | `0x00` | 仅返回 SW（Fire-and-forget） |

**响应布局：**

仅返回 2 字节 SW，无 Payload。

| 状态码 | 含义 |
|--------|------|
| `0x9000` | 操作成功（SIGSTOP / SIGCONT 已送达） |
| `0x6700` | Lc 错误（必须为 `0x08`） |
| `0x6982` | 权限不足（`CAP_KILL` 未持有，或目标进程拒绝信号） |
| `0x6A80` | 无效目标（PID=0、进程不存在、或 P1 非法） |
| `0x6F00` | 系统错误（其他 `kill()` 失败） |

**幂等性**：对已暂停的进程再次发送 SIGSTOP 是内核级无操作；对运行中的进程发送 SIGCONT 同样无害。两个方向均满足 §1.5.2 幂等性约束。

**平台实现说明（Linux 参考实现）**：当前以 `SIGSTOP` / `SIGCONT` 实现。相比 cgroup CPU 配额方案，信号方案会完全暂停进程而非限速到某个百分比。生产级实现可升级为 cgroup v2 的 `cpu.max`，语义指令不变，实现由 `asyd` 内部决定，Agent 侧透明。见 `asys-design-notes.md` ADR-19。

### 1.4.2 `0x22 SVC_RESTART`（服务重启）

重启指定命名服务，执行模式为**异步**（`execution: async`）——`0x9000` 代表入队成功，响应 Payload 包含 4 字节 `Task_Handle`，Agent 通过 `0x11 TASK_QUERY` 查询最终结果。

**请求布局：**

| 字段 | 值 | 说明 |
|------|-----|------|
| `CLA` | `0x04` | `Sec=01`（Signed），Standard ISA 强制要求 |
| `INS` | `0x22` | SVC_RESTART |
| `P1` | `0x00` | 保留 |
| `P2` | `0x00` | 保留 |
| `Lc` | `4 + N` | Seq(4B) + N字节服务名（N ≤ 64） |
| `Data` | `[Seq(4B BE)][SvcName(NB)]` | 见下方约束；Auth_Tag 由 APDU parser 在物理层剥离，不计入 Lc |
| `Le` | `0x06` | 期望返回 Task_Handle(4B) + SW(2B) |

**SvcName 约束：**
- 字符集：`[a-z0-9_\-.]`（systemd 服务名合法字符集）
- 最大长度：64 字节
- **不含 `.service` 后缀**，`asyd` 内部自动拼接——从协议层切断路径注入攻击面
- 空字符串或非法字符返回 `0x6A80`（Wrong Data）

**响应布局：**

| 字段 | 长度 | 说明 |
|------|------|------|
| `Task_Handle` | 4B | `[Session_ID(16bit) | Random(16bit)]`，见下方生命周期 |
| `SW` | 2B | `0x9000` = 入队成功 |

**幂等性保证：** 若同一 Session 内对同一 `SvcName` 已有 Pending 状态的 Task_Handle，`asyd` 直接返回已有 Handle，不重复调用 `systemctl`，避免 systemd 单元锁竞争。

### 1.4.3 `0x11 TASK_QUERY`（任务状态查询）

Protocol Control 组指令，`CLA.Sec=00`（无需签名）。Agent 携带 `Task_Handle` 查询异步任务的最终执行结果。

**请求布局：**

| 字段 | 值 | 说明 |
|------|-----|------|
| `CLA` | `0x00` | Plain，无需签名 |
| `INS` | `0x11` | TASK_QUERY |
| `P1` | `0x00` | 保留 |
| `P2` | `0x00` | 保留 |
| `Lc` | `0x04` | Task_Handle 长度 |
| `Data` | `[Task_Handle(4B BE)]` | 由异步指令响应获取 |
| `Le` | `0x03` | 期望返回 Status(1B) + SW(2B) |

**响应布局：**

| 字段 | 长度 | 说明 |
|------|------|------|
| `Status` | 1B | 任务状态码（见下表） |
| `SW` | 2B | `0x9000`（查询本身成功，任务状态通过 Status 表达） |

**Status 状态码：**

| 值 | 含义 | Agent 处理策略 |
|----|------|----------------|
| `0x00` | Pending | 任务执行中，稍后重试 |
| `0x01` | Success | 执行完成，释放 Handle |
| `0x02` | Failed | 执行失败（systemctl 退出码非零），上报告警 |
| `0x03` | Timeout | 超时（默认 30 秒），视为失败 |
| `0x04` | Cancelled | 任务已取消（预留给 `0x12 TASK_CANCEL`） |
| `0xFF` | Handle Not Found | Handle 无效、已过期或不属于当前 Session |

**安全边界**：`asyd` 通过 Handle 高 16 位的 Session_ID 验证归属权——查询不属于当前 Session 的 Handle 一律返回 `0xFF`，不泄露任何任务信息。

**交互时序示例：**

```
1. Agent → asyd: SVC_RESTART("nginx") [Signed, Seq=42]
2. asyd  → Agent: Task_Handle=0x0001AABB, SW=0x9000  (入队成功，fork 已发起)
3. Agent → asyd: TASK_QUERY(0x0001AABB) [Plain]      (3秒后查询)
4. asyd  → Agent: Status=0x01 (Success), SW=0x9000   (systemctl 退出码=0)
   → Handle 释放
```

### 1.4.4 Task_Handle 生命周期

**Handle 结构：** `uint32_t handle = (session_id << 16) | (rand() & 0xFFFF)`

- 高 16 位 Session_ID：用于 O(1) 定位内存池和归属权校验
- 低 16 位随机数：防止攻击者猜测其他 Session 的 Handle

**Handle 释放条件（任一触发）：**
1. `TASK_QUERY` 查询到终态（Success / Failed / Timeout / Cancelled）后立即释放
2. 30 秒超时自动释放（无论是否被查询，无论处于何种状态）——覆盖两种场景：Pending 超时（底层操作无响应）和终态 Handle 未被及时取走（Agent 失联或逻辑卡死）。超时后 `TASK_QUERY` 返回 `Status=0xFF`
3. 所属 Session（TCP 连接）断开时立即释放该 Session 下所有 Handle

**断开不撤销语义：** Handle 失效仅代表"放弃获取结果"，不代表撤销底层操作——`fork/exec systemctl` 一旦发起，其执行过程独立于传输层连接状态，无法中止。Agent 重连后无法获取该次重启的结果。

### 1.5 执行模式与幂等性约束（Execution Mode & Idempotency）

#### 1.5.1 同步与异步执行模式

每条 Standard ISA 指令在定义时必须声明其执行模式：

| 模式 | 标记 | 语义 |
|------|------|------|
| 同步（Sync） | `execution: sync` | `0x9000` 代表指令已执行完成，Agent 可立即信任结果 |
| 异步（Async） | `execution: async` | `0x9000` 代表指令已成功入队，响应 Payload 包含 4 字节 `Task_Handle` |

**异步指令的后续查询**：对于 `execution: async` 的指令，Agent 应使用 Protocol Control 组的 `0x11 TASK_QUERY` 指令，携带 `Task_Handle` 查询该任务的最终执行结果。

**为什么需要区分**：许多 Standard ISA 指令（如 `SVC_RESTART`）在内核层面是异步的——`asyd` 调用平台服务管理器后立即返回，但服务实际启动可能需要数秒甚至失败。若不区分执行模式，Agent 的"感知-决策"闭环会因 `SYS_STATUS` 尚未反映出失败状态而产生误判。

#### 1.5.2 幂等性约束

**所有 Standard ISA 指令在协议层必须声明其幂等性。**

以 `SVC_RESTART` 为例：Agent 因网络抖动重试时，若服务已处于运行状态，第二次调用不应造成额外中断。

实现策略：
- 协议层：每条 Standard ISA 指令的定义中包含 `idempotent: true/false` 标记
- 实现层：`asyd` 在执行前检查系统当前状态，仅在状态不符合预期时才真正执行操作

幂等性约束防止 Agent 在高频重试场景下造成系统状态反复震荡。

### 1.6 状态字规范（SW Status Word Specification）

状态字由 2 字节组成（SW1, SW2），位于每个响应帧的末尾。其作用是让 Agent 能够瞬间判断"是我的指令错了"、"我的权限不够"还是"系统撑不住了"，从而触发不同的自愈逻辑。

所有状态码对齐 ISO/IEC 7816 标准，降低开发者认知负载。

| 状态码 | 语义 | Agent 处理策略 |
|--------|------|----------------|
| `0x9000` | Success | 正常解析 Payload |
| `0x6400` | Execution Blocked | 系统瞬时不可用（缓冲区锁定、自我保护触发等）。执行指数退避重试，区分瞬时失败与永久失败 |
| `0x6982` | Security: Access Denied | Agent 身份合法，但对目标资源越权，操作被拒绝。停止重试，上报安全日志 |
| `0x6985` | Replay Detected | 会话内序列号重放检测（`Seq <= last_seen_seq`）。**收到此码不代表操作失败**——它意味着"该包已被服务端接收过"。SDK 重传场景下的处理策略：同步指令视为已执行成功；异步指令（如 `SVC_RESTART`）应查询最近发起的 Task_Handle 确认状态，而非触发错误处理逻辑。见第2.2.4节 |
| `0x6A80` | Wrong Data | Payload 内部数据非法（如 PID 不存在）。停止该参数的所有重试 |
| `0x6A81` | Instruction Not Found | 指令在 Capability Map 中未注册，物理不存在。触发安全审计，同步权限位图，停止所有尝试 |
| `0x6D00` | Instruction Not Supported | 指令权限存在，但当前内核/硬件不具备执行能力。平滑降级，切换备选指令 |
| `0x6Fxx` | System Emergency | `asyd` 执行层遭遇底层内核错误，低字节 `xx` 携带具体原因码（见下表）。启动熔断机制，上报告警 |

**`0x6Fxx` 子码定义：**

| 状态码 | 对应内核错误 | 语义 |
|--------|------------|------|
| `0x6F00` | 通用系统错误 | `asyd` 内部错误或未分类系统异常 |
| `0x6F01` | `ENOMEM` | 内核内存耗尽，节点处于 OOM 边缘 |
| `0x6F02` | `EIO` | 底层 I/O 错误，存储或设备故障 |
| `0x6F03` | `ENOSPC` | 存储空间耗尽 |
| `0x6F04` | `ETIMEDOUT` | 内核操作超时（如等待设备响应） |
| `0x6F05` | `EBUSY` | 资源被内核锁定，暂时不可用 |
| `0x6FFF` | 未知内核错误 | 无法映射到已知子码，携带原始 errno |

Agent 通过 `0x6Fxx` 的低字节可以区分"协议不支持"（`0x6D00`）与"底层硬件/内核故障"——前者应降级切换指令，后者应上报基础设施告警并暂停对该节点的所有操作。`0x6F01`（ENOMEM）是触发节点急救流程的关键信号。

**`0x6982` 与 `0x6A81` 的关键区别**：

- `0x6A81` 是**物理边界**——指令根本不存在于该 Agent 的视界，触发安全审计
- `0x6982` 是**逻辑边界**——指令存在但操作目标越权，操作被拒绝，触发权限日志
- 前者意味着"我违规了"，后者意味着"环境不允许"

### 1.7 指令分发器拓扑（Instruction Dispatcher）

状态码的触发顺序不只是返回值问题，而是 `asyd` 核心调度引擎的拓扑结构问题。

**核心原则：先定义存在，再验证权力。**

```c
void handle_request(agent_ctx *ctx, apdu_packet *pkt) {
    // 第一道：存在性检查，O(1) 位图比对
    if (!is_instruction_in_bitmap(ctx->cap_map, pkt->ins_code)) {
        send_response(ctx, SW_NOT_FOUND);   // 0x6A81
        return;
    }

    // 第二道：细粒度权限校验
    if (!check_permission(ctx, pkt)) {
        send_response(ctx, SW_ACCESS_DENIED);  // 0x6982
        return;
    }

    // 第三步：完全授权后分发执行
    instruction_handler handler = get_handler(pkt->ins_code);
    handler(ctx, pkt);
}
```

**三个战略优势：**

**1. 极低计算开销**：位图比对（Bitwise AND）是机器码级操作。面对大规模恶意探测时，`asyd` 可在极低 CPU 消耗下拒绝 99% 的非法请求。

**2. 防止侧信道攻击（Side-channel）**：若先查权限再查存在性，攻击者可通过响应时间的微小差异推测哪些指令"存在但被禁用"，从而反推系统能力。先查存在性使所有未授权操作在表现上完全一致，消灭信息泄露面。

**3. 支持多租户隔离（Multi-tenant Isolation）**：不同 Agent 可部署完全不同的指令空间，实现真正的多租户隔离，无需任何额外的权限隔离层。

### 1.8 Vendor 指令规范（Vendor Extension Specification）

#### 1.8.1 自描述指令帧格式

当 `INS >= 0xC0` 时，`asyd` 强制按 Vendor 模式解析。`Vendor_ID`（4 字节）位于 Payload 头部，每条指令完全自描述，无需会话状态切换：

```
[CLA][INS][P1][P2][Lc][Vendor_ID(4B)][Actual_Data][Le]
                       └─ Payload 前4字节强制为 Vendor_ID ─┘
```

`asyd` 分发逻辑：识别到 `INS >= 0xC0` 时，直接读取 Payload 前 4 字节作为 `Vendor_ID`，查询该会话的厂商白名单，定位对应函数表，执行 O(1) 分发。

**无状态保证**：每条 Vendor 指令携带完整的路由信息，网络抖动、包序错乱或重传不影响分发正确性。

#### 1.8.2 Vendor_ID 空间划分

| 范围 | 名称 | 分配方式 |
|------|------|----------|
| `0x00000000-0x000003FF` | 黄金区（1024个） | ASys 官方手动分配，零碰撞保证 |
| `0x00000400-0x0000FFFF` | 注册区 | 申请制，面向核心生态厂商 |
| `0x00010000-0xFFFFFFFF` | 哈希区 | 自助派生：`CRC32("vendor-domain.com") OR 0x00010000` |

**碰撞处理**：Agent 在 `SYS_CAPS` 握手阶段验证节点返回的 Vendor 信息与预期是否一致。若检测到哈希碰撞，拒绝连接并上报。

#### 1.8.3 动态过滤机制

`asyd` 的分发循环在收到 Vendor 指令时，采用**两阶段读取**策略，防止超大 Payload 撑爆内存池：

```c
if (pkt->ins >= 0xC0) {
    if (pkt->lc < 4) {
        send_response(ctx, SW_WRONG_LENGTH);   // 0x6700
        return;
    }
    uint8_t vid_buf[4];
    read_exactly(ctx->conn, vid_buf, 4);
    uint32_t vendor_id = read_u32_be(vid_buf);

    if (!is_vendor_allowed(ctx->vendor_whitelist, vendor_id)) {
        drain_and_discard(ctx->conn, pkt->lc - 4);
        send_response(ctx, SW_ACCESS_DENIED);  // 0x6982
        return;
    }

    read_remaining(ctx->conn, pkt->lc - 4);
    vendor_handler fn = get_vendor_handler(vendor_id, pkt->ins);
    fn(ctx, pkt);
}
```

**安全保证**：只有通过白名单校验的 Vendor 数据才进入内存缓冲区，攻击者无法通过构造超大 Payload 撑爆 `asyd` 的内存池。

**Vendor Payload 内存配额硬限制：**

`asyd` 必须对 Vendor Extensions 的 Payload 大小设置硬性上限，防止大 Payload 与 Core/Standard ISA 的静态内存池产生竞争：

- 标准帧（`CLA.Ext=0`）：Lc ≤ 255 字节，无需额外约束
- 扩展帧（`CLA.Ext=1`）：Vendor Extensions 的 Lc 上限为 **16384 字节（16KB）**，超出返回 `0x6700`（Wrong Length）

Vendor Extensions 的 Payload 必须在**独立的有界内存区**中读取和处理，不得复用 Core/Standard ISA 的静态 APDU 缓冲池。两者物理隔离，确保 Vendor 扩展的内存压力不影响核心指令的执行路径。具体实现参见 `impl-notes.md` 第1.3节。

### 1.9 协议演进准则（Evolutionary Principles）

以下准则是对所有未来 ASys 实现者和协议维护者的强制性约束，确保协议在数十年演进中保持向后兼容性。

**准则一：偏移量不变性（Offset Immutability）**

除非发生大版本跃迁（Major Version Bump），否则任何 Core ISA 指令的现有字段偏移量不得修改。新增字段只能占用 Reserve 空间或在响应末尾（SW 之前）扩展。

**准则二：静默忽略原则（Silent Ignore）**

Agent 必须能够安全忽略响应中未定义的 Reserve 字段；服务端必须能够忽略请求中未定义的填充位。任何一方不得因遇到未知字段而中断连接或返回错误。这是协议向前兼容的基础。

**准则三：原子化替代（Atomic Replacement）**

若某项核心指标失效（如旧内核不再支持某字段），服务端应填充预定义的哨兵值（`0xFF` 或 `0x0000` 视字段类型而定），而非删除该字段或缩短响应长度。响应的字节总长度在同一协议版本内永远不变。

**准则四：大版本跃迁准则（Major Version Transition）**

当确实需要打破偏移量不变性时，必须通过 `SYS_CAPS` 响应中的 `Protocol_Version` 字段（字节 8-9）声明新版本号。旧版本服务端必须继续支持旧格式响应，至少持续一个完整的大版本周期，以保障 Agent 的平滑迁移窗口。

---

## 2. 安全模型

ASys 的安全架构分为四层，从传输到执行形成纵深防御。

### 2.1 传输安全：Noise Protocol IK

ASys 放弃依赖 PKI 证书体系的 mTLS，采用 **Noise Protocol Pattern IK** 作为传输层安全机制。其核心优势是零证书依赖、纯密码学原语（Curve25519 + ChaCha20-Poly1305 + BLAKE2b），在任何 POSIX 兼容系统上均可通过单一纯 C 库实现。

**前向安全性边界**：Noise IK 的会话密钥由 Initiator 临时密钥（`e`）参与派生，每次握手独立生成，服务端静态私钥泄露**不能解密历史会话内容**。已知局限是握手消息中 Agent 静态公钥经服务端静态公钥加密传输——静态私钥泄露后，历史握手包中的 Agent 身份（静态公钥）理论上可被还原。这是 IK 模式为换取 1-RTT 握手和握手早期身份验证所做的已知权衡，不是实现缺陷。后续版本计划引入 Rekey 机制，周期性刷新会话密钥，进一步收窄静态密钥泄露的影响窗口。

#### 2.1.1 服务端密钥管理（asyd 节点侧）

`asyd` 首次启动时自动生成密钥材料，存储于 `/etc/asyd/`：

```
/etc/asyd/                   # 权限 0700，owner: root（生产）
├── id_curve25519            # Curve25519 静态私钥，权限 0600，永不离开节点
├── id_curve25519.pub        # Curve25519 静态公钥，权限 0644，由 asyd 在握手前通过 Pre-Handshake Frame 主动推送
└── authorized_agents        # Agent 公钥白名单，每行一条 hex 公钥，管理员手动维护
```

类比 SSH host key 的管理方式——私钥不离节点，公钥由 `asyd` 在连接建立时主动推送给 Agent（见第3.3.0节 Pre-Handshake Frame），无需带外分发。

**一台机器，一个身份**：`id_curve25519` 是节点的身份根基。克隆虚拟机时必须删除此文件，`asyd` 首次启动时会自动生成新密钥对，赋予克隆节点独立身份，防止多节点共享同一公钥指纹导致 Capability Map 冲突。

#### 2.1.2 客户端密钥管理（Agent 侧）

每个 Agent 在初始化时生成自己的 Curve25519 静态密钥对，存储于 `~/.asys/`：

```
~/.asys/                     # 权限 0700
├── id_curve25519       # Curve25519 静态私钥，权限 0600，永不离开 Agent 环境
├── id_curve25519.pub        # Curve25519 静态公钥，权限 0644
└── known_hosts              # 已信任的 asyd 节点公钥指纹记录（类比 SSH known_hosts）
```

**与 SSH 的对比：**

```
SSH                              ASys
────────────────────             ────────────────────
~/.ssh/id_ed25519                ~/.asys/id_curve25519
~/.ssh/id_ed25519.pub            ~/.asys/id_curve25519.pub
~/.ssh/known_hosts               ~/.asys/known_hosts
ssh-keygen                       asys-keygen
~/.ssh/authorized_keys           /etc/asyd/authorized_agents
```

**`known_hosts` 格式**：每行一条记录，空格分隔：

```
# <host>:<port>  <server_pub_key_hex_64chars>
192.168.0.217:7816  <server-public-key-hex>
10.0.1.42:7816      <server-public-key-hex>
```

**大规模部署的意义**：1000 个 Agent，每个在初始化时各自运行 `asys-keygen` 生成独立身份，管理员将 Agent 公钥写入每个节点的 `/etc/asyd/authorized_agents`，之后 Agent 自动凭密钥连接。管理员只需维护 `authorized_agents`——和管理 SSH `authorized_keys` 完全相同的心智模型。

#### 2.1.3 Agent 身份验证

`asyd` 采用**公钥白名单**模式：握手完成后，检查 Agent 静态公钥是否在 `/etc/asyd/authorized_agents` 中，不在则返回 `0x6982` 并断开连接。

**Agent 注册流程：**

1. Agent 运行 `tools/client/asys_keygen.py` 生成 `~/.asys/` 密钥对
2. 管理员将 Agent 公钥写入节点白名单：
   ```bash
   # 直接追加
   echo "<agent_pub_key_hex>" >> /etc/asyd/authorized_agents
   # 或通过 SSH 复制
   cat ~/.asys/id_curve25519.pub | ssh user@host "cat >> /etc/asyd/authorized_agents"
   ```
3. 后续连接 Agent 凭密钥直接握手通过，无需任何额外步骤

**连接流程（v0.3.1 起，Client-Speak-First）：**

1. 客户端发起 TCP 连接
2. **Agent 发送 4 字节 Magic**（`0x41535953`），超时 1 秒，不符则 `asyd` 静默断开
3. **`asyd` 发送 Pre-Handshake Frame（38字节明文）**：`[Magic(4B)][Version(2B)][ServerPubKey(32B)]`
4. 客户端显示服务端公钥指纹，首次确认后写入 `~/.asys/known_hosts`；后续自动比对
5. 客户端完成 **Noise IK 握手**，建立加密通道
6. `asyd` 检查 Agent 公钥是否在白名单，不在则返回 `0x6982`
7. 验证通过，进入业务指令处理

**与 SSH 的类比：**

```
SSH                              ASys
────────────────────             ────────────────────
首次连接显示服务端指纹             首次连接显示服务端公钥指纹
用户确认 → known_hosts            用户确认 → ~/.asys/known_hosts
        ↓                                 ↓
ssh-copy-id 写入公钥              管理员写入 authorized_agents
        ↓                                 ↓
后续公钥免密登录                   后续连接直接握手通过
```

### 2.2 指令安全：CLA 安全报文标记与防重放

#### 2.2.1 CLA 字节安全位（借鉴 ISO 7816 Part 8）

借鉴 ISO 7816 的安全报文机制，CLA 字节的 bit3-2 标记指令的安全级别：

| CLA bit3-2 | 语义 | 适用范围 |
|------------|------|---------|
| `00` | 无额外签名，Noise 通道加密已足够 | Core ISA / Protocol Control |
| `01` | 指令已签名，需验签后执行 | Standard ISA |
| `10` | 指令已加密+签名，高敏感操作 | Vendor ISA / Security 组 |
| `11` | 预留 | — |

`asyd` 在解析 APDU 帧头时即可根据 CLA 决定验签路径，无需读取 Payload——验签发生在任何业务逻辑之前。

#### 2.2.2 安全帧 Data 段布局

当 `CLA bit3-2 = 01` 或 `10` 时，`Data` 段布局强制如下：

```
Data = [Seq(4B BE)] + [Payload]
```

| 偏移（Data 段） | 长度 | 字段 | 说明 |
|----------------|------|------|------|
| `+0` | 4 | `Seq` | 32位大端序递增序列号，会话内从1开始，必须大于 `Last_Seen_Seq` |
| `+4` | Lc-4 | `Payload` | 指令业务数据 |

最小 `Lc = 0x04`（4字节：仅 Seq，无业务数据）。Auth_Tag 不在 Data 段内，附加在报文物理末尾（`Le` 字段之后），不计入 `Lc`（见第3.1.2节）。

**注意**：`Epoch_ID` 不在帧中传输，由双方从 Noise IK 握手密钥独立派生（见第2.2.3节），仅参与 Auth Tag 计算。

#### 2.2.3 指令签名算法（Auth Tag）

**Epoch_ID 派生（握手后立即执行）：**

```
Epoch_ID = HMAC-BLAKE2b(recv_key, "asys-epoch-v1")[:4]
```

- `Epoch_ID` 从 Noise IK 握手密钥派生，**不在网络上传输**，双方独立计算结果相同
- 每次握手产生唯一的 `Epoch_ID`，不同会话的 `Epoch_ID` 不同，跨会话重放密码学失效
- 服务端在 `noise_ik_write_msg2()` 返回后立即派生，存入 SessionCtx

**算法定义：**

```
Auth_Tag = HMAC-BLAKE2b(recv_key, CLA || INS || P1 || P2 || Lc || Epoch_ID || Seq || Payload)[:16]
```

- `recv_key`：Noise IK 握手后 Agent 发送方向的会话密钥（即 `asyd` 的 recv_key）
- `Epoch_ID`：4字节，从 recv_key 派生，混入 HMAC 保证跨会话重放密码学失效
- 签名覆盖完整 5 字节 Header + Epoch_ID + Seq + Payload，任何字段被篡改均导致验签失败
- 取前 16 字节与 Auth Tag 占位长度对齐，不改变帧格式

**验签流程（asyd 侧）：**

```
1. 检查 frame->sec != PLAIN，Plain 帧跳过验签
2. 提取字段：Header(5B)、Epoch_ID(4B，从 SessionCtx 读取)、Seq(4B)、Payload、Auth_Tag(16B)
3. 计算 Expected_Tag = HMAC-BLAKE2b(recv_key, Header||Epoch_ID||Seq||Payload)[:16]
4. crypto_verify16(Expected_Tag, Received_Tag)  ← 常量时间比较，防时序攻击
5. 验签失败 → 返回 0x6982，断开连接（安全事件）
6. 验签通过 → 检查 Seq > last_seen_seq（SessionCtx 内存），否则返回 0x6985
7. 更新 last_seen_seq，执行指令
```

**常量时间比较（强制要求）：**

必须使用 `crypto_verify16()`（Monocypher 内置），严禁使用 `memcmp()`。`memcmp()` 在发现第一个不匹配字节时提前返回，攻击者可通过响应时间差逐字节推测 Auth Tag。

#### 2.2.4 防重放：Epoch_ID + 会话内递增序列号

ASys 采用 **Epoch_ID + 会话内 Seq** 的双层防重放机制，不依赖磁盘持久化。

**防重放分层：**

| 层次 | 机制 | 防御目标 |
|------|------|---------|
| 跨会话 | `Epoch_ID` 混入 Auth Tag | 截获旧会话的包，在新会话重放 → 验签直接失败（`0x6982`） |
| 会话内 | `last_seen_seq` 内存比较 | 截获当前会话的包，在同一会话重放 → 返回 `0x6985` |

**Seq 语义：**

- Seq 从 1 开始，每次握手重置（不跨会话累积）
- 服务端只在内存维护 `last_seen_seq`（SessionCtx），不持久化到磁盘
- 服务端崩溃重启后，Agent 重连获得新 `Epoch_ID`，Seq 从 1 重新开始，旧包自动失效

**`0x6985` 响应格式：**

标准 2 字节响应：`[SW1=0x69][SW2=0x85]`

收到 `0x6985` 的含义是"该 Seq 已被服务端接收过"，**不代表操作失败**。Agent 和 SDK 必须根据指令类型区分处理：

- **同步指令**（`execution: sync`）：视为已执行成功，效果与收到 `0x9000` 等同
- **异步指令**（`execution: async`，如 `SVC_RESTART`）：上一次发送已被接收，响应包在网络中丢失。SDK 应查询该指令最近发起的 Task_Handle 确认执行状态，而非触发错误处理或告警逻辑

**网络重传场景（最常见触发原因）：**

```
① Agent 发送 SVC_RESTART（Seq=42）
② asyd 执行入队，返回 Task_Handle + 0x9000
③ 响应包在网络中丢失，Agent 未收到
④ SDK 超时重传，再次发送 SVC_RESTART（Seq=42）
⑤ asyd 检测到 Seq=42 已见过，返回 0x6985
⑥ Agent SDK 识别 0x6985 为"已送达"语义，
   查询最近 Task_Handle → 获取执行状态
```

`SVC_RESTART` 的幂等性保证（同 Session 同服务名重复发送返回已有 Handle）与此场景互补：若 `asyd` 在第④步未触发重放检测（Seq 已递增），幂等性保证阻止二次 fork；若触发重放检测（Seq 未变），`0x6985` 语义指引 Agent 去查 Handle，两条路径均不产生额外副作用。

**异常场景处理：**

| 场景 | 行为 |
|------|------|
| 正常断网重连 | 新握手产生新 `Epoch_ID`，Seq 从 1 重新开始，自动通过 |
| 网络重传（Seq 未变） | 返回 `0x6985`，SDK 按指令类型处理（见上） |
| 会话内真实重放 | 同上，`asyd` 侧行为一致，Agent 侧语义相同 |
| 跨会话重放 | `Epoch_ID` 不同，HMAC 验签失败，返回 `0x6982` |
| 服务端崩溃重启 | 内存 Seq 丢失，Agent 重连获得新 `Epoch_ID`，旧包自动失效 |

### 2.3 权限模型：Capability Map

Noise 握手完成、身份确认后，`asyd` 根据 Agent 静态公钥查询对应的 Capability Map。

- **Capability Map**：每个 Agent 身份对应一张指令位图，精确到单条指令的操作权限
- 超出 Capability Map 范围的指令调用返回 `0x6A81`（Instruction Not Found）
- 越权，操作被拒绝，返回 `0x6982`（Access Denied）
- 分发拓扑遵循 1.7 节：存在性检查 → 权限校验 → 执行

> **注**：当前实现使用全局统一位图（`CORE_CAPS_BITMAP` / `EXT_CAPS_BITMAP`），所有通过白名单的 Agent 共享同一指令集。per-Agent 细粒度位图（不同 Agent 持有不同指令权限）计划在后续版本实现。*(planned, not in v1.0)*

#### 2.3.1 权限校验时机：类 POSIX 文件描述符模型

ASys 的权限校验语义与 POSIX `open()` 完全对齐——**入队即授权，授权不追溯**：

| 操作 | 权限校验 | 类比 |
|------|---------|------|
| 新指令入队 | 重新 `check_permission` | `open()` 时校验文件权限 |
| Task_Handle 执行期间 | 不再校验，继续执行 | 已打开的 fd 不受后续 `chmod` 影响 |
| `0x12 TASK_CANCEL` 指令 | 必须持有取消权限，重新校验 | `ioctl/close` 需要有效 fd |

**权限变更的生效点**：仅影响新指令的入队校验，不追溯已获 `Task_Handle` 的运行中任务。若需强制中断，必须通过 `0x12 TASK_CANCEL` 指令显式干预。

### 2.4 三层执行防御

**第一层：语义隔离（Semantic Isolation）**

Agent 操作的是语义指令（`SVC_RESTART`），不是命令字符串。`asyd` 内部维护从语义指令到平台原生调用的固定映射，Agent 无从得知后端实现——命令注入攻击面从设计上被消灭。

**第二层：行为白名单（Behavioral Whitelist）**

对需要传递参数的指令，解析层维护严格的参数约束表，禁止路径穿越、通配符、Shell 元字符等非法输入。

**第三层：资源控制域隔离（Resource Control Domain Sandbox）**

执行 Standard ISA 指令时，操作上下文被严格限制在 Capability 绑定的资源控制域内。Linux 参考实现使用 cgroup/namespace，其他平台由 `asyd` 映射至等效机制。即使前两层同时失效，宿主机仍然安全。

> **注**：本层描述为设计目标，当前版本尚未实现，计划在后续版本实现。*(planned, not in v1.0)*

### 2.5 审计黑匣子（Audit Black Box）

> **注**：本节描述为设计目标，当前版本尚未实现，计划在后续版本实现。*(planned, not in v1.0)*

**所有 APDU 指令流构成不可篡改的操作流水。**

#### 2.5.1 Append-Only 日志

审计日志通过平台机制强制只增：

- Linux：`chattr +a`
- FreeBSD：`flags sappnd`

任何 Agent 指令无法修改或删除已写入的审计记录，即使 Agent 持有高权限。

#### 2.5.2 写前推送时序

审计影子端口的推送必须在指令执行之前或同步完成：

```
1. 记录审计条目（本地 append-only，fsync）
2. 推送到影子端口（可选，见下方模式）
3. 执行指令
4. 记录执行结果
```

**非阻塞写入强制约束：**

审计落盘操作**绝不能同步阻塞执行路径**。在磁盘 I/O 挂起或文件系统只读的极端场景下（恰恰是 `asyd` 作为急救接口被调用的场景），同步等待落盘会导致执行路径死锁——"止血接口"被自己要救的"磁盘挂起"憋死。

强制实现要求：
- 审计写入必须使用**非阻塞 I/O**（`O_NONBLOCK`）或独立写入线程，写入超时上限 **100ms**
- 超时未完成时立即降级为内存环形缓冲区（见第4.2节降级机制），**不阻塞指令执行**
- Core ISA 指令（`0x00-0x0F`）和 Protocol Control 指令（`0x10-0x1F`）的执行路径不得等待任何审计 I/O

具体非阻塞实现参见 `impl-notes.md` 第4节。

**审计模式按指令组划分：**

| 指令范围 | 默认模式 | 说明 |
|---------|---------|------|
| `0x00-0x1F` Core + Protocol | 旁路模式 | 低风险操作，本地审计后即刻执行，异步推送 |
| `0x20-0x8F` Standard ISA | 严格模式 | 推送确认后执行，推送失败返回 `0x6400` |
| `0x90-0xBF` Standard ISA 预留 | 严格模式 | 同上，不可降级为旁路模式 |
| `0xC0-0xFF` Vendor Extensions | 严格模式 | 同上，不可降级为旁路模式 |

管理员可覆盖 Standard ISA 的默认模式，但 Vendor Extensions 的严格模式为强制约束。

推送失败时返回 `0x6400`（Execution Blocked），语义为"Audit Sync Failure"——Agent 应执行指数退避重试，区分审计系统瞬时故障与永久失效。

#### 2.5.3 审计降级与 AUDIT_DEGRADED 标志

当审计日志无法持久化存储时（磁盘满、写入失败等），`asyd` 必须进入降级模式，**所有响应帧须设置 `AUDIT_DEGRADED` 警告标志**，通知 Agent 当前处于降级审计状态。

`asyd` 实现者必须提供至少一种降级机制（如内存缓冲、影子端口转发），确保系统在审计存储失效时仍能维持可感知的运行状态，而非静默失效。具体的分级降级策略参见 `impl-notes.md` 第4节。

**紧急豁免白名单**：管理员可通过启动参数定义紧急豁免指令列表（规划中），这些指令在审计存储完全失败时仍可执行，但必须同步推送到影子端口。

#### 2.5.4 审计记录格式

每条审计记录包含：

```
[Timestamp(8B)][Agent_PubKey_Hash(4B)][INS(1B)][CLA(1B)][Seq(4B)][Param_Digest(4B)][SW(2B)]
合计：24 字节固定长度
```

二进制定长格式，防止文本日志的格式注入，可直接对接 SIEM 系统。

---

## 3. 协议规范（ASys-APDU）

> **部署前提**：ASys 的低延迟优势依赖 `asyd` 独立端口的直连通信（默认 TCP 7816）。受限网络环境下可通过 SSH 隧道承载 ASys 流量，但双层加密与隧道缓冲会显著抵消协议的延迟优势——SSH 隧道是应急兼容模式，不是推荐的生产部署方式。

ASys 借鉴了 ISO/IEC 7816 的 APDU 结构布局，但为优化机机协同效率，对 CLA 字节的位域进行了重新定义，不完全沿用 ISO 7816 的行业分类语义。

### 3.1 帧布局与 CLA 位域

#### 3.1.1 标准帧格式

```
[CLA][INS][P1][P2][Lc][Data][Le]
  1    1    1   1   1   var   1   (bytes)
```

| 字段 | 长度 | 说明 |
|------|------|------|
| `CLA` | 1 byte | 指令类别，位域见下表 |
| `INS` | 1 byte | 指令码（见第1节编码空间） |
| `P1` | 1 byte | 参数1 |
| `P2` | 1 byte | 参数2 |
| `Lc` | 1 byte | Data 段字节数（标准帧，不含 Auth Tag） |
| `Data` | var | 指令数据（含 Seq、Vendor_ID 等安全字段） |
| `Le` | 1 byte | 期望响应长度。`0x01-0xFE`=期望返回 N 字节；`0xFF`=期望返回最大长度（255字节）；`0x00`=仅返回 SW，不期望 Data（Fire-and-forget） |

#### 3.1.2 CLA 字节位域定义

| Bit | 名称 | 语义 |
|-----|------|------|
| `7-5` | Ver | 协议大版本号，当前为 `000`（v1.x） |
| `4` | M | More Data 链式标志。`1`=后续仍有分片，`0`=最后一帧或单帧 |
| `3-2` | Sec | 安全报文标记。`00`=Plain，`01`=Signed，`10`=Enc+Sign，`11`=预留 |
| `1` | Ext | 扩展帧标志。`1`=扩展帧（Lc 后强制跟 2 字节实际长度），`0`=标准帧 |
| `0` | RFU | 预留，固定填 `0` |

**Auth Tag 的位置与 MAC 覆盖范围**：当 `Sec != 00` 时，16 字节 Auth Tag（HMAC-BLAKE2b，见 §2.2.3）**永远附加在整个报文的物理末尾**（`Le` 字段之后），不计入 `Lc`：

```
安全帧：[CLA][INS][P1][P2][Lc][Data][Le][Auth Tag(16B)]
标准帧：[CLA][INS][P1][P2][Lc][Data][Le]
```

MAC 覆盖范围为完整 5 字节 Header（`CLA||INS||P1||P2||Lc`）+ `Epoch_ID`（4B，派生值，不在帧中传输）+ `Seq` + `Payload`，即：

```
HMAC-BLAKE2b(recv_key, CLA||INS||P1||P2||Lc||Epoch_ID||Seq||Payload)[:16]
```

`Le` 字段不计入 MAC 覆盖范围。将 Auth Tag 置于末尾彻底消除 `Le` 字段被篡改导致越界读取的风险，同时实现**零拷贝（Zero-copy）**转发。

### 3.2 长度编码切换

#### 3.2.1 标准帧（Lc ≤ 255 字节）

```
[CLA][INS][P1][P2][Lc(1B)][Data(Lc bytes)][Le(1B)]
```

`Lc` 直接表示 Data 段字节数，最大 255 字节。

#### 3.2.2 扩展帧（CLA.Ext = 1 显式触发）

当 Data 段超过 255 字节时，发送方设置 `CLA bit1 = 1`：

```
[CLA(Ext=1)][INS][P1][P2][0x00][Lc_high][Lc_low][Data][Le_high][Le_low]
```

- `Lc` 字段固定填 `0x00`（占位），实际长度由紧随的 `Lc_high`、`Lc_low` 表示
- 最大 Data 段：65535 字节
- 扩展帧的 `Le` 扩展为 2 字节，`0x0000` 代表"仅返回 SW"

### 3.3 连接建立与认证

#### 3.3.0 Pre-Handshake Frame（连接前服务端身份广播）

**连接建立流程（Client-Speak-First，v0.3.1 起）：**

```
TCP 握手完成
  → Agent 发送 4 字节 Magic（0x41535953）
  → asyd 验证 Magic（超时 1 秒，硬编码）
  → asyd 推送 38 字节 Pre-Handshake Frame
  → Noise IK 握手
```

`asyd` 在 `accept()` 后等待客户端发送 Magic，超时硬编码为 **1 秒**。Magic 不符或超时则立即断开，不推送任何数据。此设计降低了通用端口扫描器触发服务端响应的可能性；连接耗尽攻击的根本防御依赖网络层（建议配合 `iptables` 速率限制）。

TCP 连接建立后、Noise IK 握手前，`asyd` 向 Agent 发送一个 **38 字节明文帧**：

```
[Magic(4B)][Version(2B)][ServerPubKey(32B)]
```

| 字段 | 长度 | 说明 |
|------|------|------|
| `Magic` | 4B | `0x41535953`（ASCII: "ASYS"），防止误连非 ASys 服务 |
| `Version` | 2B | 协议版本号，如 `0x0100` 表示 v1.0，客户端不兼容时应断开 |
| `ServerPubKey` | 32B | 服务端 Curve25519 静态公钥原始字节 |

**客户端处理流程：**

1. 验证 `Magic == 0x41535953`，不匹配则断开（误连非 ASys 端口）
2. 验证 `Version` 兼容性，不兼容则断开
3. 检查 `~/.asys/known_hosts`：
   - 无记录（首次连接）：显示公钥指纹，等待用户确认，写入 `known_hosts`
   - 有记录且匹配：静默继续
   - 有记录但不匹配：打印警告，拒绝连接（防中间人攻击）
4. 用 `ServerPubKey` 作为 Noise IK 的服务端静态公钥，发起握手

**安全说明**：`ServerPubKey` 明文传输没有安全损失——公钥本来就是公开的，安全性依赖于用户确认指纹这一步。这与 SSH 首次连接时服务端明文发送公钥的机制完全一致。

> **SDK 实现强制约束**：第 3 步的"等待用户确认"**不得由 SDK 自动完成**（禁止自动 TOFU）。`known_hosts` 无记录时，SDK 必须中断连接并抛出异常，由调用方决定如何处理首次信任建立。自动写入未确认指纹意味着内网 ARP 欺骗或 DNS 污染即可劫持连接。生产部署推荐通过配置管理工具（Ansible / K8s Secret / Vault）将节点公钥预注入 `known_hosts`，消除首次连接的交互式确认需求。

#### 3.3.1 Noise IK 握手序列

Noise IK 握手在建立 TCP 连接后立即发生，共 2 条消息（1-RTT）：

```
Agent → asyd:  [e, es, s, ss]
                 ↑   ↑  ↑  ↑
                 Agent 临时公钥
                     与 asyd 静态密钥的 DH
                        Agent 静态公钥（加密传输）
                           两个静态密钥的 DH

asyd → Agent:  [e, ee, se]
                 ↑   ↑  ↑
                 asyd 临时公钥
                     两个临时密钥的 DH
                        asyd 静态与 Agent 临时的 DH
```

握手完成后双方各持对称会话密钥，后续所有 APDU 帧均在此加密通道内传输。

**握手首包重放防御（Bloom Filter 去重）**

> **注**：当前版本尚未实现，计划在后续版本实现。*(planned, not in v1.0)*

```c
if (bloom_filter_check(e_pub_hash)) {
    close_connection();  // 沉默丢弃，不分配任何资源
    return;
}
bloom_filter_add(e_pub_hash);
```

**分段式双 Filter（防误判率累积）**

```
维护两个 Filter：Current 和 Previous
查询：Current OR Previous → 有则拒绝（覆盖 2.5~5 分钟窗口）
写入：仅写入 Current
每 2.5 分钟轮换：Previous = Current，Current = 新建空 Filter
```

#### 3.3.2 SYS_HELLO 的 ABANDON_ALL 清理标志

> **注**：当前版本尚未实现，计划在后续版本实现。*(planned, not in v1.0)*

`SYS_HELLO` 的请求 Payload 携带 1 字节 Flags：

```
SYS_HELLO 请求 Payload：
[Client_Timestamp(8B)][Flags(1B)]
                        bit0 = ABANDON_ALL
```

当 `ABANDON_ALL=1` 时，`asyd` 根据 Agent 静态公钥哈希立即释放匹配的僵尸缓冲区，在返回 `0x9000` 之前完成，确保 Agent 重连后第一毫秒即拥有干净的内存环境。

### 3.4 链式传输规范

> **注**：当前版本尚未实现，计划在后续版本实现。*(planned, not in v1.0)*

#### 3.4.1 M 位状态机

```
帧 1：CLA.M=1, INS=target, Lc=65535, Data=[first chunk]
       → asyd 返回 Task_Handle(4B) + SW=0x9000
帧 2：CLA.M=1, INS=0x10, Data=[Task_Handle(4B)][next chunk]
       → asyd 返回 SW=0x9000（继续等待）
帧 N：CLA.M=0, INS=0x10, Data=[Task_Handle(4B)][last chunk]
       → asyd 触发执行，返回最终结果
```

`Task_Handle` 强绑定到原始 Session，内部数据结构参见 `impl-notes.md` 第5节。异步任务的最终状态通过 `0x11 TASK_QUERY` 查询，携带 `Task_Handle` 作为 Payload。

#### 3.4.2 超时与丢包处理

- 默认超时：**30 秒**（规划中通过 `--chain-timeout` 启动参数配置）
- 超时后若 Agent 续传：返回 `0x6A80`（Invalid Handle）

### 3.5 异常处理优先级

| 优先级 | 检查项 | 状态字 |
|--------|--------|--------|
| 1（最高） | CLA 版本不支持 | `0x6E00` |
| 2 | Lc/Le 长度非法 | `0x6700` |
| 3 | Auth Tag 验证失败 | `0x6982` |
| 4 | 序列号重放检测 | `0x6985` |
| 5 | 指令不存在（位图查询） | `0x6A81` |
| 6 | 权限不足 | `0x6982` |
| 7 | 参数非法 | `0x6A80` |
| 8（最低） | 执行层错误 | `0x6Fxx`（低字节携带内核错误子码，见 1.6 节） |

### 3.6 版本协商与迁移

- **CLA.Ver**：每帧携带，`asyd` 据此选择解析路径
- **Protocol_Version**：握手后通过 `SYS_CAPS` 返回

向后兼容策略：旧版本节点收到高版本 CLA.Ver 帧，返回 `0x6E00`，Agent 应降级重试。

### 3.7 字节序与对齐强制规范

**强制大端序（Network Byte Order）**：所有 2B/4B/8B 多字节字段必须采用大端序编码。

**禁止隐式填充（No Implicit Padding）**：所有帧结构在定义时必须手动填充到 4 字节或 8 字节边界，严禁依赖编译器自动对齐。

**验证要求**：测试规范必须包含跨语言字节序验证用例——同一帧由 C 客户端和 Python 客户端分别构造，`asyd` 的解析结果必须完全一致。

---

*本规范随项目演进持续更新。协议版本 v1.0。*
