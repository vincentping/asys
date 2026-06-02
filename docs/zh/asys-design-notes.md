# ASys 架构决策记录（ADR）
## Agentic System Interface — Design Notes

> 本文档记录 ASys 关键设计决策的"为什么"——为什么这样选择，为什么不用其他方案。
> 面向核心贡献者，防止未来重蹈已经踩过的坑。
> 最后更新：2026-05-27

---

## 目录

**协议设计基础**
1. [Why Binary over JSON/Text?](#1-why-binary-over-jsontext)
2. [Why Big-Endian?](#2-why-big-endian)
3. [Why No Floating Point?](#3-why-no-floating-point)
5. [Why APDU Frame Format?](#5-why-apdu-frame-format)
12. [Why High Nibble Paging?](#12-why-high-nibble-paging)
6. [Why Port 7816?](#6-why-port-7816)
28. [Core ISA vs Extensions 的分层类比：USB 协议](#28-core-isa-vs-extensions-的分层类比usb-协议)

**安全架构**
4. [Why Noise IK over mTLS?](#4-why-noise-ik-over-mtls)
7. [Why Monocypher over libsodium/noise-c?](#7-why-monocypher-over-libsodium--noise-c)
9. [Why Public Key Whitelist?](#9-why-public-key-whitelist)
14. [Why HMAC-BLAKE2b over keyed BLAKE2b？](#14-why-hmac-blake2b-over-keyed-blake2b)
16. [Why "Privileged Daemon, Unprivileged Interface"?](#16-why-privileged-daemon-unprivileged-interface)
22. [Pre-Handshake Frame 的 DoS 风险与 Client-Speak-First（v0.3.1 已实现）](#22-pre-handshake-frame-的-dos-风险与-client-speak-first-v031-已实现)
23. [`0x6985` 的网络重传语义：重放检测 vs 已送达确认](#23-0x6985-的网络重传语义重放检测-vs-已送达确认)
24. [Vendor Extensions 的内存边界与静态池隔离](#24-vendor-extensions-的内存边界与静态池隔离)
25. [审计写前推送的非阻塞约束：急救接口不能被磁盘 I/O 阻塞](#25-审计写前推送的非阻塞约束急救接口不能被磁盘-io-阻塞)
26. [云原生弹性场景下的身份管理：已知适用边界](#26-云原生弹性场景下的身份管理已知适用边界)
27. [Task_Handle TTL 与内存回收策略](#27-task_handle-ttl-与内存回收策略)

**实现决策**
8. [Why C over Rust/Go?](#8-why-c-over-rustgo)
10. [Why Static Memory Pool over malloc?](#10-why-static-memory-pool-over-malloc)
11. [Why Instruction Bitmap over ACL?](#11-why-instruction-bitmap-over-acl)
13. [Why Append-Only Audit Log?](#13-why-append-only-audit-log)
17. [Why TCP_NODELAY on Every Accepted Connection?](#17-why-tcp_nodelay-on-every-accepted-connection)
18. [Why Pre-Handshake Frame for Server Identity Broadcast?](#18-why-pre-handshake-frame-for-server-identity-broadcast)
19. [Why SIGSTOP/SIGCONT for PROC_THROTTLE?](#19-why-sigstopsigcont-for-proc_throttle)
20. [Why fork/exec systemctl for SVC_RESTART?](#20-why-forkexec-systemctl-for-svc_restart)
21. [Why Command-Line Arguments over Config File?](#21-why-command-line-arguments-over-config-file)

**跨语言互操作**
15. [Noise IK 跨语言互操作陷阱（C ↔ Python）](#15-noise-ik-跨语言互操作陷阱c--python)

---

## 1. Why Binary over JSON/Text?

**决策**：协议帧采用强类型二进制，不使用 JSON / YAML / XML / 纯文本。

**背景**：AI Agent 调用系统接口时，传统工具（Ansible、SSH）返回的是人类可读的文本输出。Agent 需要通过正则表达式或 LLM 解析这些文本，产生"解析幻觉"风险。

**文本格式的根本问题：**

- **格式漂移**：`ps`、`free`、`df` 等命令的输出格式随发行版、locale 设置、版本更新而变化。一次 Minor Version 升级就可能让 Agent 的正则表达式静默失效。
- **LLM Token 浪费**：Agent 消耗算力解析文本格式，而不是用于决策。在高频采样场景（10Hz+）下，解析开销不可忽视。
- **OOM 边缘行为**：在系统资源耗尽的临界状态下，JSON 解析器可能因无法分配内存而崩溃——而这恰恰是最需要 Agent 介入的时刻。
- **歧义性**：文本是为人类设计的，天然带有歧义。"1.5" 是 CPU 负载还是版本号？上下文决定语义，机器无法可靠判断。

**二进制的优势：**

- **字节偏移永久锁定**：`SYS_STATUS` 的 CPU 负载永远在偏移量 0，无论底层是 RHEL 9 还是 10。Agent 解析逻辑是一行 `struct.unpack`，不是正则表达式。
- **定长结构**：响应的字节总长度在同一协议版本内永远不变（见 `asys-spec.md` 第1.9节准则三），解析无需状态机。
- **零拷贝可行**：二进制定长结构可以直接映射到 C struct，`recv()` 写入的内存即为最终数据，无需中间解析缓冲区。

**结论**：确定性优于易调试性。调试工具（`asys-inspect`）可以在二进制之上构建，但解析幻觉无法在文本协议上消除。

---

## 2. Why Big-Endian?

**决策**：所有多字节字段强制大端序（Network Byte Order），禁止小端序。

**背景**：`asyd` 用 C 实现，SDK 用 Python 和 Elixir 实现，运行在不同字节序的平台上。

**为什么不用小端序（主机字节序）：**

- x86_64 是小端，但 ARM、RISC-V 等平台字节序各异。如果用小端，在非 x86 平台上每个字段都需要字节交换，反而增加了代码复杂度。
- 协议的目标是跨平台一致性，不是为某个特定平台优化。

**为什么选大端序（网络字节序）：**

- 大端序是网络协议的行业标准（TCP/IP、ISO 7816、所有 IETF RFC），整个网络栈生态都默认大端。
- Python 的 `struct.pack('>H', value)`、Elixir 的 `<<value::big-16>>` 都有原生的大端序支持。
- 跨语言互操作性是首要目标：C 客户端和 Python 客户端构造同一帧，`asyd` 解析结果必须完全一致（见 `asys-spec.md` 第3.7节验证要求）。

**性能影响**：在 x86_64 上，`bswap` 指令完成字节交换只需 1 个时钟周期，开销可忽略不计。

**结论**：跨平台一致性优先于单平台性能优化。

---

## 3. Why No Floating Point?

**决策**：协议内严禁浮点数，所有百分比与负载值通过整数放大表示，由消费端还原。

**背景**：系统监控数据（CPU 使用率、负载均值）本质上是有限精度的采样值。

**浮点数的问题：**

- **跨平台精度差异**：IEEE 754 浮点数在不同平台、不同编译器（尤其是优化级别不同时）下，同一计算可能产生微小的精度差异。这对协议的确定性是致命的——同一个值在 C 端和 Python 端序列化后字节不一致。
- **对齐问题**：浮点数（尤其是 `double`）有严格的对齐要求，容易引入隐式填充，违反"禁止隐式填充"原则（见 `asys-spec.md` 第3.7节）。
- **二进制协议不友好**：浮点数有 NaN、Inf、denormal 等特殊值，在定长二进制协议中引入了不必要的复杂性。

**整数放大方案：**

| 字段 | 放大倍数 | 精度 | 还原方式 |
|------|---------|------|---------|
| 负载均值 | ×10 | 0.1 | `value / 10.0` |
| CPU 使用率 | 整数 % | 1% | 直接使用 |
| 进程 CPU Usage | ×100 | 0.01% | `value / 100.0` |
| 网络速率 | 整数 Mbps | 1 Mbps | 直接使用 |

精度完全满足运维监控场景需求。

**结论**：整数放大在系统监控场景完全够用，消除了跨平台浮点精度问题和序列化不一致风险。

---

## 4. Why Noise IK over mTLS?

**决策**：传输安全采用 Noise Protocol Pattern IK，放弃 mTLS。

**背景**：`asyd` 的设计目标是零外部依赖，可在任何 POSIX 系统上运行。

**mTLS 的问题：**

- **PKI 依赖**：mTLS 需要 CA、证书、吊销列表（CRL/OCSP）、证书轮换机制。在边缘节点和嵌入式场景下，维护 PKI 基础设施成本极高。
- **运维复杂度**：证书过期是生产事故的常见原因。`asyd` 作为系统急救接口，不能因证书管理失误而失联。
- **库依赖**：OpenSSL/BoringSSL 是重量级依赖，引入大量代码和潜在漏洞面。

**Noise IK 的优势：**

- **零证书依赖**：纯密码学原语（Curve25519 + ChaCha20-Poly1305 + BLAKE2b），无需 CA，无需证书管理。
- **单文件纯 C 实现**：基于 Monocypher，整个密码学层约 2000 行 C 代码，可审计、无外部依赖。
- **IK 模式天然契合**：IK 模式（Initiator Knows responder's static key）完美匹配 `asyd` 的部署模型——Agent 提前知道节点公钥，握手 1-RTT 完成，比 mTLS 的多次握手更高效。
- **身份绑定**：握手完成后 Agent 静态公钥即为身份标识，直接索引 Capability Map，无需额外的身份层。

**为什么选 IK 而不是其他 Noise 模式（NN、NK、XX）：**

| 模式 | 特点 | 问题 |
|------|------|------|
| NN | 双方匿名 | 无法验证 Agent 身份 |
| NK | 仅服务端有静态公钥 | 客户端匿名，无法做 Capability Map |
| XX | 握手中交换双方公钥，完整前向安全性 | 需要额外 RTT；握手完成前无法验证 Initiator 身份，无法在握手早期拒绝非授权 Agent |
| **IK** | 客户端预知服务端公钥，1-RTT | **完美契合；握手第一消息即可验证 Agent 身份并决定是否继续** |

**前向安全性权衡**：IK 模式的会话内容受 Initiator 临时密钥保护（每次握手独立），静态私钥泄露不暴露历史会话内容。已知局限：握手阶段 Agent 静态公钥（身份）经服务端静态公钥加密，静态私钥泄露后历史握手包中的 Agent 身份可被还原。这是 IK 为换取 1-RTT 和早期身份验证的已知权衡——对 `asyd` 这种需要在握手早期拒绝非授权 Agent 的场景，XX 模式反而是退步。后续版本计划引入 Noise 规范原生支持的 **Rekey 机制**，在长连接期间周期性刷新会话密钥，缩小静态密钥泄露的影响半径。

**结论**：Noise IK 在保证同等安全强度的前提下，大幅降低了实现和运维复杂度，与 ASys 的零依赖设计哲学完全一致。

---

## 5. Why APDU Frame Format?

**决策**：帧格式借鉴 ISO/IEC 7816 APDU（`[CLA][INS][P1][P2][Lc][Data][Le]`），而非设计全新格式。

**背景**：ASys 创始人有智能卡（Smartcard）行业背景，APDU 是经过数十年验证的二进制指令帧格式。

**APDU 的天然契合性：**

- **指令语义天然对齐**：APDU 的设计哲学是"指令 + 参数 + 期望响应长度"，与 ASys 的"原子指令"模型完美契合。`INS` 字节直接对应 ASys 的指令码，`P1/P2` 对应参数，`Le` 对应期望响应长度。
- **状态字（SW）机制**：ISO 7816 的 SW1/SW2 两字节状态字是成熟的错误分类体系，`0x9000` = Success 已是行业惯例，降低开发者认知负载。ASys 在此基础上扩展了 `0x6Fxx` 子码体系。
- **经过实战验证**：全球数十亿张智能卡运行 APDU 协议，其边界条件和安全属性经过了极其严苛的验证。
- **扩展帧支持**：APDU 的扩展帧机制提供了从 255 字节到 65535 字节的平滑扩展路径，ASys 通过 `CLA.Ext` 位显式触发，消除了格式推断的歧义。

**与 ISO 7816 的差异：**

ASys 对 CLA 字节的位域进行了重新定义，不完全沿用 ISO 7816 的行业分类语义（见 `asys-spec.md` 第3.1.2节）。核心是借鉴 APDU 的帧结构和 SW 体系，而不是照搬整个协议。

**结论**：站在巨人肩膀上。APDU 的设计哲学与 ASys 的需求高度契合，数十年的实战验证是最好的安全背书。

---

## 6. Why Port 7816?

**决策**：`asyd` 默认监听 TCP 7816 端口。

**理由：**

- **致敬 ISO 7816**：ASys 的 APDU 帧格式直接借鉴自 ISO/IEC 7816 标准，端口号是对这一技术渊源的显式致敬。
- **社区信号**：7816 向智能卡/安全工程社区传递了明确的技术信号——这不是巧合，是有意为之。懂的人一看端口号就知道这个协议的技术谱系。
- **端口可用性**：7816 在 IANA 注册端口范围（1024-49151）内，未被知名服务占用，不存在端口冲突风险。

---

## 7. Why Monocypher over libsodium / noise-c?

**决策**：密码学原语使用 Monocypher，而非 libsodium 或 noise-c 库。

**背景**：实现 Noise IK 需要 Curve25519、ChaCha20-Poly1305、BLAKE2b 三个密码学原语。

**libsodium 的问题：**

- 需要系统级安装（`dnf install libsodium-devel`），引入外部依赖，违反零依赖设计原则。
- 在没有包管理器的嵌入式/最小化环境中无法使用。

**noise-c 的问题：**

- 完整的 Noise Protocol 框架库，包含大量 ASys 不需要的协议变体。
- 体积较大，编译复杂，不适合嵌入项目。

**Monocypher 的优势：**

- **单文件集成**：只需 `monocypher.c` + `monocypher.h` 两个文件，直接放入 `src/asyd/core/`，零系统依赖。
- **约 2000 行代码**：体积足够小，可以完整审计。
- **覆盖所需原语**：Curve25519（X25519 DH）、ChaCha20-Poly1305（AEAD）、BLAKE2b（哈希/KDF），恰好是 Noise IK 所需的全部。
- **CC0 公有领域**：无版权限制，与 ASys 的开源策略完全兼容。
- **无 libc 依赖**：甚至不依赖 C 标准库，可在极端环境下运行。

**权衡**：我们在 Monocypher 之上自行实现了 Noise IK 状态机（`noise_ik.c`），而不是使用现成的 Noise 框架。这增加了约 300 行代码，但换来了完全的透明性和可控性——每一行密码学逻辑都在我们的代码库中，可审计、可调试。

**结论**：Monocypher 是"刚好够用"的最小化密码学库，完美契合 ASys 的零依赖哲学。

---

## 8. Why C over Rust/Go?

**决策**：`asyd` 参考实现用 C 编写，而非 Rust、Go 或其他现代语言。

**背景**：ASys 的核心设计约束是零运行时依赖，能在任何 POSIX 兼容系统上运行。

**Go 的问题：**

- Go runtime 包含 GC、goroutine 调度器等，二进制体积通常 10MB+。
- GC 暂停会影响响应延迟的确定性，与 ASys 的 < 1ms 目标冲突。

**Rust 的问题：**

- Rust 工具链（rustup、cargo）不是所有 Linux 发行版的标准配置，尤其是老旧的嵌入式系统。
- 虽然 Rust 可以做到零运行时，但编译工具链的安装门槛比 gcc 高得多。

**C 的优势：**

- **普遍可用**：`gcc` 是所有 Linux 发行版的标准配置，`gcc -O2 -pthread asyd.c -o asyd` 一行命令，在任何 POSIX 系统上都能编译。
- **零运行时**：C 程序的运行时就是操作系统本身，没有额外的 runtime 层。
- **静态内存控制**：C 允许完全控制内存布局，实现零 malloc 的静态预分配池。
- **技术谱系一致**：ASys 借鉴智能卡（C）和 POSIX（C），参考实现用 C 是技术谱系的自然延续。

**注**：SDK 层（Python、Elixir）不受此约束，使用最适合 Agent 开发者的语言。C 只是 `asyd` 守护进程的实现语言。

**结论**：C 是实现"零依赖、可在任何 POSIX 系统运行"这一目标的唯一可行选择。

---

## 9. Why Public Key Whitelist？

**决策**：Agent 身份验证采用**公钥白名单**，管理员将 Agent 公钥直接写入 `/etc/asyd/authorized_agents`。

**两个信任方向：**

```
客户端信任服务端：SSH 风格指纹验证
  首次连接 → asyd 发送 Pre-Handshake Frame（38B 明文，含服务端公钥，见第18节）
           → 客户端显示指纹，用户确认后保存到 ~/.asys/known_hosts
  后续连接自动比对 known_hosts，指纹不符则拒绝连接

服务端信任客户端：公钥白名单（连接前预置）
  管理员预先将 Agent 公钥写入 /etc/asyd/authorized_agents
  握手完成后 asyd 检查公钥是否在白名单，不在则返回 0x6982 断开
```

**注册与连接顺序：**

```
1. 管理员将 Agent 公钥写入服务端白名单
   echo "<agent_pub_key_hex>" >> /etc/asyd/authorized_agents
   （或：cat ~/.asys/id_curve25519.pub | ssh user@host "cat >> /etc/asyd/authorized_agents"）

2. Agent 首次连接，确认服务端指纹写入 known_hosts

3. 后续连接直接握手通过
```

**与 SSH 的类比：**

```
SSH                                    ASys
──────────────────────────────         ──────────────────────────────
管理员在服务端写入 authorized_keys      管理员在服务端写入 authorized_agents

客户端首次连接，显示服务端指纹          客户端首次连接，显示服务端公钥指纹
用户确认 → ~/.ssh/known_hosts          用户确认 → ~/.asys/known_hosts

后续连接公钥免密登录                    后续连接直接握手通过
```

---

## 10. Why Static Memory Pool over malloc？

**决策**：`asyd` 核心链路零 malloc，启动时静态预分配所有运行时内存。

**背景**：`asyd` 的核心使命之一是在系统资源耗尽的极端场景下仍能响应——OOM、磁盘 100%、CPU 饱和。

**malloc 在极端场景下的问题：**

- OOM 时 `malloc` 返回 NULL，若未检查则导致空指针解引用崩溃。
- 即使检查了 NULL，运行时内存分配失败意味着无法处理新请求——这恰恰是最需要 Agent 介入的时刻。
- 动态分配导致内存碎片，长期运行后性能不可预测。
- `malloc` 的内存可能被 OS 换出到 swap，在内存压力下引入不确定的延迟。

**静态预分配 + 三角组合：**

```
mlockall(MCL_CURRENT)     → 锁定已分配内存，防止换出到 swap
oom_score_adj = -1000     → OOM Killer 最后才清理 asyd
静态内存池                 → 启动时一次性分配，运行时零 malloc
```

三者缺一不可：
- 只有静态池没有 mlockall：内存仍可能被换出，高压下延迟不确定
- 只有 mlockall 没有静态池：动态分配仍可能在 OOM 时失败
- 只有 oom_score_adj 没有静态池：进程存活但无法处理请求

**APDU_POOL_SIZE 的含义：**

```c
#define APDU_POOL_SIZE 8  // APDU 解析缓冲池大小
```

目前三个相关常量绑定在一起：

```c
LISTEN_BACKLOG  = 8   // 内核 TCP accept 队列
MAX_CLIENTS     = 8   // 同时连接数上限
APDU_POOL_SIZE  = 8   // APDU 解析缓冲池，每连接一个 slot
```

**三个值应该分开配置（TD-07）：**

- `LISTEN_BACKLOG`：内核参数，与并发连接数无关，可以独立设置（建议 16-128）
- `MAX_CLIENTS`：运行时并发连接上限，生产环境可能需要 64+，应支持编译时覆盖
- `APDU_POOL_SIZE`：应等于 `MAX_CLIENTS`，两者绑定即可

当前 `APDU_POOL_SIZE=8` 对开发测试够用，生产环境部署多 Agent 时需要调大。见 `CLAUDE.md` TD-07。

**结论**：静态内存预分配是 `asyd` 作为"系统临终前最后接口"的物理保证，不是性能优化，而是生存能力设计。

---

## 11. Why Instruction Bitmap over ACL？

**决策**：Capability Map 用指令位图（Bitwise AND）而非 ACL 规则表实现权限检查。

**背景**：每个 Agent 身份需要对应一组允许调用的指令集合。实现方式有位图和 ACL 两种主流选择。

**ACL 的问题：**

- O(n) 查找，n 为规则条数。面对大规模恶意探测时 CPU 消耗线性增长。
- 规则表需要解析，存在注入和格式错误风险。
- 规则的"存在性"和"权限"混在一起，难以实现"物理不存在"的语义。

**位图的优势：**

**1. O(1) 查找**：`(bitmap >> ins) & 1` 是单条机器指令，无论指令空间多大，查找时间恒定。

**2. 防侧信道攻击**：
```
错误顺序：先查权限 → 再查存在性
  攻击者可通过响应时间差异推断"存在但被禁用"的指令

正确顺序（ASys）：先查存在性（位图）→ 再查权限
  所有未授权操作响应时间完全一致，消除信息泄露面
```

**3. 多租户隔离**：不同 Agent 持有不同位图，Agent A 的 `0x20` 和 Agent B 的 `0x20` 可以完全不同。这是真正的多租户隔离，无需额外隔离层。（注：当前实现使用全局统一位图，per-Agent 细粒度位图计划在后续版本实现。）

**4. "物理不存在"语义**：位图为 0 的指令对该 Agent 而言字面上不存在，不是"被拒绝"，而是"虚无"。攻击者无从探测系统能力边界。

**结论**：位图是实现"指令级最小权限"和"防侧信道"的最优数据结构，O(1) 查找是额外的性能红利。

---

## 12. Why High Nibble Paging？

**决策**：ISA 编码空间以 INS 字节的高位半字节（High Nibble）作为逻辑页索引，每页 16 条指令。

**背景**：256 个指令槽（0x00-0xFF）需要在 Core ISA、Protocol Control、Standard ISA、Vendor Extensions 之间合理分配。

**为什么用高位半字节（而非其他分法）：**

- **直觉性**：`0x2x` 一眼就知道是 Process Control，`0x3x` 是 Network Control。任何开发者看到指令码就能判断所属分组，无需查表。
- **对齐自然**：16 条指令一组恰好对应一个十六进制位，与人类阅读十六进制的习惯完全一致。
- **扩展空间充足**：每组 16 个槽，目前大部分组只用了 2-3 个，未来有足够的扩展空间。

**编码空间的分配逻辑：**

```
0x00-0x0F  Core ISA（16槽）       → 协议宪法，已定义指令永久锁定
0x10-0x1F  Protocol Control（16槽）→ 协议内部，0x10=续传，0x11=TASK_QUERY，0x12=TASK_CANCEL
0x20-0x8F  Standard ISA（112槽）  → 7个功能组，每组16槽，协议组定义
0x90-0xBF  Standard ISA 预留（48槽）→ 3页，协议组保留，未来新增标准指令组无需 Major Version
0xC0-0xFF  Vendor Extensions（64槽）→ 4页，通过 Vendor_ID 支持无限厂商复用
```

**Vendor 空间的设计哲学**：Vendor Extensions 只需 4 页 64 个 INS 槽，原因是 `Vendor_ID`（4字节）已经提供了理论上无限的命名空间——不同厂商可以复用同一 INS 槽，通过 Vendor_ID 区分，互不冲突。给 Vendor 分配过多 INS 槽是浪费，预留给 Standard ISA 更有价值。

**Standard ISA 预留的意义**：`0x90-0xBF` 的 3 页 48 槽供协议组未来扩展新标准指令组，无需走 Major Version——这是协议长期演进的缓冲区。

**结论**：High Nibble Paging 在可读性、扩展性、治理清晰度三个维度都是最优选择，符合"任何人看到指令码就知道语义"的设计目标。

---

## 13. Why Append-Only Audit Log？

> **注**：本节描述为设计目标，当前版本尚未实现，计划在后续版本实现。

**决策**：审计日志强制 Append-Only（`chattr +a` / `chflags sappnd`），写前推送，24字节定长格式。

**背景**：ASys 的设计哲学之一是"所有 APDU 指令流构成不可篡改的操作流水"——这是 Agent 时代合规审计的基础。

**为什么 Append-Only：**

- Agent 可能持有高权限指令，但不应能修改自己的操作记录。Append-Only 通过文件系统属性强制执行，而非依赖 Agent 的自律。
- 即使 Agent 被攻陷或产生幻觉，历史操作记录仍然完整可查。
- 符合金融、医疗等合规场景的不可篡改审计要求。

**为什么写前推送（先记录后执行）：**

```
错误顺序：执行指令 → 记录审计
  若执行成功但记录失败，操作无法追溯

正确顺序（ASys）：记录审计 → 执行指令
  即使执行失败，审计记录已存在，可回溯"曾经尝试过什么"
```

**为什么 24 字节定长格式：**

```
[Timestamp(8B)][Agent_PubKey_Hash(4B)][INS(1B)][CLA(1B)][Seq(4B)][Param_Digest(4B)][SW(2B)]
```

- **定长**：无需解析器，可直接 `mmap` + 随机访问，SIEM 系统可直接消费。
- **防格式注入**：文本日志可被精心构造的参数内容"污染"，二进制定长格式完全免疫。
- **紧凑**：24 字节/条，4MB 内存缓冲区可容纳约 170,000 条记录，降级场景下的内存缓冲完全够用。

**AUDIT_DEGRADED 标志的设计理由：**

审计系统失效时，`asyd` 不是静默继续运行，而是在每个响应帧上打 AUDIT_DEGRADED 标志——让 Agent 知道当前处于降级审计状态，由 Agent 决定是否继续执行高风险指令。这是"透明失败"而非"静默失败"的设计哲学。

**结论**：Append-Only + 写前推送 + 定长格式共同构成了 ASys 的审计黑匣子，是 Agent 操控系统在合规层面的基础保证。

---

## 14. Why HMAC-BLAKE2b over keyed BLAKE2b？

**决策**：Epoch_ID 派生和 Auth Tag 计算均使用 **HMAC-BLAKE2b**，而非 keyed BLAKE2b 或 HMAC-SHA256。

**背景**：ASys 需要一个带密钥的哈希函数（MAC）用于：
- `Epoch_ID = HMAC-BLAKE2b(recv_key, "asys-epoch-v1")[:4]`
- `Auth_Tag = HMAC-BLAKE2b(recv_key, Header||Epoch_ID||Seq||Payload)[:16]`

最初设计选用了 keyed BLAKE2b（Monocypher 的 `crypto_blake2b_keyed`），但跨平台实现验证暴露了兼容性问题，最终统一为 HMAC-BLAKE2b。

**为什么不用 HMAC-SHA256：**

- `asyd` 的 C 端已经引入 Monocypher，Monocypher 内置 BLAKE2b。如果用 HMAC-SHA256，C 端需要额外引入 SHA256 实现，打破零依赖原则。
- HMAC-BLAKE2b 性能优于 HMAC-SHA256（BLAKE2b 比 SHA256 快约 3 倍）。

**为什么从 keyed BLAKE2b 改为 HMAC-BLAKE2b：**

最初设计用 keyed BLAKE2b，C 端实现简单（`crypto_blake2b_keyed`）。但在 RHEL 上验证 Python 端实现时，发现所有可行路径均被封堵：

| Python 方案 | 结果 | 原因 |
|-------------|------|------|
| `hashlib.blake2b(key=...)` | ❌ | RHEL 的 hashlib 底层是 OpenSSL，不支持 `key=` 参数 |
| `hashlib.blake2b(..., usedforsecurity=False)` | ❌ | RHEL hashlib 完全走 OpenSSL，无内置实现 |
| `pyblake2` 库 | ❌ | 需要 C 编译环境，RHEL 上构建失败 |

**解决方案**：改 C 端而非 Python 端——复用 `noise_ik.c` 中已经实现的 `hmac_blake2b()` 辅助函数，无需引入任何新依赖。Python 端用 `cryptography` 库的 `hmac.HMAC(key, hashes.BLAKE2b(64))` 实现，已在 RHEL 上验证通过。

**附带收益**：HMAC-BLAKE2b 与 Noise IK 的 KDF 使用同一底层函数（`hmac_blake2b()`），整个 `asyd` 的密码学层只有一个 MAC 构造，代码审计面更小。

**教训**：跨平台密码学实现必须在目标平台上实际验证，不能假设标准库 API 在所有发行版上行为一致。RHEL 的 OpenSSL 后端限制是一个真实踩过的坑，在设计阶段无法从文档中预判。

**结论**：HMAC-BLAKE2b 是在"零依赖"、"跨平台兼容"、"算法一致性"三个约束下唯一可行的选择。

---

## 15. Noise IK 跨语言互操作陷阱（C ↔ Python）

> 记录于 2026-03-20。来源：`noise_ik.c` v0.4 与 `noiseprotocol` Python 库的互操作调试。

在 C 实现（Monocypher）与 Python `noiseprotocol` 库之间实现 Noise_IK_25519_ChaChaPoly_BLAKE2b 互操作时，发现三类隐蔽的实现差异。**这些差异在纯 C 单语言测试中全部被抵消，只有跨语言测试才能暴露。**

---

### 陷阱一：HKDF 的 BLAKE2b 构造方式

**症状**：握手密钥协商结果不一致，双方派生出不同的 session key。

**根因**：Noise 协议规范要求 HKDF 使用 HMAC 构造。`noiseprotocol` 库正确使用了 **HMAC-BLAKE2b**（标准 HMAC 构造，block size = 128 字节）。而 Monocypher 提供的是 **keyed BLAKE2b**，两者是不同的密码学构造，输出不同。

```
HMAC-BLAKE2b(key, data) ≠ BLAKE2b-keyed(key, data)
```

**修复**：在 `noise_ik.c` 中实现 `hmac_blake2b()` 辅助函数（block size = 128 字节），替换 `mix_key()` 和 `split()` 中所有 BLAKE2b 调用。

**对社区 SDK 的影响**：如果社区贡献 Elixir SDK，需确认其 Noise 库使用的是 HMAC-BLAKE2b（HMAC 构造，block size = 128 字节），而非 keyed BLAKE2b。任何新语言的 SDK 对接，必须确认其 Noise 库使用的是 HMAC 构造而非 keyed 构造。

---

### 陷阱二：ChaCha20-Poly1305 的变体选择

**症状**：握手和传输层的 AEAD 加解密失败，MAC 验证不通过。

**根因**：Noise 协议规范指定的是 **IETF ChaCha20-Poly1305**（RFC 8439），nonce 为 12 字节（4 字节零填充 + 8 字节小端序计数器）。`noiseprotocol` 库正确实现了此变体。而 Monocypher 的 `crypto_aead_lock` 默认使用 **XChaCha20-Poly1305**，nonce 为 24 字节，是不同的算法。

**修复**：将 `noise_ik.c` 中所有 AEAD 操作从 `crypto_aead_lock` / `crypto_aead_unlock` 替换为 Monocypher 的 `crypto_aead_init_ietf` + `crypto_aead_write` / `crypto_aead_read`。

**对社区 SDK 的影响**：对接任何新语言时，必须确认使用的是 IETF ChaCha20（12 字节 nonce），而非 XChaCha20（24 字节 nonce）或原始 ChaCha20 变体。

---

### 陷阱三：Noise IK 的 DH token 方向与 split 密钥分配

**症状**：纯 C 测试全部通过，但与 Python 互操作时解密失败。两个错误在 C-only 测试中互相抵消，跨语言测试才能暴露。

**根因**：两处 DH 方向错误 + 一处 split 分配错误。

**错误一**：`write_msg2` 中 `se` token 的 DH 计算方向错误。

```c
// 错误：DH(s_priv, re_pub)
// 正确：DH(e_priv, rs_pub)
// Noise 规范：responder 的 se token = server_ephemeral × client_static
```

**错误二**：`read_msg2` 中 `se` token 的 DH 计算方向错误。

```c
// 错误：DH(e_priv, rs_pub)
// 正确：DH(s_priv, re_pub)
// Noise 规范：initiator 的 se token = client_static × server_ephemeral
```

**错误三**：`split()` 的输出密钥分配方向错误。

```c
// Responder (asyd)：output1 → recv_key，output2 → send_key
// Initiator (Agent)：output1 → send_key，output2 → recv_key
// 两端必须镜像分配，否则加解密方向对调
```

**根本教训**：用同一套实现同时扮演 initiator 和 responder 的单语言测试，无法发现对称性错误——错误在双端抵消。**Noise IK 的正确性验证必须包含跨语言或跨实现的互操作测试。**

---

### 检查清单：对接新语言 SDK 时必须验证

新语言 SDK（如 Elixir）对接 `noise_ik.c` 之前，逐项确认：

| 项目 | 要求 | 常见错误 |
|------|------|---------|
| HKDF 构造 | HMAC-BLAKE2b，block size = 128 字节 | 误用 keyed BLAKE2b |
| AEAD 变体 | IETF ChaCha20-Poly1305，nonce = 12 字节 | 误用 XChaCha20（24 字节 nonce） |
| DH token 方向 | 严格按 Noise 规范的 initiator/responder 角色 | 方向对调在单语言测试中抵消 |
| 互操作测试 | 跨语言握手 + 加解密验证，不能只靠单语言自测 | 单语言测试无法发现对称性错误 |

---

## 16. Why "Privileged Daemon, Unprivileged Interface"?

**决策**：`asyd` 采用"特权守护进程，非特权接口"模式——以受限 root 权限运行，但对外只暴露严格对齐的二进制 APDU 接口，不暴露任何 Shell 或脚本执行能力。

**背景**：Standard ISA 副作用指令（`PROC_THROTTLE`、`NET_ISOLATE`、`SVC_RESTART`）需要内核级别的操作能力。这要求 `asyd` 持有一定的特权，但直接运行完整 root 是危险的。

**为什么需要特权：**

| 能力 | 用途 | 对应指令 |
|------|------|---------|
| `CAP_KILL` | 向任意进程发送信号 | `PROC_THROTTLE` |
| `CAP_SYS_RESOURCE` | 调整 OOM 分数、mlockall | OOM 防护 |
| `CAP_NET_ADMIN` | 网络命名空间操作 | `NET_ISOLATE` |
| `CAP_SYS_PTRACE` | 读取 `/proc/<pid>/` 详细信息 | `PROC_TREE` |
| `CAP_DAC_READ_SEARCH` | 读取任意用户的 `/proc/<pid>/stat`、`/proc/<pid>/status` | `SYS_PROCS` |

**为什么不给完整 root：**

完整 root 意味着 `asyd` 被攻陷后攻击者可以加载内核模块、修改硬件驱动、重启系统。通过 Linux Capabilities 机制，可以精确授予上表中的四个能力，明确排除危险能力（`CAP_SYS_MODULE`、`CAP_SYS_RAWIO`、`CAP_SYS_BOOT`）。

**"非特权接口"消解了特权风险：**

`asyd` 持有特权，但对外接口是严格对齐的二进制 APDU 帧，不是 Shell。这意味着：

- **无命令注入面**：Agent 操作的是语义指令（`SVC_RESTART`），不是命令字符串，`asyd` 内部维护从语义指令到平台原生调用的固定映射，Agent 无从注入任何 Shell 元字符。
- **无缓冲区溢出路径**：帧格式在头部显式声明 `Lc`，`asyd` 严格按 `Lc` 读取，物理上不可能读超出声明长度的字节。
- **确定性攻击面**：解析路径是确定的（Deterministic），不存在依赖运行时状态的动态分支，极大降低了通过缓冲区溢出获取 root shell 的风险。

**两种运行模式：**

| 模式 | 权限 | 可用指令集 | 适用场景 |
|------|------|-----------|---------|
| `full` | 受限 root（Capabilities） | Core ISA + Standard ISA | 生产环境 |
| `monitor` | 普通用户 | 仅 Core ISA（观测指令为主，无 Standard ISA 副作用指令） | 受限环境、容器（**规划中，尚未实现**） |

**注**：Core ISA 包含 `SYS_CAPS`、`SYS_HELLO`、`SYS_STATUS`、`SYS_PROCS` 等观测指令（无副作用），以及 Protocol Control 分组的 `TASK_QUERY` 等（无副作用但不是只读系统信息）。"只读零副作用"的说法不够精确，准确表述是"无 Standard ISA 副作用指令"。

`asyd` 启动时自检有效 Capabilities，自动降级并在 `SYS_CAPS` 响应的指令位图中如实反映当前可用指令集。Agent 通过位图感知节点模式，无需额外协议支持。`monitor` 模式计划在后续版本实现。

**与白皮书第3.3节的呼应：**

> "在 ASys 的世界里，Agent 没有'被拒绝'的操作，只有'未定义'的虚无。不存在的操作，便没有攻击面。"

monitor 模式下，Standard ISA 指令在位图中为 0，对 Agent 而言物理不存在，攻击者无法探测。

**"Caged Root" 实现策略：**

与其在"完整 root"和"普通用户"之间二选一，ASys 采用第三条路——**以 root 身份启动，但通过内核机制把 root 的能力边界锁死**：

```ini
User=root                    # 身份是 root，有权执行 SVC_RESTART 等高权指令
CapabilityBoundingSet=...    # 只保留必要能力，危险能力物理不存在
NoNewPrivileges=true         # 即使被攻陷，无法通过 setuid 等手段进一步提权
```

三道锁的协同效果：
- **第一道（CapabilityBoundingSet）**：逻辑权限边界——能做什么
- **第二道（NoNewPrivileges）**：提权通道封死——即使被攻陷也无法逃逸
- **第三道（Seccomp，见 `impl-notes.md` 第9.5节）**：系统调用边界——如何与内核沟通

`fork/exec systemctl` 的子进程继承父进程的受限能力集，`SVC_RESTART` 可以正常执行，同时不存在权限逃逸路径。

**与"特权分离（双进程）"方案的权衡：**

双进程方案（worker + monitor）在理论上隔离性更强，但引入了 IPC 复杂度和额外的进程管理开销。Caged Root 在保持单进程简洁性的同时，通过内核边界实现了同等的安全效果——对于 `asyd` 的威胁模型，这是更合适的权衡。

**结论**：特权是工具，不是目的。Caged Root 策略让 `asyd` 用最小能力完成工作，用确定性二进制接口消解特权风险——这是"受控的后门"与"安全的系统代理"之间的本质区别。

---

## 17. Why TCP_NODELAY on Every Accepted Connection?

**决策**：`asyd` 在每个 `accept()` 后立即对客户端 socket 设置 `TCP_NODELAY`。

**背景**：ASys 的响应帧发送分两次 `send()` 完成——先发 2 字节长度前缀，再发密文 payload。这是"长度前缀 + 密文"协议帧格式的必然结构。

**Nagle 算法的干扰：**

TCP 默认启用 Nagle 算法——当有未确认的小包在途时，内核会缓冲后续数据，等待 ACK 后再一起发送。两次 `send()` 的场景下：

```
send(prefix, 2B)    → 内核发出，等待 ACK
send(enc_buf, NB)   → 内核缓冲，等 ACK 才发
等待时间 = 一个网络 RTT
```

在 loopback（RTT ≈ 0）下看不出来，在真实网络下每帧多出一个 RTT 的等待，完全淹没缓存命中效果。

**语言惯用写法导致的不对称性：**

相同的协议设计，不同语言的惯用写法产生了不同的行为——这是一个值得警惕的教训：

```python
# Python 客户端（send_apdu）：天然合并，无 Nagle 问题
ciphertext = noise.encrypt(plaintext)
prefix = struct.pack('>H', len(ciphertext))
sock.sendall(prefix + ciphertext)   # 字符串拼接是 Python 惯用法，一次发送
```

```c
/* C 服务端（asyd.c）：两次 send，触发 Nagle */
send(ctx->fd, prefix, 2, 0);          // 先发 2 字节前缀
send(ctx->fd, enc_buf, enc_len, 0);   // 再发 payload，内核等待 ACK
```

Python 开发者拼字符串是天然操作，无意中规避了 Nagle 问题；C 开发者写两次 `send()` 也是天然操作，却触发了 40ms 的等待。**同一个协议设计，不同语言的惯用写法导致了截然不同的性能表现，且在 loopback 测试中完全不可见。**

**实测数据（修复前后对比，Windows → RHEL VM，ping RTT < 1ms）：**

| 场景 | 修复前 | 修复后 |
|------|--------|--------|
| SYS_STATUS 缓存命中 | ~40ms | < 1ms |
| SYS_STATUS 冷采样 | ~90ms | ~51ms |
| SYS_PROCS | ~45ms | ~6ms |

**为什么不合并两次 send()：**

合并需要将 prefix 和 enc_buf 拷贝到一个新缓冲区，引入额外内存拷贝，违反零拷贝设计原则。`TCP_NODELAY` 一行解决问题，无任何副作用。

**修复：**

```c
/* accept() 后立即设置，禁用 Nagle 算法 */
int flag = 1;
setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
```

**对未来实现者的警告：**

任何 `asyd` 的移植实现（Rust、Go、Elixir），只要采用"长度前缀 + payload"的分帧发送模式，都必须禁用 Nagle 算法。此问题在 loopback 测试中完全不可见，只有跨真实网络测试才能暴露。**如果移植语言的惯用写法是合并发送（如 Python 的字符串拼接、Elixir 的 `IO.binwrite`），则天然规避此问题；如果是分次发送（如 C 的两次 `send()`），则必须显式禁用 Nagle。**

**结论**：协议帧结构决定了必须禁用 Nagle 算法。这不是优化选项，而是正确性要求。

---

## 18. Why Pre-Handshake Frame for Server Identity Broadcast?

**决策**：TCP 连接建立后、Noise IK 握手前，`asyd` 主动向客户端发送一个 38 字节明文帧（`[Magic(4B)][Version(2B)][ServerPubKey(32B)]`），客户端据此完成指纹验证和 `known_hosts` 管理，然后才进行 Noise IK 握手。

**背景**：Noise IK 模式（IK = Initiator Knows responder's static key）要求客户端在握手前就知道服务端公钥。最初的实现要求用户手动从 RHEL 节点上 `xxd` 出公钥指纹，粘贴到命令行：

```bash
python3 client_core_isa.py <64-hex-pubkey> <host> 7816
```

这个体验很差，且不符合"比 SSH 更简单"的设计目标——ASys 没有用户名和密码，理应比 SSH 更简洁。

**为什么不改用 Noise XX：**

Noise XX 模式在握手过程中交换双方公钥，客户端无需预先知道服务端公钥。但代价是：

- `noise_ik.c` 需要完全重写，工作量大
- 已经踩过三个跨语言互操作坑（HKDF 构造、AEAD 变体、DH 方向），XX 重新来一遍同样的风险
- XX 比 IK 多一个 RTT（2-RTT vs 1-RTT）

**为什么不在握手中加 SYS_HELLO 帧：**

有建议在服务端发送公钥时顺带使用 `SYS_HELLO (0x01)` 帧格式。这违反协议分层原则——`SYS_HELLO` 是 Core ISA 业务指令，属于加密通道内的指令层，不应出现在握手前的明文传输阶段。语义污染会让 `SYS_HELLO` 在两个不同上下文里有两种含义，增加解析复杂度。

**Pre-Handshake Frame 的设计：**

独立的 38 字节定长结构，不使用 APDU 格式：

```
[Magic(4B): 0x41535953]["ASYS"][Version(2B)][ServerPubKey(32B)]
```

- `Magic` 防止误连非 ASys 端口（比如误连到 SSH 或其他服务）
- `Version` 实现握手前版本协商，不兼容时客户端可以在浪费一次 Noise IK 握手之前就断开
- `ServerPubKey` 是客户端发起 Noise IK 握手所必需的输入

**安全性分析：**

服务端公钥明文传输没有安全损失——公钥本来就是公开的，不需要保密。安全性依赖于用户确认指纹这一步（`known_hosts` 机制）。这与 SSH 的安全模型完全一致：SSH 也是首次连接时明文发送服务端公钥，让用户确认指纹后写入 `~/.ssh/known_hosts`。

客户端公钥的保护不受影响——它仍然在 Noise IK msg1 中加密传输，与原来完全相同。

**用户体验对比：**

```
改动前：
python3 client_core_isa.py <64-hex-pubkey> <host> 7816   ← 需要带外获取公钥

改动后：
python3 client_core_isa.py <host> 7816                   ← 和 SSH 一样简洁
→ asyd 主动发送公钥
→ 显示指纹，用户确认
→ 写入 known_hosts，后续自动验证
```

**结论**：Pre-Handshake Frame 以极小的实现代价（`asyd.c` 增加一行 `send()`，`noise_ik.c` 完全不动）实现了与 SSH 完全对齐的用户体验，同时保持了协议分层的清晰边界。

---

## 19. Why SIGSTOP/SIGCONT for PROC_THROTTLE?

**决策**：`PROC_THROTTLE`（`0x20`）当前实现使用 `SIGSTOP/SIGCONT`，而非 cgroup CPU throttle。

**两种方案对比：**

| | SIGSTOP/SIGCONT | cgroup CPU throttle |
|---|---|---|
| Capability | `CAP_KILL` | `CAP_SYS_RESOURCE` |
| 效果 | 完全暂停进程 | 限制 CPU 配额，进程继续运行 |
| 副作用 | 粗暴，可能破坏进程内部状态 | 优雅，进程感知不到 |
| 回滚 | `SIGCONT` 即可 | 删除 cgroup 配置 |
| 实现复杂度 | 极简（一行 `kill()`） | 需操作 cgroup v2 文件系统 |
| Demo 视觉效果 | CPU 立即归零，直观 | CPU 逐渐下降，效果不明显 |

**为什么当前选 SIGSTOP：**

- 当前目标是完成 OODA 闭环 demo，SIGSTOP 实现极简，demo 录制时 CPU 立即归零，视觉冲击力强。
- 已持有 `CAP_KILL`，无需额外 Capability。
- 协议语义（`PROC_THROTTLE` = 限制资源消耗）允许实现选择——SIGSTOP 是合法的平台映射，不违反规范。

**后续演进路径：**

cgroup CPU throttle 是生产级的正确实现——进程不感知、副作用可控、回滚干净。OODA 闭环 demo 跑通后，可将实现升级为 cgroup v2 的 `cpu.max` 配置，对外协议接口完全不变。

**结论**：先用 SIGSTOP 跑通闭环，再用 cgroup 做生产加固。两步走，不反工。

---

## 20. Why fork/exec systemctl for SVC_RESTART?

**决策**：`SVC_RESTART`（`0x22`）使用 `fork/exec systemctl` 与 systemd 交互，而非直接调用 D-Bus API。

**两种方案对比：**

| | fork/exec systemctl | D-Bus API |
|---|---|---|
| 外部依赖 | 无（systemctl 是系统标配） | 需要 libdbus 或 sd-bus |
| 零依赖原则 | 符合 | 违反 |
| 实现复杂度 | 简单 | 高（D-Bus 协议复杂） |
| 内存影响 | fork 后子进程独立，父进程不受影响 | 在进程内直接调用，无额外进程 |
| 错误处理 | 通过子进程退出码判断 | 通过 D-Bus 返回值判断 |

**关于"零 malloc"原则的边界：**

`fork` 发生在请求处理路径的边缘——`asyd` fork 后立即 exec，子进程独立运行，父进程不等待、不持有子进程内存引用。这是"零 malloc"原则的边界案例，不是核心违反。零 malloc 的目标是防止在高压场景下动态分配失败，`fork/exec` 的子进程内存与父进程完全隔离，不影响 `asyd` 主进程的内存确定性。

**为什么不用 D-Bus：**

引入 `libdbus` 或 `sd-bus` 会破坏 ASys 的零外部依赖设计原则。`asyd` 的核心价值之一是"在任何 POSIX 系统上 `gcc -O2 asyd.c -o asyd` 一行编译"——D-Bus 依赖破坏了这个承诺。

**Zombie 进程处理：**

"父进程不等待"并不意味着可以忽略子进程回收——未被 `wait()` 回收的子进程会变成 zombie，占用 PID 表项，直到 `asyd` 退出。三种处理方案：

| 方案 | 机制 | 是否阻塞请求路径 | 复杂度 |
|------|------|----------------|--------|
| `waitpid()` 阻塞等待 | 父进程等待子进程退出 | 是（不可用） | 低 |
| `SIGCHLD` 设为 `SIG_IGN` | 内核自动回收僵尸进程 | 否 | 极低 |
| double-fork | 让 init 接管孙进程 | 否 | 高 |

**修正：不能使用 `SIGCHLD = SIG_IGN`**

`SVC_RESTART` 需要知道 `systemctl` 的退出码（成功=0，失败≠0），才能将 Task_Handle 状态更新为 `Success(0x01)` 或 `Failed(0x02)`。`SIG_IGN` 让内核自动回收子进程，但同时丢失了退出码——无法区分重启成功还是失败，Task_Handle 永远停在 Pending 状态。

**选择：注册 SIGCHLD handler，非阻塞回收**

```c
/* asyd 初始化阶段 */
signal(SIGCHLD, sigchld_handler);

/* SIGCHLD 处理函数：循环非阻塞回收所有已退出子进程 */
static void sigchld_handler(int sig) {
    (void)sig;
    int status;
    pid_t pid;
    /* WNOHANG：非阻塞，立即返回，不阻塞请求路径 */
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        /* 根据 pid 查 task_pool，更新对应 Handle 状态 */
        int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        task_pool_update_by_pid(pid, exit_code == 0 ? TASK_SUCCESS : TASK_FAILED);
    }
}
```

**为什么 WNOHANG 不阻塞请求路径：** `waitpid(-1, &status, WNOHANG)` 立即返回，不等待子进程退出。handler 在信号递达时被异步调用，不占用 dispatch 线程。

**结论**：`fork/exec systemctl` 在保持零依赖的前提下完成任务。SIGCHLD handler + WNOHANG 在不阻塞请求路径的同时精准捕获退出码，是子进程回收与状态追踪的唯一正确方案。

---

## 21. Why Command-Line Arguments over Config File?

**决策**：`asyd` 的运行时参数通过命令行参数传入，不提供独立的配置文件（如 INI/TOML）。

**背景**：`asyd` 作为系统级 daemon，部署后需要允许管理员调整监听端口、绑定地址、运行模式等参数，而无需重新编译。

**配置文件的问题：**

- **引入解析器代码**：任何格式的配置文件（INI、TOML、JSON）都需要解析器，违反零依赖哲学——解析器本身是代码，是潜在的攻击面。
- **冗余的配置层**：`asyd` 的标准部署方式是 systemd unit，systemd 本身就是配置管理层。`ExecStart` 即是配置文件，修改参数就是修改 unit 文件，管理员工具链（`systemctl edit`、`systemctl daemon-reload`）已经覆盖这个场景。
- **热重载的局限性**：端口和绑定地址的变更必须重启 daemon（重新 `bind()`），配置文件 + SIGHUP 热重载对这类参数没有意义。真正需要热重载的（白名单）已通过 SIGHUP 单独处理。

**命令行参数的优势：**

- **零解析器**：`getopt_long` 是 POSIX 标准库，不引入任何外部依赖。
- **systemd 原生集成**：`ExecStart=/usr/local/bin/asyd --port 8816 --listen 127.0.0.1` 即完成配置，符合 Linux 服务管理惯例。
- **参数数量可控**：当前可配置项少（≤ 6 个），命令行完全够用。

**当前支持的参数：**

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--port <n>` | 7816 | 监听端口 |
| `--listen <addr>` | 0.0.0.0 | 绑定地址 |
| `--debug` | off | 前台运行 + stderr 详细日志 |

**未来扩展预留：**

若后续可配置项超过 6 个，或出现"分组配置"需求（如按指令类别设置超时），可在届时引入配置文件支持。命令行参数与配置文件并不互斥——当前阶段命令行足够，不提前过度设计。

**结论**：命令行参数在当前参数规模下是最简方案，与 systemd 部署模型原生契合，零额外代码，符合 ASys 的零依赖设计哲学。

---

## 22. Pre-Handshake Frame 的 DoS 风险与 Client-Speak-First（v0.3.1 已实现）

**背景**：v0.3.0 的初始设计中，TCP 连接建立后 `asyd` 立即主动推送 38 字节 Pre-Handshake Frame（Server-Speak-First）。这一机制在功能上解决了密钥分发问题，但引入了两个已知的安全风险。v0.3.1 采纳了本节的改进方向，实现了 Client-Speak-First。

**风险一：端口扫描触发出向流量**

任何扫描器只要完成 TCP 三次握手，`asyd` 就会主动发送 38 字节响应。虽然 38 字节本身不构成放大攻击（响应未远大于请求），但 Server-Speak-First 打破了防火墙的默认防御状态——扫描者无需发送任何应用层数据即可触发服务端响应，增加了被动暴露面。

**风险二：并发未完成握手消耗 CPU**

攻击者可以发起大量 TCP 连接并推进到 Noise IK 握手第一阶段（发送 `[e, es, s, ss]`），迫使 `asyd` 执行 Curve25519 点乘。在 `asyd` 作为"系统临终急救接口"的定位下，CPU 被握手计算耗尽与被 OOM 耗尽同样危险。

**现有缓解**

`MAX_CLIENTS=8` 的静态连接池是天然的限流机制——超出上限的连接在 `accept()` 层面排队，不会无限消耗握手计算资源。当前风险在静态连接池的保护下是可控的。

**改进方向：Client-Speak-First**

代价最低的改进方案：Agent 在 TCP 连接后先发送 4 字节 Magic（`0x41535953`），`asyd` 验证通过后再推送 Pre-Handshake Frame。

```
当前（Server-Speak-First）：
  TCP 握手完成 → asyd 立即推送 Pre-Handshake Frame（38B）

改进后（Client-Speak-First）：
  TCP 握手完成 → Agent 发送 Magic（4B）→ asyd 验证 → 推送 Pre-Handshake Frame（38B）
```

**等待 Magic 的超时：硬编码 1 秒**

`asyd` 在 `accept()` 后等待 Magic 的超时硬编码为 **1 秒**，不暴露为启动参数。推导依据：

- 合法 Agent 发送 4 字节 Magic 是内存操作，耗时微秒级；即使广域网延迟 200ms 也远在 1 秒内
- `asyd` 的主要部署场景是本地或近端网络（同一 DC / VPC），高延迟广域网不是目标场景
- 没有合理的生产场景需要把这个值调成 2 秒或 500ms，暴露参数只增加配置负担
- 与 60 秒的会话空闲超时相比，1 秒显著缩短了无效连接占用槽位的时间

**防御边界的诚实说明**

Client-Speak-First 的真实价值是**降低单次连接的 CPU 和 I/O 开销**：
- **通用端口扫描器**（不了解 ASys 协议的）无法触发任何响应——这是主要防御目标
- 了解协议的攻击者可以发送正确 Magic，但 Noise IK 握手的 CPU 消耗仍受 `MAX_CLIENTS` 限流
- **连接耗尽攻击**（不停建立 TCP 连接）两种方案都无法从应用层完全防御，根本防御依赖网络层：建议部署时配合 `iptables` 对 7816 端口设置单 IP 连接速率限制，并启用 `net.ipv4.tcp_syncookies=1`

**关于 WireGuard Cookie/Puzzle 机制**

WireGuard 的 Cookie 机制（高负载时要求客户端先解哈希拼图）是更完善的防御，但引入了额外的协议状态和实现复杂度，与 ASys 的极简设计哲学有冲突。在 `MAX_CLIENTS` 静态连接池已提供基础限流的前提下，暂不采纳。

**结论**：Client-Speak-First 改进成本极低，降低了无效连接的资源消耗；连接耗尽的根本防御在网络层，不在协议层。

## 23. `0x6985` 的网络重传语义：重放检测 vs 已送达确认

**背景**：`0x6985`（Replay Detected）的设计初衷是拦截会话内序列号重放攻击。但在实际部署中，触发 `0x6985` 最常见的场景不是攻击，而是**网络层重传**——响应包丢失后 SDK 自动重发同一 Seq 的指令包。

**问题**：原始规范对 `0x6985` 的 Agent 处理策略描述不足，仅说明"Seq 回绕时重新递增"。若 SDK 将 `0x6985` 当作错误处理（如触发告警或将节点标记为异常），会产生错误的自愈逻辑——而指令实际上已被 `asyd` 成功接收。

**具体场景（异步指令）：**

```
① Agent 发送 SVC_RESTART（Seq=42）
② asyd 入队成功，返回 Task_Handle + 0x9000
③ 响应包网络丢失，Agent 未收到
④ SDK 超时重传，再次发送 SVC_RESTART（Seq=42）
⑤ asyd 检测 Seq=42 已见过，返回 0x6985
⑥ SDK 若误判为"操作失败" → 触发不必要的告警或节点下线
   SDK 若正确处理为"已送达" → 查 Task_Handle → 获取执行结果
```

**设计决策：`0x6985` 的语义修订**

`0x6985` 的语义从"重放攻击拦截"扩展为**"该 Seq 已被服务端处理过"**——无论触发原因是攻击重放还是网络重传，服务端侧行为一致，Agent 侧语义也应一致：

- **同步指令**：视为已执行成功，等同于收到 `0x9000`
- **异步指令**：上次发送已被接收，查询最近 Task_Handle 确认状态

**为什么不引入新状态码（如 `0x9001 TASK_ALREADY_RUNNING`）：**

引入新状态码需要 Agent 在重传时携带业务上下文（如 SvcName）才能让 `asyd` 返回对应 Handle，增加了协议复杂度。而 `SVC_RESTART` 的幂等性保证（同 Session 同服务名重复调用返回已有 Handle）已经覆盖了业务层的重复调用场景。两个机制组合，已能完整处理重传场景，无需新状态码。

**与幂等性保证的互补关系：**

| 场景 | 触发机制 | 结果 |
|------|---------|------|
| SDK 重传，Seq 未变 | `0x6985` 拦截 | Agent 查已有 Handle |
| SDK 重传，Seq 已递增 | 幂等性保证 | `asyd` 返回已有 Handle，不重复 fork |
| 真实重放攻击，Seq 未变 | `0x6985` 拦截 | 同网络重传，攻击者无法区分 |

两条路径均不产生额外副作用。

**规范更新**：已在 `asys-spec.md` §1.6 状态字表和 §2.2.4 防重放节更新 `0x6985` 的 Agent 处理策略。

## 24. Vendor Extensions 的内存边界与静态池隔离

**背景**：Core ISA 和 Standard ISA 的响应均为定长结构，静态 APDU 缓冲池大小可精确预算。但 Vendor Extensions 支持扩展帧（最大 65535 字节），动态 Payload 深度与静态内存池存在张力。

**问题**：若 Vendor 扩展的大 Payload 与 Core/Standard ISA 共用静态池：
- Vendor 扩展的内存压力可能挤占核心指令的缓冲区
- 极端场景下（大 Payload Vendor 指令并发），Core ISA 的"急救"能力受损
- 两阶段读取已防止未授权 Payload 进入内存，但授权后的大 Payload 落在哪里规范原先未明确

**决策：物理隔离 + Payload 硬上限**

1. **Vendor Extensions 使用独立内存区**，不复用 Core/Standard ISA 的静态 APDU 池
2. **Vendor Payload 硬上限 16KB**（扩展帧 Lc > 16384 返回 `0x6700`）——足够传输复杂业务数据（SQL 脚本、BGP 配置），同时防止内存失控
3. **Vendor 池满返回 `0x6400`**（Execution Blocked），不影响 Core/Standard ISA 路径

**为什么是 16KB 而非更大：**

16KB 可以容纳绝大多数运维场景的业务 Payload（一段 SQL、一份路由配置、一个 Shell 脚本片段）。需要传输更大数据的场景应使用链式传输（`CLA.M=1`）分片，而不是单帧超大 Payload——这也是更安全的设计，每片独立鉴权。

**结论**：两层隔离（独立内存池 + Payload 硬上限）确保 Vendor 扩展的任何行为不能影响 Core ISA 的急救能力。

---

## 25. 审计写前推送的非阻塞约束：急救接口不能被磁盘 I/O 阻塞

**背景**：ASys 的审计设计要求"写前推送"——先落盘审计记录，再执行指令。这在正常场景下保证了操作可追溯性。

**矛盾**：`asyd` 的核心使命之一是在磁盘 I/O 100% 挂起时仍然作为急救接口。若审计落盘同步阻塞执行路径，`PROC_THROTTLE` 等止血指令会在等待审计写入时死锁——急救接口被自己要救的故障场景憋死。

**决策：审计写入强制非阻塞**

- 审计写入通过独立线程或 `O_NONBLOCK` 实现，写入超时上限 **100ms**
- 超时后立即降级为内存环形缓冲区，**不阻塞指令执行**
- Core ISA（`0x00-0x0F`）和 Protocol Control（`0x10-0x1F`）的执行路径只允许调用无锁的 `audit_ring_push()`，不得等待任何磁盘 I/O

**"写前推送"原则的修订**：

原始语义"先落盘，再执行"在极端场景下不可行。修订为：**先入审计队列（内存），再执行；审计队列异步持久化到磁盘**。"写前"的保证是"写入内存队列"而非"写入磁盘"——在磁盘失效的降级状态下，内存环形缓冲区是审计的临时载体，`AUDIT_DEGRADED` 标志通知 Agent 当前处于降级审计状态。

**结论**：非阻塞审计是"急救接口"定位的必要条件，不是可选优化。

---

## 26. 云原生弹性场景下的身份管理：已知适用边界

**背景**：ASys v0.3.0 的身份模型要求每台机器持有独立的 Curve25519 密钥对，Agent 首次连接时确认服务端指纹写入 `known_hosts`，管理员将 Agent 公钥写入 `authorized_agents`。

**已知局限**：这一模型在以下场景下运维负担较重：

- **K8s / 公有云高频弹性**：节点生命周期可能只有数分钟，每次扩容都产生新密钥，Agent 侧 `known_hosts` 和服务端 `authorized_agents` 需要频繁同步
- **万级节点初始化**：批量部署时，公钥注册的自动化程度决定了运维成本

**为什么不引入 CA 签名信任链**：

引入 CA（即使是自签名企业 CA）会重新引入 mTLS 放弃的那些问题：证书管理、吊销机制、证书轮换。这与 ADR-4 选择 Noise IK 的核心理由直接冲突——"asyd 作为系统急救接口，不能因证书管理失误而失联"。在急救接口的设计优先级下，运维便利性不能以引入证书依赖为代价。

**务实的改进方向（不引入 CA）**：

- **节点启动脚本自动化**：云原生部署中，节点启动时自动运行 `asys-keygen`，将公钥推送到中心化密钥管理服务（如 Vault、etcd），管理员维护的是密钥管理服务而非每个节点的 `authorized_agents`
- **Agent 侧 `known_hosts` 自动化**：通过部署脚本在 Agent 启动时预填充 `known_hosts`，而非依赖首次连接的交互式确认
- **SIGHUP 批量热重载**：编排层（Ansible、K8s DaemonSet）统一下发 `authorized_agents` 更新并触发热重载

**结论**：ASys v0.3.0 的身份模型适合长期稳定运行的节点（物理机、长生命周期 VM）。高频弹性云原生场景是已知的适用边界，改进方向是自动化运维脚本，而非引入证书体系。

**SDK 实现层的强制约束**：无论部署场景如何，SDK 实现**严禁自动 TOFU**（自动信任并写入未经确认的指纹）。`known_hosts` 无记录时 SDK 必须抛出异常，由调用方决定信任建立方式。这是协议层无法在握手字节层面强制、但文档层必须明确的安全边界——自动 TOFU 的 SDK 会将 Pre-Handshake Frame 的明文公钥传输从"设计合理的安全机制"变为"中间人攻击的入口"。

---

## 27. Task_Handle TTL 与内存回收策略

**背景**：`asyd` 采用静态内存预分配（`task_pool` 固定槽位数），Task_Handle 对应池中一个槽位。若槽位无法及时回收，静态池耗尽后新的异步指令将返回 `0x6400`（Execution Blocked）。

**需要回收的两类场景：**

1. **Pending 超时**：底层操作（如 `systemctl restart`）无响应，子进程长时间不退出。若不强制超时，槽位永久占用。
2. **终态 Handle 未被取走**：`asyd` 已记录 Success/Failed，但 Agent 因幻觉、网络中断或逻辑卡死而从未发送 `TASK_QUERY`。连接仍然存活（TCP keepalive 维持），但槽位永远不会被条件 1（查询到终态）触发释放。

**决策：统一 30 秒 TTL，覆盖所有状态**

选择统一 TTL（而非分状态 TTL）的理由：

- **实现简单**：`task_pool_sweep_timeouts()` 只需比较 `time(NULL) - created_at > 30`，一个条件覆盖所有状态，无需状态机分支
- **语义清晰**：Agent 有 30 秒窗口来查询任何终态 Handle；30 秒对任何正常轮询策略都绰绰有余（建议轮询间隔 1-3 秒）
- **静态池保护**：30 秒 × 最大并发任务数 = 静态池峰值占用上限，可精确计算

**为什么选 30 秒而非更短或更长：**

- `SVC_RESTART` 的执行超时本身是 30 秒（`TASK_TIMEOUT` 在 30 秒后触发），TTL 与执行超时对齐意味着"入队后 60 秒内（执行 30 秒 + 结果等待 30 秒）Agent 必须取走结果"——这是合理的端到端 SLA
- 更短（如 5 秒）可能在高延迟网络中导致 Agent 正常轮询时 Handle 已过期
- 更长（如 300 秒）会在 Agent 失联场景下长时间占用静态池槽位

**Session 断开时立即回收（优先于 TTL）：**

TCP 断开是最强的"Agent 已失联"信号。Session 断开时 `task_pool_release_session(session_id)` 立即清零该 Session 下所有槽位（无论状态），无需等待 TTL。这是最常见的资源回收路径，覆盖了绝大多数 Agent 失联场景。

**`0xFF` 的统一语义：**

Handle 过期（TTL 触发）、Session 不匹配、Handle 从未存在——三种情况统一返回 `Status=0xFF`（Not Found），不区分具体原因，不泄露槽位状态信息。

**结论**：30 秒统一 TTL + Session 断开立即回收，两条路径互补，确保静态内存池在任何 Agent 行为（正常、失联、幻觉）下都能及时回收，不依赖 Agent 的主动配合。

---

## 28. Core ISA vs Extensions 的分层类比：USB 协议

Core ISA 之于 Standard ISA + Vendor Extensions，如同 USB 核心协议之于设备描述符——USB 的电源管理、握手和枚举逻辑是永恒不变的核心；而连接的是鼠标、硬盘还是显卡，由各自的设备描述符决定。这保证了任何主机（Agent）插上任何设备（Node）都能第一时间握手成功，同时不限制设备的功能边界。

USB 的枚举（Enumeration）与描述符（Descriptor）机制和 ASys 的 `SYS_CAPS` 握手过程几乎是同构的：主机无需预知设备类型，只需通过标准握手读取描述符，即可理解设备能力并加载对应驱动。这正是 ASys 希望 Agent 与节点之间建立的关系。

---

*本文档持续补充，每个重大设计决策都应在此留档。*