# ASys — Agentic System Interface

> AI Agent 的二进制系统接口协议 —
> 端口 7816，零 Shell 解析，确定性语义。

[English](README.md) | 中文 

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/vincentping/asys)](https://github.com/vincentping/asys/releases/latest)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://github.com/vincentping/asys)

---

## 目录

- [为什么做 ASys](#为什么做-asys)
- [架构](#架构)
- [指令集](#指令集)
- [快速开始](#快速开始)
- [安全模型](#安全模型)
- [文档](#文档)
- [Changelog](#changelog)

---

## 为什么做 ASys

SSH 是为人类设计的。Agent 不需要终端。

当 AI Agent 通过 SSH 执行 `ps aux | grep nginx`，它拿到的是自由文本——格式因 OS、locale 和工具版本而异，Agent 还得自己解析。但当 Agent 调用 ASys 的 `SYS_PROCS` 指令，拿到的是固定的 44 字节二进制帧：进程总数、top-5 PID、CPU%、内存%、状态标志——类型明确，无歧义，在每个节点上都一样。

ASys 是一个实验：如果从头设计一个专门给 AI Agent 用的系统接口，会是什么样？二进制帧替代文本，长连接替代每命令建连，指令级能力授权替代宽泛的 SSH 访问，内置审计日志替代 shell history。

它不是 SSH、Ansible 或 Kubernetes operator 的替代品——这些工具服务它们本来的用户（人类和编排流水线）很好。ASys 是另一个选项：当操作者是 AI Agent，你想要一个从头为此设计的接口。

它也不是 MCP 的替代品。MCP 标准化的是 Agent 如何调用*工具*，ASys 则是工具用来抵达*操作系统*的那一层——一个 MCP server 完全可以用 ASys 作为它的系统后端。

如需了解完整的设计 rationale 以及 ASys 在 Agent 基础设施中的定位，请从[**白皮书**](docs/zh/asys-whitepaper.md)开始阅读。

---

## 架构

```
AI Agent (LLM)
     │
     │  Tool calls
     ▼
Python SDK  (~/.asys/id_curve25519)
     │
     │  Noise_IK_25519_ChaChaPoly_BLAKE2b
     │  TCP 端口 7816
     ▼
asyd  (C daemon，零外部依赖)
     │
     │  POSIX syscalls
     ▼
Linux
```

---

## 指令集

### Core ISA（0x00–0x0F）— 只读，零副作用

| INS  | 名称       | 响应 | 描述                                              |
|------|------------|------|---------------------------------------------------|
| 0x00 | SYS_CAPS   | 36B  | 静态能力：CPU、RAM、磁盘、ISA bitmap              |
| 0x01 | SYS_HELLO  | 18B  | 节点 UID + 纳秒级时间戳                           |
| 0x02 | SYS_STATUS | 23B  | 负载均值、CPU%、可用 RAM、磁盘、网络、RPI         |
| 0x03 | SYS_PROCS  | 44B  | 进程总数 + CPU 占用前 5（PID、CPU%、MEM%）        |

### 协议控制（0x10–0x1F）

| INS  | 名称       | 响应 | 描述                                  |
|------|------------|------|---------------------------------------|
| 0x11 | TASK_QUERY | 3B   | 通过 Task_Handle 轮询异步任务状态     |

### Standard ISA — 进程控制（0x20–0x2F）— 签名，需要提升权限

| INS  | 名称          | 响应    | 描述                                       |
|------|---------------|---------|--------------------------------------------|
| 0x20 | PROC_THROTTLE | SW only | 通过 PID 对进程执行 SIGSTOP / SIGCONT      |
| 0x21 | NET_ISOLATE   | —       | 隔离进程网络访问 *(规划中)*                |
| 0x22 | SVC_RESTART   | 6B      | 重启指定 systemd 服务（异步）              |

**实测 RTT**（Noise IK 加密，RHEL on VirtualBox，Windows Python 客户端）：

| 指令          | RTT             | 备注                                            |
|---------------|-----------------|-------------------------------------------------|
| SYS_HELLO     | < 1ms           |                                                 |
| SYS_CAPS      | < 1ms           | 无缓存；静态数据在启动时读取一次                |
| SYS_STATUS    | < 1ms / ~51ms   | 缓存命中 / 冷采样（50ms CPU 双采样）            |
| SYS_PROCS     | ~6ms / ~200ms   | 热调用；首次调用阻塞 200ms 冷采样              |
| PROC_THROTTLE | ~200µs dispatch |                                                 |
| SVC_RESTART   | ~200µs dispatch | 异步；通过 TASK_QUERY 轮询结果                 |

---

## 快速开始

### 前置条件

- Linux（RHEL/Fedora/Ubuntu/Debian），x86_64
- `gcc`、`make`
- Python 3.8+，`pip install noiseprotocol cryptography`（仅客户端需要）

### 编译并运行

```bash
git clone https://github.com/vincentping/asys
cd asys
make
sudo bin/asyd
```

`asyd` 监听 TCP 7816。首次启动时在 `/etc/asyd/id_curve25519` 生成密钥对。

**选项：**

| 选项              | 默认值  | 描述                             |
|-------------------|---------|----------------------------------|
| `--port <n>`      | 7816    | TCP 监听端口                     |
| `--listen <addr>` | 0.0.0.0 | 绑定地址                         |
| `--debug`         | off     | 前台运行，向 stderr 输出详细日志 |
| `--version`       | —       | 打印版本号并退出                 |
| `--help`          | —       | 打印用法并退出                   |

```bash
# 示例：自定义端口，仅本地监听
sudo bin/asyd --port 8816 --listen 127.0.0.1

# 示例：debug 模式（前台，详细日志）
sudo bin/asyd --debug
```

### 注册 Agent

```bash
# 在客户端机器上——生成 Agent 身份
python3 tools/client/asys_keygen.py

# 在服务端——将 Agent 公钥添加到白名单
echo "<pubkey_hex>" | sudo tee -a /etc/asyd/authorized_agents
```

Agent 公钥由 `asys_keygen.py` 打印。同时在 `~/.asys/id_curve25519` 生成客户端密钥对，用于 Noise IK 握手。不在 `/etc/asyd/authorized_agents` 中的 Agent 连接将被拒绝，返回 SW=0x6982。

首次连接时，客户端会提示确认服务端公钥指纹并保存到 `~/.asys/known_hosts`——详见下文[首次连接](#首次连接)。

不重启 daemon 重载白名单（不影响已有连接）：

```bash
sudo kill -HUP $(pidof asyd)
```

### 首次连接

首次连接时，客户端显示服务端公钥指纹：

```
ASys server fingerprint (SHA256): a3:f1:2c:...
Connect to localhost:7816? [yes/no]: yes
Fingerprint saved to ~/.asys/known_hosts
```

后续连接自动验证指纹。指纹不匹配则中止连接——与 SSH `known_hosts` 机制相同。

### 运行示例

所有客户端脚本可在任意机器（包括 Windows）上运行，通过网络连接远程 `asyd`。无 SSH，无 Shell，加密通道上的签名二进制指令。

#### 1. Core ISA — 验证完整连接栈

连接 `asyd`，完成 Noise IK 握手，然后依次执行全部四条 Core ISA 指令（SYS_CAPS、SYS_HELLO、SYS_STATUS、SYS_PROCS），并运行缓存时序测试。

```bash
python3 examples/client_core_isa.py <server-ip>
```

```
ASys Test Client  —  localhost:7816
====================================================
Connected to localhost:7816
Handshake OK

── SYS_CAPS (0x00) ─────────────────────────────────
  Core bitmap:      0x0002000F  active=['0x00', '0x01', '0x02', '0x03', '0x11']
  Ext  bitmap:      0x00000005
  Protocol:         v1.0
  Kernel hash:      0x06060057
  CPUs:             8  arch=x86_64
  RAM:              15660 MB   swap=4096 MB
  Root partition:   1031018 MB   fs=ext4
  RPI type:         NATIVE_KERNEL (PSI)
  SW:          0x9000  OK

── SYS_HELLO (0x01) ────────────────────────────────
  Magic:            'ASYS'
  Node UID:         0xFCAB032F
  Server timestamp: 1779912196.304 s  (1779912196304227300 ns)
  RTT:              0.28 ms
  SW:          0x9000  OK

── SYS_STATUS (0x02) ───────────────────────────────
  Load avg:         1m=0.0  5m=0.0
  CPU usage:        0%
  Mem available:    14540 MB
  Root disk:        0% used   IO wait=0 ms
  Network:          in=0 Mbps   out=0 Mbps
  RPI:              0/100
  RTT:              51.05 ms
  SW:          0x9000  OK

── SYS_PROCS (0x03) ────────────────────────────────
  Total processes:  48
  Top 5 by CPU (lifetime share):
    [0] PID=5964    CPU=   0.07%  MEM=  0%  flags=Privileged
    [1] PID=433     CPU=   0.05%  MEM=  0%  flags=Zombie
    [2] PID=1       CPU=   0.02%  MEM=  0%  flags=Privileged
    [3] PID=6       CPU=   0.00%  MEM=  0%  flags=Privileged
    [4] PID=80      CPU=   0.00%  MEM=  0%  flags=Privileged
  RTT:              2.87 ms
  SW:          0x9000  OK

── Cache Timing Test ───────────────────────────────
   6 rounds, 200ms interval
   #       SYS_STATUS     SYS_PROCS
   ────  ────────────  ────────────
   0           0.61ms        2.52ms
   1           0.85ms        2.92ms
   2           0.95ms        2.47ms
   3          52.25ms        2.68ms
   4           0.95ms        2.68ms
   5           1.21ms        2.70ms

====================================================
Done.
```

#### 2. SVC_RESTART — 异步指令模式

发送 `SVC_RESTART` 指令，获取 `Task_Handle`，然后轮询 `TASK_QUERY` 直到服务重启完成。

```bash
python3 examples/client_svc_restart.py <server-ip> 7816 sshd
```

```
ASys Phase 3 E2E Test  —  localhost:7816
Service: sshd
====================================================
Handshake OK

► SVC_RESTART("sshd")
  SW:           0x9000  OK
  Task_Handle:  0x001D7D05
  RTT:          1.0 ms

► TASK_QUERY polling (max 30s) ...
  [ 1s]  Status = Success ✓

====================================================
PASS  SVC_RESTART("sshd") completed with Status=Success
```

#### 3. Multi-agent — 并发 session 隔离

并发启动四个独立 Agent，验证 per-session 锁的正确性：并发读不交叉，跨 session 的 `TASK_QUERY` 不泄露 handle 信息，突然断连不影响其他 session。

```bash
python3 examples/client_multi_agent.py <server-ip>
```

```
=== ASys Agent Simulator — localhost:7816 ===
Validates per-session lock correctness (Phase 4 P1)


[Scenario 1: Concurrent Core ISA — 4 agents × 5 SYS_STATUS]
  PASS  Agent-A2: 5× SYS_STATUS all SW=0x9000
  PASS  Agent-A3: 5× SYS_STATUS all SW=0x9000
  PASS  Agent-A1: 5× SYS_STATUS all SW=0x9000
  PASS  Agent-A4: 5× SYS_STATUS all SW=0x9000

[Scenario 2: Cross-session TASK_QUERY isolation]
  PASS  Agent-B1: SVC_RESTART crond → SW=0x9000
  PASS  Agent-B1: obtained valid Task_Handle
  PASS  Agent-B2 querying B1's handle → Status=0xFF (no info leak)
  PASS  Agent-B1 querying own handle → Status != 0xFF

[Scenario 3: Concurrent SVC_RESTART — 3 agents, 3 different services]
  PASS  Agent-C1: SVC_RESTART crond   → SW=0x9000 + handle
  PASS  Agent-C2: SVC_RESTART rsyslog → SW=0x9000 + handle
  PASS  Agent-C3: SVC_RESTART sshd    → SW=0x9000 + handle
  PASS  All 3 Task_Handles are distinct
  FAIL  Agent-C1: crond   → Status=Success ✓  (Status=Failed)
  FAIL  Agent-C2: rsyslog → Status=Success ✓  (Status=Failed)
  PASS  Agent-C3: sshd    → Status=Success ✓

[Scenario 4: Disconnect resilience — Agent-D abruptly disconnects]
  PASS  Agent-D-stable: SYS_HELLO before disrupt → 0x9000
  PASS  Agent-D-bad: abrupt disconnect (no handshake)
  PASS  Agent-D-stable: SYS_STATUS after disrupt → 0x9000
  PASS  Agent-D-new: fresh connect after disrupt → SYS_HELLO 0x9000

====================================================
Summary: 17 passed, 2 failed
SOME TESTS FAILED — check output above
```

> **关于 Scenario 3 的 FAIL：** `crond`/`rsyslog` 返回 `Status=Failed` 意味着 `systemctl restart` 返回非零——这些服务在测试节点上未安装或未运行。ASys 协议路径（dispatch → fork → SIGCHLD → handle update）本身执行正确；当底层系统操作失败时，`Status=Failed` 是预期响应。

#### 4. PROC_THROTTLE — 观察并控制一个实时进程

这个 demo 用两台机器展示 ASys 真正的使用场景：远程操作者通过网络观察并控制一个 Linux 节点。

**在服务端（RHEL/Linux）——启动 CPU 占用程序：**

```bash
python3 examples/server_cpu_hog.py
```

```
CPU hog started  PID=2644
Press Ctrl+C to stop.
```

**在客户端（任意机器，例如 Windows）——连接并限速：**

```bash
python3 examples/client_proc_throttle.py <server-ip>
```

```
ASys Throttle Client  —  <server-ip>:7816
====================================================
Handshake OK

  CPU=100%  load1m=3.2  RPI=87/100

  #    PID       CPU%   MEM%
  ---  --------  ------  -----
  1    2644      99.87%     0%
  2    1281       9.09%     0%
  3       1       0.00%     1%
  4       9       0.00%     0%
  5      17       0.00%     0%

Select # or PID to throttle (blank to cancel): 1
  Selected #1 → PID 2644

  PROC_THROTTLE STOP  PID=2644 ...
  SW=0x9000  OK
  Waiting 2 s for CPU to settle...
  CPU=0%  (was 100%,  Δ=-100%)

  PID 2644 paused.  Press Ctrl+C to restore or exit.
^C
  Restore PID 2644? (yes/no) [no]: yes
  PROC_THROTTLE CONT  PID=2644  SW=0x9000  OK
```

客户端运行在 Windows，被限速的进程在 RHEL 上。无 SSH，无 Shell，一条签名二进制指令，通过加密通道传输。

---

## 安全模型

**传输层：** Noise IK（Curve25519 + ChaCha20-Poly1305 + BLAKE2b）——1-RTT 双向认证。无密码，无证书，无 CA。Session 内容具备前向保密性（session key 由每次握手的临时密钥派生；static private key 泄露不会暴露历史 session 内容）。已知边界：Agent 的 static public key 在握手中被加密于服务端 static public key 之下——static private key 泄露理论上可从已记录的握手流量中还原 Agent 身份。

**服务端身份：** 每次新连接时，`asyd` 在 Noise 握手之前发送 38 字节的 Pre-Handshake Frame（`[Magic][Version][ServerPubKey]`）。客户端将服务端公钥指纹与 `~/.asys/known_hosts` 比对（SSH 风格：首次连接时确认，后续不匹配则拒绝）。公钥本身是公开的；安全性依赖指纹确认，而非密钥保密。

**重放保护：** 签名指令携带 **Epoch_ID**（`HMAC-BLAKE2b(recv_key, "asys-epoch-v1")[:4]`），握手后派生，从不传输。每个 session 产生唯一 Epoch_ID；在不破解 session key 的前提下，跨 session 重放在密码学上不可能。session 内部，单调递增序列号（`Seq`）以 `0x6985` 阻止重放。

**权限收敛：** `asyd` 在 systemd 下以 **Caged Root** 运行：`CapabilityBoundingSet` 将权限精确限制到各指令所需（`CAP_KILL`、`CAP_SYS_RESOURCE`、`CAP_NET_ADMIN`、`CAP_SYS_PTRACE`、`CAP_DAC_READ_SEARCH`）。`NoNewPrivileges=true` 即使进程被攻陷也阻止权限提升。

**指令安全级别**（CLA 字节，bits 3–2）：

| 级别   | 适用范围     | 机制                              |
|--------|--------------|-----------------------------------|
| Plain  | Core ISA     | 仅 Noise 通道加密                 |
| Signed | Standard ISA | 每帧附加 HMAC-BLAKE2b Auth Tag    |

---

## 文档

| 文档 | 描述 |
|------|------|
| [`docs/zh/asys-whitepaper.md`](docs/zh/asys-whitepaper.md) | 背景、设计 rationale、可选方案对比及 ASys 的定位 |
| [`docs/zh/asys-spec.md`](docs/zh/asys-spec.md) | 协议规范：ISA、安全模型、APDU 帧格式 |
| [`docs/zh/asys-design-notes.md`](docs/zh/asys-design-notes.md) | 架构决策记录（为什么不用 JSON / mTLS / shell） |
| [`docs/zh/asys-conformance.md`](docs/zh/asys-conformance.md) | 一致性测试指南 |
| [`sdk/definitions/asys.isa`](sdk/definitions/asys.isa) | 机器可读 ISA 定义（TOML） |

---

## Changelog

> **版本号说明**：`asyd` 软件版本（v0.3.x）与 ASys 协议版本（v1.0，`0x0100`）独立管理。仅当线格式或指令语义发生变化时，协议版本才会递增。

### v0.3.1 — 2026-05-28

- **Client-Speak-First**（ADR-22）：TCP 连接建立后，`asyd` 等待客户端先发送 4 字节 Magic（`0x41535953`）再响应；硬编码 1 秒超时；不匹配或超时则静默关闭，不返回任何响应。降低对通用端口扫描器的暴露面。
- `asyd` 新增 `--help` 和 `--version` 参数
- 一致性测试：`test_client_magic.c`（TC-MAG-001/002/003）加入 `make check`

### v0.3.0 — 2026-05-27（初始开源版本）

- `asyd` C daemon，零外部依赖，静态内存池，请求路径零 `malloc`
- Noise IK（Curve25519 + ChaCha20-Poly1305 + BLAKE2b）传输，1-RTT 双向认证
- Agent 公钥白名单（`/etc/asyd/authorized_agents`），SSH 风格指纹验证
- Pre-Handshake Frame：握手前服务端广播公钥，`~/.asys/known_hosts` 管理
- HMAC-BLAKE2b Auth Tag 验证 + Epoch_ID 跨 session 重放保护
- Core ISA：`SYS_CAPS`、`SYS_HELLO`、`SYS_STATUS`、`SYS_PROCS`
- Standard ISA：`PROC_THROTTLE`、`SVC_RESTART`（异步，配合 `TASK_QUERY`）
- per-session 并发，60s 空闲超时，journald 日志，systemd Caged Root 部署

---

## License

Apache 2.0 — Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)

Monocypher（加密库）：CC-0 / ISC 双许可证。
