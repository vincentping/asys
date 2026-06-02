# ASys 一致性测试指南
## Agentic System Interface — Conformance Test Guide

> 本文档定义"什么样的实现才算符合 ASys 标准"。
> 第三方实现（如 asyd-rust、asyd-go）必须通过本文档定义的所有测试，
> 才能使用"ASys Certified"标签。
> 配套文档：[asys-spec.md](asys-spec.md)
> 最后更新：2026-05-28

---

## 目录

1. [一致性级别定义](#1-一致性级别定义)
2. [测试环境要求](#2-测试环境要求)
3. [帧解析一致性](#3-帧解析一致性)
4. [字节序验证](#4-字节序验证)
5. [安全模型验证](#5-安全模型验证)
6. [状态字验证](#6-状态字验证)
7. [Core ISA 行为验证](#7-core-isa-行为验证)
8. [跨语言互操作验证](#8-跨语言互操作验证)
9. [Standard ISA 行为验证](#9-standard-isa-行为验证)
10. [端到端集成测试](#10-端到端集成测试)
11. [测试向量索引](#11-测试向量索引)

---

## 1. 一致性级别定义

| 级别 | 要求 | 标签 |
|------|------|------|
| **Level 0** | 通过第3节（帧解析）+ 第4节（字节序）+ 第6节（状态字） | ASys Compatible |
| **Level 1** | Level 0 + 第5节（安全模型）+ 第7节（Core ISA） | ASys Certified |
| **Level 2** | Level 1 + 第8节（跨语言互操作） | ASys Full Certified |

**最低要求**：任何声称"支持 ASys 协议"的实现必须达到 Level 0。生产环境部署推荐 Level 1。

---

## 2. 测试环境要求

**编译工具链：**
- C 实现：gcc 9.0+ 或 clang 10.0+，`-O2 -pthread`
- Python 实现：Python 3.8+，依赖 `pip install noiseprotocol cryptography`；客户端密钥持久化至 `~/.asys/id_curve25519`
- 其他语言：需提供对应的大端序和 HMAC-BLAKE2b 支持

**参考实现（基准）：**
- `src/asyd/asyd.c`（v0.3.1）+ 对应 handlers，编译命令见 `CLAUDE.md`
- Python 客户端：`examples/client_core_isa.py`
- **注意**：所有 APDU 帧在 Noise IK 加密通道内传输。端到端测试（第7、8节）需先完成 Noise IK 握手；单元测试（`test_noise_ik`、`test_whitelist`、`test_apdu_parser`、`test_handlers`）直接调用模块接口，无需握手。

**测试运行方式：**
```bash
# 从 tests/conformance/ 目录运行
# Noise IK 握手测试
gcc -O2 -Wall test_noise_ik.c \
    ../../src/asyd/core/monocypher.c \
    ../../src/asyd/core/noise_ik.c \
    -I../../src/asyd/core -o test_noise_ik && ./test_noise_ik

# Agent 公钥白名单测试
gcc -O2 -Wall test_whitelist.c \
    ../../src/asyd/core/whitelist.c \
    ../../src/asyd/core/monocypher.c \
    -I../../src/asyd/core -o test_whitelist && ./test_whitelist

# APDU 解析器测试
gcc -O2 -Wall test_apdu_parser.c \
    ../../src/asyd/core/apdu_parser.c \
    -I../../src/asyd/core -o test_apdu_parser && ./test_apdu_parser

# Core ISA handler 测试
gcc -O2 -Wall test_handlers.c \
    ../../src/asyd/core/apdu_parser.c \
    ../../src/asyd/core/dispatcher.c \
    ../../src/asyd/handlers/sys_caps.c \
    ../../src/asyd/handlers/sys_hello.c \
    ../../src/asyd/handlers/sys_status.c \
    ../../src/asyd/handlers/sys_procs.c \
    -I../../src/asyd/core -o test_handlers && ./test_handlers

# Task Handle 内存池测试
gcc -O2 -Wall test_task_pool.c \
    ../../src/asyd/core/task_pool.c \
    -I../../src/asyd/core -o test_task_pool && ./test_task_pool

# PROC_THROTTLE handler 测试
gcc -O2 -Wall test_proc_throttle.c \
    ../../src/asyd/core/apdu_parser.c \
    ../../src/asyd/core/dispatcher.c \
    ../../src/asyd/core/task_pool.c \
    ../../src/asyd/handlers/proc_throttle.c \
    -I../../src/asyd/core -o test_proc_throttle && ./test_proc_throttle

# SVC_RESTART + TASK_QUERY handler 测试
gcc -O2 -Wall test_svc_restart.c \
    ../../src/asyd/core/apdu_parser.c \
    ../../src/asyd/core/dispatcher.c \
    ../../src/asyd/core/task_pool.c \
    ../../src/asyd/handlers/svc_restart.c \
    ../../src/asyd/handlers/task_query.c \
    -I../../src/asyd/core -ldl -o test_svc_restart && ./test_svc_restart

# Auth Tag 验签测试
gcc -O2 -Wall test_auth_verify.c \
    ../../src/asyd/core/crypto_utils.c \
    ../../src/asyd/core/auth_verify.c \
    ../../src/asyd/core/apdu_parser.c \
    ../../src/asyd/core/monocypher.c \
    -I../../src/asyd/core -o test_auth_verify && ./test_auth_verify

# Seq 重放检测测试
gcc -O2 -Wall test_seq_replay.c \
    ../../src/asyd/core/crypto_utils.c \
    ../../src/asyd/core/monocypher.c \
    -I../../src/asyd/core -o test_seq_replay && ./test_seq_replay

# Client-Speak-First Magic 验证测试（v0.3.1，无需运行 asyd）
gcc -O2 -Wall -pthread test_client_magic.c -o test_client_magic && ./test_client_magic
```

**已验证通过的参考结果：**

| 测试套件 | 用例数 | 状态 |
|---------|--------|------|
| `test_noise_ik` | 全部 | ✓ ALL TESTS PASSED |
| `test_whitelist` | 16 | ✓ 16/16 |
| `test_apdu_parser` | 58 | ✓ 58/58 |
| `test_handlers` | 25 | ✓ 25/25 |
| `test_task_pool` | 30 | ✓ 30/30 |
| `test_proc_throttle` | 7 | ✓ 7/7 |
| `test_svc_restart` | 16 | ✓ 16/16 |
| `test_task_query` | 19 | ✓ 19/19 |
| `test_auth_verify` | 19 | ✓ 19/19 |
| `test_seq_replay` | 21 | ✓ 21/21 |
| `test_client_magic` | 5 | ✓ 5/5（v0.3.1） |
| `client_multi_agent.py` | 19 | ✓ 19/19（Windows → RHEL E2E） |

---

## 3. 帧解析一致性

### TC-FRAME-001：标准帧最小帧解析

- **输入**：`00 01 00 00 00 00`（6字节，CLA=0x00，INS=0x01，P1=0x00，P2=0x00，Lc=0x00，Le=0x00）
- **预期**：
  - `cla=0x00`，`ins=0x01`，`p1=0x00`，`p2=0x00`
  - `data_len=0`，`data=NULL`，`auth_tag=NULL`
  - `ext=0`，`sec=0`（PLAIN）
  - `total_size=6`
- **对应测试**：`test_apdu_parser.c` TC-1

### TC-FRAME-002：标准帧带 Data

- **输入**：`00 02 01 02 03 AA BB CC FF`（9字节，Lc=3，Data=AA BB CC，Le=FF）
- **预期**：
  - `data_len=3`，`data[0]=0xAA`，`data[2]=0xCC`
  - `le=0xFF`，`total_size=9`
- **对应测试**：`test_apdu_parser.c` TC-2

### TC-FRAME-003：扩展帧解析（CLA.Ext=1）

- **输入**：`02 03 00 00 00 01 00 [256字节数据] 00 00`
  - CLA=0x02（bit1=1，Ext=1），INS=0x03
  - Lc占位=0x00，Lc_high=0x01，Lc_low=0x00（即256字节）
- **预期**：
  - `ext=1`，`data_len=256`
  - `total_size=7+256+2=265`
- **对应测试**：`test_apdu_parser.c` TC-5

### TC-FRAME-004：非法 Lc 拒绝

- **输入**：`00 01 00 00 FF 00`（声明 Lc=255，但实际只有1字节 Data）
- **预期**：`APDU_NEED_MORE`（等待更多数据，不崩溃，不挂起）
- **对应测试**：`test_apdu_parser.c` TC-7（半包处理）

### TC-FRAME-005：Extended Lc placeholder 校验

- **输入**：`02 01 00 00 FF 00 01 AA 00 00`（Ext=1 但 Lc 占位字节=0xFF 而非 0x00）
- **预期**：`APDU_ERR_EXT_LC`
- **对应测试**：`test_apdu_parser.c` TC-11

### TC-FRAME-006：CLA 版本错误

- **输入**：`20 01 00 00 00 00`（CLA bit7-5=001，版本不支持）
- **预期**：`APDU_ERR_VERSION`
- **对应测试**：`test_apdu_parser.c` TC-9

### TC-FRAME-007：CLA RFU 位拒绝

- **输入**：`01 01 00 00 00 00`（CLA bit0=1，RFU 位被设置）
- **预期**：`APDU_ERR_RFU`
- **对应测试**：`test_apdu_parser.c` TC-10

### TC-FRAME-008：安全帧 Auth Tag 位置

- **输入**：`04 01 00 00 02 DE AD 00 [16字节 Auth Tag]`（CLA Sec=01，Signed）
- **预期**：
  - `sec=1`（SIGNED）
  - `auth_tag` 指向 Le 之后的 16 字节
  - `auth_tag` 不计入 `data_len`
  - `total_size=5+2+1+16=24`
- **对应测试**：`test_apdu_parser.c` TC-3

### TC-FRAME-009：流水线粘包处理

- **输入**：两帧连续写入缓冲区（Frame A + Frame B）
- **预期**：
  - 第一次 `try_parse` 返回 Frame A
  - `consume()` 后第二次 `try_parse` 返回 Frame B
  - `consume()` 后 `filled=0`
- **对应测试**：`test_apdu_parser.c` TC-8

---

## 4. 字节序验证

### TC-ENDIAN-001：多字节字段大端序

所有多字节字段必须以大端序编码，验证方式：

```python
# Python 验证脚本
import struct

# 构造 SYS_HELLO 请求
req = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x00])

# 解析 SYS_HELLO 响应（18字节）
resp = recv(18)
magic = struct.unpack('>I', resp[0:4])[0]   # 大端 uint32
assert magic == 0x41535953, f"Magic should be 0x41535953, got {magic:#010x}"

ts_ns = struct.unpack('>Q', resp[8:16])[0]  # 大端 uint64
assert ts_ns > 0, "Timestamp should be non-zero"
```

### TC-ENDIAN-002：跨语言一致性

同一 APDU 帧由 C 客户端和 Python 客户端分别构造，发送给 `asyd`，解析结果必须完全一致。

**验证步骤：**
1. C 客户端构造 `SYS_STATUS` 请求帧，记录原始字节
2. Python 客户端构造同一帧，记录原始字节
3. 两者字节序列必须逐字节相同
4. `asyd` 对两者的响应必须完全相同

**测试向量**：见 `tests/vectors/endian_sys_hello_req.bin`

---

## 5. 安全模型验证

### TC-SEC-001：未知公钥拒绝（白名单模式）

- **输入**：未在 `/etc/asyd/authorized_agents` 中的 Agent 公钥发起 Noise IK 握手
- **预期**：握手阶段返回 `0x6982`，连接立即终止，不进入任何业务逻辑
- **对应测试**：`test_whitelist.c` TC-WL-004

### TC-SEC-002：Auth Tag 篡改检测

- **输入**：翻转 Auth Tag 第一个字节（`auth_tag[0] ^= 0xFF`）
- **预期**：解密/验证失败，返回 `NOISE_ERR_AUTH`，不执行任何业务逻辑
- **对应测试**：`test_noise_ik.c`（MAC Tamper Detection）

### TC-SEC-003：序列号重放检测

- **输入**：重复发送序列号 ≤ `Last_Seen_Seq` 的签名帧
- **预期**：返回 2 字节 `0x6985`（Replay Detected）
- **相关规范**：`asys-spec.md` 第2.2.4节

---

## 5.1 Agent 公钥白名单验证（`test_whitelist.c`）

> 对应测试文件：`tests/conformance/test_whitelist.c`
> 依赖：`whitelist.c`、`monocypher.c`

### TC-WL-001：缺少文件 → WL_OK，count=0

- **输入**：`whitelist_load()` 目标路径不存在
- **预期**：返回 `WL_OK`，`wl.count == 0`（空白名单，不崩溃）

### TC-WL-002：有效文件 → 正确计数

- **输入**：文件含 2 条合法 hex 公钥
- **预期**：返回 `WL_OK`，`wl.count == 2`

### TC-WL-003：已知公钥 → WL_OK

- **输入**：`whitelist_check(&wl, KEY_A)`，KEY_A 在白名单中
- **预期**：返回 `WL_OK`

### TC-WL-004：未知公钥 → WL_ERR_DENIED

- **输入**：`whitelist_check(&wl, KEY_C)`，KEY_C 不在白名单中
- **预期**：返回 `WL_ERR_DENIED`（对应协议层 `0x6982`）

### TC-WL-005：注释行和空行跳过

- **输入**：文件含 `# 注释行`、空行和 2 条合法公钥
- **预期**：`wl.count == 2`（只计入有效条目）

### TC-WL-006：可选 label 解析

- **输入**：条目格式为 `<64-char hex>  my-agent-label`
- **预期**：`wl.entries[0].label == "my-agent-label"`

### TC-WL-007：NULL 参数 → WL_ERR_DENIED，不崩溃

- **输入**：`whitelist_check(NULL, KEY_A)` 和 `whitelist_check(&wl, NULL)`
- **预期**：均返回 `WL_ERR_DENIED`，无崩溃、无 segfault

### TC-WL-008：whitelist_wipe() 清零所有密钥材料

- **输入**：已加载 1 条公钥，调用 `whitelist_wipe(&wl)`
- **预期**：`wl.count == 0`，`wl.entries[0].pub` 全为零字节

---

## 5.2 Auth Tag 验签测试（`test_auth_verify.c`）

> 对应测试文件：`tests/conformance/test_auth_verify.c`
> 依赖：`crypto_utils.c`、`auth_verify.c`、`apdu_parser.c`、`monocypher.c`

### TC-AUTH-001：正确 Auth Tag 通过验签

- **输入**：构造一个 Signed 帧（`CLA=0x04`），用已知 `recv_key` 计算正确的 Auth Tag
- **预期**：`verify_auth_tag()` 返回 1

### TC-AUTH-002：错误 Auth Tag 拒绝

- **输入**：正确帧，但翻转 Auth Tag 第0字节（`auth_tag[0] ^= 0xFF`）
- **预期**：`verify_auth_tag()` 返回 0

### TC-AUTH-003：Auth Tag 全零拒绝

- **输入**：Auth Tag 为 16 字节全零（占位符）
- **预期**：`verify_auth_tag()` 返回 0

### TC-AUTH-004：Plain 帧跳过验签

- **输入**：`CLA=0x00`（`sec=PLAIN`）
- **预期**：`asyd.c` 中不调用 `verify_auth_tag()`，直接进入 dispatch
- **验证方式**：构造 Plain 帧，确认 `dispatch()` 被正常调用

### TC-AUTH-005：HMAC 覆盖范围完整性

- **输入**：正确帧，修改 INS 字节但保留原 Auth Tag
- **预期**：`verify_auth_tag()` 返回 0（INS 在 Header 里，被 HMAC 覆盖）

### TC-AUTH-006：HMAC 覆盖 Lc 字段

- **输入**：正确帧，修改 Lc 字节但保留原 Auth Tag
- **预期**：`verify_auth_tag()` 返回 0（Lc 在 Header 里，被 HMAC 覆盖）

### TC-AUTH-007：Payload 长度为零

- **输入**：`data_len=4`（只有 Seq，无 Payload），Auth Tag 正确
- **预期**：`verify_auth_tag()` 返回 1（空 Payload 是合法情况）

### TC-AUTH-008：`crypto_verify16` 常量时间

- **说明**：无法在单元测试中严格验证时序，但需确认使用了 `crypto_verify16()` 而非 `memcmp()`
- **验证方式**：代码审查确认，`auth_verify.c` 中不出现 `memcmp`

---

## 5.3 Seq 重放检测测试（`test_seq_replay.c`）

> 对应测试文件：`tests/conformance/test_seq_replay.c`
> 依赖：`crypto_utils.c`、`monocypher.c`

### TC-SEQ-001：首条 Signed 指令通过

- **前提**：`last_seen_seq = 0`
- **输入**：Seq = 1
- **预期**：`1 > 0`，通过；`last_seen_seq` 更新为 1

### TC-SEQ-002：Seq=0 被拒绝（哨兵值）

- **前提**：`last_seen_seq = 0`
- **输入**：Seq = 0
- **预期**：`0 <= 0`，返回 2 字节 `0x6985`（Replay Detected）

### TC-SEQ-003：正常递增通过

- **前提**：`last_seen_seq = 100`
- **输入**：Seq = 101
- **预期**：通过，`last_seen_seq` 更新为 101

### TC-SEQ-004：重放检测——等于 Last_Seen_Seq

- **前提**：`last_seen_seq = 100`
- **输入**：Seq = 100
- **预期**：`100 <= 100`，返回 2 字节 `0x6985`（Replay Detected）

### TC-SEQ-005：重放检测——小于 Last_Seen_Seq

- **前提**：`last_seen_seq = 100`
- **输入**：Seq = 50
- **预期**：`50 <= 100`，返回 2 字节 `0x6985`（Replay Detected）

### TC-SEQ-006：新连接重置 last_seen_seq

- **输入**：新会话（`last_seen_seq` 初始化为 0），发送 Seq=1
- **预期**：`check_and_advance` 返回 1，`last_seen_seq` 更新为 1

### TC-SEQ-007：连续递增通过，夹带重放被拒绝

- **操作**：Seq 1→2→3 均通过；再发 Seq=2（重放）被拒绝；Seq=4 继续通过
- **预期**：`last_seen_seq = 4`，Seq=2 返回 0

### TC-SEQ-008：Seq=0 始终被拒绝

- **输入一**：新会话（`last_seen_seq = 0`），发送 Seq=0
- **预期**：`check_and_advance` 返回 0，`last_seen_seq` 保持 0
- **输入二**：正常推进后（`last_seen_seq = 5`），发送 Seq=0
- **预期**：返回 0，`last_seen_seq` 保持 5

---

## 5.4 Client-Speak-First Magic 验证（`test_client_magic.c`）

> 对应测试文件：`tests/conformance/test_client_magic.c`
> 依赖：无（仅 POSIX sockets）；使用 `socketpair(2)` 在进程内模拟 TCP 连接，无需运行 asyd
> 引入版本：v0.3.1

**背景**：v0.3.1 起，`asyd` 改为 Client-Speak-First 连接模式。TCP 握手完成后，`asyd` 不再主动发送任何数据，而是等待 Agent 首先发送 4 字节 Magic（`0x41535953`，ASCII "ASYS"），超时硬编码为 1 秒。Magic 不符或超时则静默断开，不向客户端发送任何响应。

### TC-MAG-001：合法 Magic 通过验证

- **前提**：socketpair 建立，服务端调用 `wait_for_client_magic(fd)`
- **输入**：客户端发送 `0x41535953`（大端序，4 字节）
- **预期**：函数返回 0（accepted）

### TC-MAG-002：非法 Magic 被拒绝

- **前提**：socketpair 建立，服务端调用 `wait_for_client_magic(fd)`
- **输入**：客户端发送 `0xDEADBEEF`（任意非 ASYS 值）
- **预期**：函数返回 -1（rejected），服务端不发送任何响应

### TC-MAG-003：超时被拒绝（~1 秒）

- **前提**：socketpair 建立，服务端调用 `wait_for_client_magic(fd)`
- **输入**：客户端不发送任何数据
- **预期**：函数返回 -1；实际等待时间 ≥ 900 ms 且 < 3000 ms

---

## 6. 状态字验证

### TC-SW-001：指令不存在返回 `0x6A81`

- **输入**：Capability Map 中未注册的 INS 码（如 `0xEE`）
- **预期**：返回 `0x6A81`，响应恰好 2 字节，不泄露任何系统信息
- **对应测试**：`test_handlers.c` TC-1

### TC-SW-002：未实现 Core 槽返回 `0x6A81`

- **输入**：`INS=0x04`（Core ISA 编码空间内，但未在 Capability Map 中注册）
- **预期**：返回 `0x6A81`（不在位图中，物理不存在）
- **对应测试**：`test_handlers.c` TC-2

### TC-SW-003：平台不支持返回 `0x6D00`

- **场景**：平台缺乏执行该指令所需的原子原语
- **预期**：返回 `0x6D00`，严禁进行模糊模拟
- **相关规范**：`asys-spec.md` 第1.2节平台中立原则

### TC-SW-004：状态字位置验证

对每条 Core ISA 指令，验证 SW 字节位于响应的最后 2 字节：

| 指令 | 响应长度 | SW 位置 |
|------|---------|---------|
| `SYS_CAPS (0x00)` | 36 字节 | `resp[34-35]` |
| `SYS_HELLO (0x01)` | 18 字节 | `resp[16-17]` |
| `SYS_STATUS (0x02)` | 23 字节 | `resp[21-22]` |
| `SYS_PROCS (0x03)` | 44 字节 | `resp[42-43]` |

---

## 7. Core ISA 行为验证

### TC-CORE-001：SYS_CAPS 响应格式

- **响应长度**：36 字节
- **字段验证**：

| 字节 | 字段 | 验证条件 |
|------|------|---------|
| `0-3` | Core Bitmap | `(value & 0xF) == 0xF`（bits 0-3 必须全为1，对应已实现的4条指令） |
| `4-7` | Ext Bitmap | `0x00000005`（bits 0, 2 = `PROC_THROTTLE(0x20)`, `SVC_RESTART(0x22)` 在 Ext ISA 中已实现） |
| `8-9` | Protocol Version | `== 0x0100`（v1.0） |
| `10-13` | Kernel Hash | 非全零 |
| `14-15` | CPU Count | `> 0` |
| `16-17` | Arch Code | 已知架构码之一（`0x0001`=x86_64，`0x0002`=aarch64，`0xFFFF`=未知） |
| `18-21` | Total RAM MB | `> 0` |
| `26-29` | Root Size MB | `> 0` |
| `32` | RPI Type | `0x01`（NATIVE_KERNEL）或 `0x02`（USER_SIMULATED） |
| `33` | Reserved | `== 0x00` |
| `34-35` | SW | `== 0x9000` |

- **对应测试**：`test_handlers.c` TC-3 至 TC-12

### TC-CORE-002：SYS_HELLO 响应格式

- **响应长度**：18 字节
- **字段验证**：

| 字节 | 字段 | 验证条件 |
|------|------|---------|
| `0-3` | Magic | `== 0x41535953`（ASCII: "ASYS"） |
| `4-7` | Node_UID | 任意值（非零为佳） |
| `8-15` | Server_Timestamp | `> 0`（纳秒 Unix Epoch） |
| `16-17` | SW | `== 0x9000` |

- **对应测试**：`test_handlers.c` TC-13 至 TC-16

### TC-CORE-003：SYS_STATUS 响应格式

- **响应长度**：23 字节
- **字段验证**：

| 字节 | 字段 | 验证条件 |
|------|------|---------|
| `0` | Load 1min × 10 | `0-255`（负载均值 × 10，最大约 25.5） |
| `1` | Load 5min × 10 | `0-255` |
| `2` | CPU % | `0-100` |
| `3-6` | Mem Available MB | `> 0` |
| `7` | Root Disk % | `0-100` |
| `8-11` | IO Wait ms | `>= 0` |
| `12-13` | Inbound Mbps | `>= 0` |
| `14-15` | Outbound Mbps | `>= 0` |
| `16` | RPI | `0x00-0x64` 或 `0xFF`（NOT_SUPPORTED） |
| `17-20` | Reserve | `== 0x00000000` |
| `21-22` | SW | `== 0x9000` |

- **缓存行为验证**：连续两次调用，第二次 RTT 必须 < 200ms（命中缓存）
- **对应测试**：`test_handlers.c` TC-17 至 TC-20

### TC-CORE-004：SYS_PROCS 响应格式

- **响应长度**：44 字节
- **字段验证**：

| 字节 | 字段 | 验证条件 |
|------|------|---------|
| `0-1` | Total_Procs | `> 0`（系统至少有一个进程） |
| `2-41` | Top 5 Slots | 见下方 Slot 验证 |
| `42-43` | SW | `== 0x9000` |

**单个 Slot 验证（8字节）**：

| Slot 偏移 | 字段 | 验证条件 |
|----------|------|---------|
| `0-3` | PID | 非空 Slot 时 `> 0`；空 Slot 时 `== 0x00000000` |
| `4-5` | CPU Usage × 100 | `0-65535` |
| `6` | MEM Usage % | `0-100` |
| `7` | Status Flag | `0x00-0x07`（3个有效 bit） |

- **空 Slot 填充验证**：进程不足5个时，空 Slot 的 PID 必须为 `0x00000000`，整个 Slot 必须全零
- **对应测试**：`test_handlers.c` TC-21 至 TC-25

---

## 8. 跨语言互操作验证

### TC-INTEROP-001：C ↔ Python 帧构造一致性

**验证步骤：**
1. Python 客户端构造 `SYS_STATUS` 请求帧（`00 02 00 00 00 00`）
2. 记录发送的原始字节
3. 对比与 C 客户端构造的同一帧，逐字节比对
4. 两者必须完全相同

**预期字节序列**：`00 02 00 00 00 00`

### TC-INTEROP-002：响应解析一致性

**验证步骤：**
1. `asyd` 返回 `SYS_STATUS` 响应
2. C 客户端解析各字段值
3. Python 客户端解析同一响应字节序列
4. 两者解析结果（各字段数值）必须完全一致

---

## 9. Standard ISA 行为验证

> 对应测试文件：`tests/conformance/test_task_pool.c`、`test_proc_throttle.c`、`test_svc_restart.c`、`test_task_query.c`

### 9.1 Task Handle 内存池（`test_task_pool.c`）

#### TC-POOL-001：基本 alloc / free 循环

- **操作**：`task_pool_alloc(session=1, svc="nginx", pid=100)`
- **预期**：返回非零 handle，高 16 位 == 1（session_id），低 16 位非零
- **后续**：`task_pool_free(handle)` → `task_pool_find_handle(handle, 1)` 返回 NULL

#### TC-POOL-002：Handle 归属权隔离

- **操作**：`task_pool_alloc(session=1, ...)` 得到 handle
- **预期**：`task_pool_find_handle(handle, session=2)` 返回 NULL
- **验证**：跨 session 查询不泄露任何任务信息

#### TC-POOL-003：幂等性查找

- **操作**：`task_pool_alloc(session=1, svc="nginx", pid=100)` 得到 handle_A
- **后续**：`task_pool_find_pending(session=1, svc="nginx")`
- **预期**：返回 handle_A（相同 session + 相同服务名，返回已有 Pending handle）

#### TC-POOL-004：不同服务名不触发幂等

- **操作**：`task_pool_alloc(session=1, svc="nginx", ...)` 得到 handle_A
- **后续**：`task_pool_find_pending(session=1, svc="redis")`
- **预期**：返回 0（不同服务名，不复用）

#### TC-POOL-005：不同 session 不触发幂等

- **操作**：`task_pool_alloc(session=1, svc="nginx", ...)` 得到 handle_A
- **后续**：`task_pool_find_pending(session=2, svc="nginx")`
- **预期**：返回 0（不同 session，不复用）

#### TC-POOL-006：pool 满时 alloc 返回 0

- **操作**：连续 `task_pool_alloc` 64 次，填满所有 slot
- **预期**：第 65 次调用返回 0
- **验证**：`task_pool_available()` 在满池时返回 0，有空位时返回 1

#### TC-POOL-007：`update_by_pid` 更新状态

- **操作**：alloc 后调用 `task_pool_update_by_pid(pid=100, TASK_SUCCESS)`
- **预期**：`task_pool_find_handle(handle, session)` 的 `status == TASK_SUCCESS`

#### TC-POOL-008：`update_by_pid` 忽略不存在的 pid

- **操作**：`task_pool_update_by_pid(pid=99999, TASK_SUCCESS)`（不存在的 pid）
- **预期**：无崩溃，无副作用，pool 状态不变

#### TC-POOL-009：超时扫描

- **操作**：alloc 一个 slot，手动将 `created_at` 设为 `time(NULL) - 31`，调用 `task_pool_sweep_timeouts()`
- **预期**：该 slot 的 `status == TASK_TIMEOUT`

#### TC-POOL-010：`release_session` 清理

- **操作**：alloc 3 个 session=1 的 slot，1 个 session=2 的 slot；调用 `task_pool_release_session(1)`
- **预期**：session=1 的 3 个 slot 全部变为 TASK_EMPTY；session=2 的 slot 不受影响

#### TC-POOL-011：free 后字段清零

- **操作**：alloc → `task_pool_free(handle)`
- **预期**：该 slot 的 `handle_id==0`，`child_pid==0`，`svc_name[0]=='\0'`，`status==TASK_EMPTY`

---

### 9.2 PROC_THROTTLE（`test_proc_throttle.c`）

#### TC-PROC-001：CLA.Sec 校验

- **输入**：`CLA=0x00`（Plain，非 Signed），`INS=0x20`，`P1=0x00`，`Lc=0x08`，Data=[Seq(4B)][PID(4B)]
- **预期**：返回 `0x6982`（Access Denied）

#### TC-PROC-002：Lc 长度校验

- **输入**：`CLA=0x04`，`INS=0x20`，`Lc=0x04`（不足 8 字节）
- **预期**：返回 `0x6700`（Wrong Length）

#### TC-PROC-003：P1 非法值拒绝

- **输入**：`CLA=0x04`，`P1=0x02`（非 0x00/0x01）
- **预期**：返回 `0x6A80`（Wrong Data）

#### TC-PROC-004：PID=0 拒绝

- **输入**：合法请求，Data 中 PID 字段为 `0x00000000`
- **预期**：返回 `0x6A80`（Wrong Data）

#### TC-PROC-005：合法 STOP 请求

- **输入**：`CLA=0x04`，`P1=0x00`（STOP），PID 为自身进程 PID（`getpid()`）
- **预期**：返回 `0x9000`
- **注**：测试后需立即发 CONT 恢复，或用子进程测试

#### TC-PROC-006：合法 CONT 请求

- **输入**：`CLA=0x04`，`P1=0x01`（CONT），PID 为已停止的进程
- **预期**：返回 `0x9000`

#### TC-PROC-007：目标进程不存在

- **输入**：PID 为 `0xFFFFFFFF`（不存在的进程）
- **预期**：返回 `0x6A80`（Wrong Data，对应 ESRCH）

---

### 9.3 SVC_RESTART（`test_svc_restart.c`）

> **注**：`handler_svc_restart` 会真实调用 `fork/exec`，单元测试需要 mock 或在隔离环境中运行。建议测试文件提供一个 `fork_mock` 桩函数，通过编译宏替换真实 `fork`。

#### TC-SVC-001：CLA.Sec 校验

- **输入**：`CLA=0x00`（Plain）
- **预期**：返回 `0x6982`

#### TC-SVC-002：Lc 最小长度校验

- **输入**：`CLA=0x04`，`Lc=0x04`（只有 Seq 4B，无服务名字节，data_len < MIN_DATA_LEN=5）
- **预期**：返回 `0x6700`（长度检查先于数据校验触发）

#### TC-SVC-003：非法字符拒绝（最短合法长度）

- **输入**：`Lc=0x05`（data_len=5，name_len=1），服务名为 `"A"`（大写字母，非法字符）
- **预期**：返回 `0x6A80`（长度合法，数据校验失败）
- **说明**：与 TC-SVC-002 的区别——此处 Lc 已满足最小长度要求，错误来自字符集校验而非长度检查

#### TC-SVC-004：非法字符拒绝

- **输入**：SvcName = `"Nginx"`（含大写字母）
- **预期**：返回 `0x6A80`

#### TC-SVC-005：非法字符拒绝（路径符）

- **输入**：SvcName = `"../etc/passwd"`
- **预期**：返回 `0x6A80`

#### TC-SVC-006：`.service` 后缀拒绝

- **输入**：SvcName = `"nginx.service"`
- **预期**：返回 `0x6A80`（协议层直接拒绝，`asyd` 在内部追加 `.service` 后缀，客户端不应提前加）
- **说明**：`svc_name_valid()` 在字符集校验后显式检查 `.service` 尾缀并拒绝，防止产生 `nginx.service.service`

#### TC-SVC-007：服务名最大长度边界

- **输入**：SvcName 恰好 64 字节（合法字符）
- **预期**：返回 `0x9000`（handle 有效）

#### TC-SVC-008：服务名超长拒绝

- **输入**：SvcName 65 字节
- **预期**：返回 `0x6A80`

#### TC-SVC-009：幂等性——返回已有 Handle

- **前提**：session=1，svc="nginx" 已有 Pending handle_A
- **输入**：再次发送 `SVC_RESTART("nginx")`，session=1
- **预期**：返回 handle_A，不创建新 handle，不 fork 新进程

#### TC-SVC-010：pool 满时不 fork

- **前提**：`task_pool_available()` 返回 0（pool 已满）
- **输入**：合法 `SVC_RESTART("nginx")`
- **预期**：返回 `0x6400`（Blocked），无子进程被创建

#### TC-SVC-011：返回的 Handle 高 16 位等于 session_id

- **输入**：合法 `SVC_RESTART("nginx")`，session_id = 1
- **预期**：响应 6 字节，`Task_Handle[31:16] == 1`，`SW=0x9000`
- **验证目的**：确认 Handle 格式符合 spec §1.4.2（高 16 位嵌入 Session_ID，供 TASK_QUERY 做跨 session 隔离检查）

#### TC-SVC-012：`fork()` 返回 ENOMEM

- **前提**：在 test_svc_restart 二进制内定义 `fork()` 覆盖符，受 `g_mock_fork_enomem` 标志控制；通过 `dlsym(RTLD_NEXT, "fork")` 调用真实 fork（编译加 `-ldl`）
- **输入**：合法 `SVC_RESTART("nginx")`，mock fork 激活（`errno=ENOMEM`，返回 -1）
- **预期**：返回 `0x6F01`（System Emergency: ENOMEM），**不挂起，不返回 `0x6F00`**
- **验证目的**：确认 `handler_svc_restart` 明确区分 `ENOMEM` 与其他 fork 失败原因，返回精确子码

---

### 9.4 TASK_QUERY（`test_task_query.c`）

#### TC-QUERY-001：Lc 长度校验

- **输入**：`Lc=0x02`（不足 4 字节）
- **预期**：返回 `0x6700`

#### TC-QUERY-002：Handle Not Found

- **输入**：`handle=0x00001234`（不存在的 handle）
- **预期**：`Status=0xFF`，`SW=0x9000`

#### TC-QUERY-003：跨 session 查询拒绝

- **前提**：session=1 分配了 handle_A
- **输入**：session=2 查询 handle_A
- **预期**：`Status=0xFF`（不泄露任务信息）

#### TC-QUERY-004：Pending 状态查询

- **前提**：task pool 中存在 Pending 状态的 handle
- **预期**：`Status=0x00`，`SW=0x9000`，handle **不被释放**

#### TC-QUERY-005：Success 状态查询并释放

- **前提**：手动将 task pool slot 状态设为 TASK_SUCCESS
- **预期**：`Status=0x01`，`SW=0x9000`，handle **被释放**（再次查询返回 0xFF）

#### TC-QUERY-006：Failed 状态查询并释放

- **前提**：手动将 task pool slot 状态设为 TASK_FAILED
- **预期**：`Status=0x02`，`SW=0x9000`，handle **被释放**

#### TC-QUERY-007：Timeout 状态查询并释放

- **前提**：手动将 task pool slot 状态设为 TASK_TIMEOUT
- **预期**：`Status=0x03`，`SW=0x9000`，handle **被释放**

#### TC-QUERY-008：Sweep 触发超时

- **前提**：存在 Pending 的 slot，`created_at = time(NULL) - 31`
- **操作**：调用 `handler_task_query`（内部会调用 `sweep_timeouts`）
- **预期**：`Status=0x03`（Timeout），handle 被释放

#### TC-QUERY-009：Cancelled 状态查询

- **前提**：手动将 task pool slot 状态设为 `TASK_CANCELLED`
- **预期**：`Status=0x04`，`SW=0x9000`
- **验证目的**：确认 `to_wire()` 正确映射 TASK_CANCELLED → 0x04（为 TASK_CANCEL 0x12 指令预留）

#### TC-QUERY-010：Lc > 4 静默接受

- **输入**：`data_len=5`（handle 4 字节 + 1 冗余字节），handle 未知
- **预期**：handler 只读 `data[0..3]`，返回 `Status=0xFF`，`SW=0x9000`（不拒绝）
- **验证目的**：确认上界宽松（`data_len < 4` 才报错，`> 4` 静默忽略冗余字节），与 spec 对齐

#### TC-QUERY-011：终态 Handle TTL 到期后回收

- **前提**：手动将一个 slot 状态设为 `TASK_SUCCESS`，`created_at = time(NULL) - 31`（已超 30 秒 TTL）
- **操作**：调用 `handler_task_query`（内部调用 `sweep_timeouts`）
- **预期**：`Status=0xFF`（Not Found）——终态 Handle 超过 TTL 同样被回收，不保留结果
- **验证目的**：确认 TTL 回收覆盖所有状态（包括终态），防止 Agent 失联时终态槽位永久占用静态池

#### TC-QUERY-012：Session 断开后终态 Handle 立即失效

- **前提**：session=1 有一个 `TASK_SUCCESS` 的 slot
- **操作**：调用 `task_pool_release_session(1)`
- **预期**：slot 变为 `TASK_EMPTY`；用原 handle 查询返回 `Status=0xFF`
- **验证目的**：确认 Session 断开时**所有状态**（包括终态）的 slot 都被立即清零，不仅是 Pending 状态

---

## 10. 端到端集成测试

> 对应测试脚本：`tests/interop/test_e2e.py`（待实现）
> 运行前提：`asyd` 已启动，Python 客户端已注册，目标服务存在

### TC-E2E-001：SVC_RESTART 正常路径

1. 发送 `SVC_RESTART("nginx")`（Signed，CLA=0x04）
2. 验证响应：Task_Handle(4B) + SW=0x9000
3. 轮询 `TASK_QUERY(handle)` 直到 Status != Pending（最多 30 秒）
4. 验证 Status == 0x01（Success）
5. 验证 nginx 确实重启：`systemctl status nginx` 的 ActiveEnterTimestamp 更新

### TC-E2E-002：TASK_QUERY 幂等轮询

1. 发送 `SVC_RESTART("nginx")` 得到 handle
2. 在任务完成前连续发送 10 次 `TASK_QUERY(handle)`
3. 验证所有响应 SW=0x9000，Pending 期间 handle 不被释放
4. 完成后再查询，Status=Success，handle 被释放

### TC-E2E-003：SVC_RESTART 幂等性

1. 发送 `SVC_RESTART("nginx")` 得到 handle_A
2. 立即再发一次 `SVC_RESTART("nginx")`
3. 验证第二次响应的 handle == handle_A（相同 handle）
4. 验证 nginx 只被重启一次（通过 journal 日志确认）

### TC-E2E-004：不存在的服务名

1. 发送 `SVC_RESTART("nonexistent-service-xyz")`
2. 收到 handle，SW=0x9000（入队成功）
3. 轮询 TASK_QUERY，验证最终 Status=0x02（Failed）

### TC-E2E-005：Session 断开后 Handle 失效

1. 发送 `SVC_RESTART("nginx")` 得到 handle
2. 立即断开 TCP 连接
3. 重新连接，用旧 handle 查询 `TASK_QUERY`
4. 验证 Status=0xFF（Not Found）

### TC-E2E-006：PROC_THROTTLE 端到端（OODA 闭环）

1. 启动一个 CPU 压测进程（`stress-ng --cpu 1` 或简单的死循环脚本）
2. 通过 `SYS_PROCS` 获取其 PID
3. 发送 `PROC_THROTTLE(pid, P1=0x00)` STOP
4. 验证 `SYS_STATUS` 的 CPU 使用率下降
5. 发送 `PROC_THROTTLE(pid, P1=0x01)` CONT
6. 验证 CPU 使用率恢复
7. 全程 SW=0x9000

---

## 10.1 Agent Simulator 场景验证

> 对应测试脚本：`examples/client_multi_agent.py`
> 运行方式：`python3 client_multi_agent.py <host> [port]`
> 验证目标：per-session 锁正确性、跨 session 隔离、断连恢复

### TC-SIM-001：并发 Core ISA

- **场景**：4个 Agent 并发各发 5 次 `SYS_STATUS`
- **预期**：全部 SW=0x9000；首轮各自触发冷采样（~50ms），后续缓存命中（< 1ms）；无串行阻塞
- **验证点**：`s_cache_lock` 正确保护缓存，多线程并发读写不产生竞态

### TC-SIM-002：跨 Session TASK_QUERY 隔离

- **场景**：Agent-B1 发 `SVC_RESTART` 得到 handle；Agent-B2 用该 handle 查询
- **预期**：Agent-B2 查询返回 `Status=0xFF`（No info leak）；Agent-B1 查询自己的 handle 返回非 0xFF
- **验证点**：handle 高16位 Session_ID 校验正确，不同 session 无法互查

### TC-SIM-003：并发 SVC_RESTART + TASK_QUERY 轮询

- **场景**：3个 Agent 同时重启3个不同服务（crond / rsyslog / sshd），各自轮询到终态
- **预期**：3个 Task_Handle 各不相同；全部最终 Status=Success；无 handle 串扰
- **验证点**：`task_pool` 并发 alloc 正确，session 隔离正确

### TC-SIM-004：断连恢复

- **场景**：Agent-D-bad 强制断连（无握手）；同时 Agent-D-stable 正常操作
- **预期**：Agent-D-stable 断连前后均 SW=0x9000；新连接可正常握手
- **验证点**：`task_pool_release_session` 不影响其他 session；`g_cslots` slot 正确释放

---

## 11. 测试向量索引

测试向量存放于 `tests/vectors/`，每个文件对应一个预期解析结果。

| 文件 | 描述 | 预期结果 |
|------|------|---------|
| `vector_sys_hello_req.bin` | `SYS_HELLO` 请求帧（6字节） | `00 01 00 00 00 00` |
| `vector_sys_hello_resp.bin` | `SYS_HELLO` 响应帧（18字节） | Magic=`41535953`，SW=`9000` |
| `vector_sys_status_req.bin` | `SYS_STATUS` 请求帧（6字节） | `00 02 00 00 00 00` |
| `vector_sys_status_resp.bin` | `SYS_STATUS` 响应帧（23字节） | 各字段见 TC-CORE-003 |
| `vector_sys_caps_req.bin` | `SYS_CAPS` 请求帧（6字节） | `00 00 00 00 00 00` |
| `vector_sys_caps_resp.bin` | `SYS_CAPS` 响应帧（36字节） | 各字段见 TC-CORE-001 |
| `vector_sys_procs_req.bin` | `SYS_PROCS` 请求帧（6字节） | `00 03 00 00 00 00` |
| `vector_invalid_lc.bin` | 非法 Lc 长度帧 | `APDU_ERR_LENGTH` 或 `APDU_NEED_MORE` |
| `vector_ext_frame_256.bin` | 扩展帧（Lc=256） | `ext=1`，`data_len=256`，`total=265` |
| `vector_bad_version.bin` | CLA 版本错误帧 | `APDU_ERR_VERSION` |
| `vector_auth_tag_tampered.bin` | Auth Tag 被篡改的安全帧 | `NOISE_ERR_AUTH` |
| `vector_unknown_ins.bin` | 未知指令码帧 | SW=`0x6A81` |

> **注**：测试向量文件待逐步填充。当前 `tests/conformance/` 目录中的测试用例（`test_apdu_parser.c`、`test_whitelist.c`、`test_handlers.c`）已覆盖上述大部分场景，向量文件是这些测试的二进制固化形式，用于跨语言互操作验证。

---

---

*本文档随协议实现进度持续完善。新增指令或安全机制时应同步更新对应测试用例。*