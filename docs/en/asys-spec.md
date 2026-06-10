# ASys Protocol Specification
## Agentic System Interface — Specification

> This document is the authoritative specification for the ASys protocol. It must be read before modifying any implementation code.
> Protocol version: v1.0 (`0x0100`) | Last updated: 2026-06-01
> Sections marked *(planned)* are defined in the specification but are not within the commitments of protocol v1.0.

---

## Table of Contents

1. [Instruction Set Specification (ISA)](#1-instruction-set-specification-isa)
2. [Security Model](#2-security-model)
3. [Protocol Specification (ASys-APDU)](#3-protocol-specification-asys-apdu)

---

## 1. Instruction Set Specification (Core ISA Specification)

### 1.1 Encoding Space (ISA Addressing)

ASys uses the high nibble (upper 4 bits) of the INS byte as a logical page index, strictly grouping 16 instructions per page to maintain structural clarity over decades of protocol evolution:

| High Nibble | Code Range | Group | Status |
|-------------|------------|-------|--------|
| `0x0` | `0x00-0x0F` | Core ISA | Defined instructions permanently locked |
| `0x1` | `0x10-0x1F` | Protocol Control | Protocol-reserved; business use prohibited (`0x10`=continuation frame, `0x11`=TASK_QUERY, `0x12`=TASK_CANCEL) |
| `0x2` | `0x20-0x2F` | Process Control | Standard, semantics locked |
| `0x3` | `0x30-0x3F` | Network Control | Standard, semantics locked |
| `0x4` | `0x40-0x4F` | Diagnostics | Standard, semantics locked |
| `0x5` | `0x50-0x5F` | Storage & Filesystem | Standard, semantics locked |
| `0x6` | `0x60-0x6F` | Security & Auth | Standard, semantics locked |
| `0x7` | `0x70-0x7F` | Runtime & Container | Standard, semantics locked |
| `0x8` | `0x80-0x8F` | Hardware & Energy | Standard, semantics locked |
| `0x9-0xB` | `0x90-0xBF` | Standard ISA Reserved | Reserved by protocol group for future standard instruction groups; no Major Version required |
| `0xC-0xF` | `0xC0-0xFF` | Vendor Extensions | Unlimited extension via `Vendor_ID` (4 pages / 64 slots; Vendor_ID provides an unlimited namespace) |

**Design principles**: Defined Core ISA instructions are permanently locked. The 7 Standard ISA pages have locked instruction semantics; empty slots may be filled by the protocol group as needed — anyone seeing `0x3x` always knows it is Network Control. Adding a new standard group requires a Major Version, which is a decision to be made deliberately. Standard ISA Reserved `0x90-0xBF` provides 3 pages / 48 slots for the protocol group to add new standard instruction groups without a Major Version bump. Vendor Extensions occupy `0xC0-0xFF` — 4 pages / 64 instruction slots. Slot count is not the constraint, because `Vendor_ID` (4 bytes) provides a theoretically unlimited namespace; different vendors can reuse the same INS slot and are distinguished by Vendor_ID without conflict.

### 1.2 Instruction Set Design Principles

- Instructions carry **verb semantics**, not technical jargon (`SVC_RESTART` rather than `EXEC_SYSTEMCTL`)
- Each instruction maps to exactly one atomic operation with no combined side effects
- All responses use **big-endian (network byte order)** byte streams for cross-platform consistency
- **Floating point is prohibited** in the protocol; all percentages and load values are expressed as scaled integers and restored by the consumer
- Vendor Extensions are freely defined by domain administrators and must be registered in the Capability Map to take effect; Standard ISA is defined by the ASys protocol group with permanently locked semantics
- **Platform neutrality**: ASys protocol semantic instructions describe operational intent without binding to specific implementation mechanisms. `asyd` is responsible for mapping semantic instructions to the host platform's native capabilities. The current reference implementation targets Linux, but the protocol is open to any POSIX-compatible system. When the target platform lacks the atomic primitives required to implement an instruction, `asyd` must not perform fuzzy simulation — it must return `0x6D00` (Instruction Not Supported), returning the decision to the agent.

### 1.3 Core ISA Detailed Definitions

The Core ISA is the constitutional layer of the ASys protocol. Its design goal is to provide deterministic observation primitives that remain stable for 50 years. Instructions `0x00-0x0F` are read-only with zero side effects; they can be called immediately after the Noise IK handshake without instruction-level signing.

#### 1.3.1 `0x00 SYS_CAPS` (Capability and Environment Discovery)

The agent's "awakening" instruction — defines what the agent can do (instruction bitmap) and the physical environment boundaries it operates within (static descriptors).

**Calling convention**: Must be called first after connection establishment. The agent should cache the response. If node capabilities change or the permission bitmap needs to be resynchronized, it can be called again at any time to refresh the local cache.

**Response layout (36 bytes)**:

| Byte | Field | Description |
|------|-------|-------------|
| `0-7` | Instruction Bitmap | First 4B: Core bitmap; next 4B: Extended bitmap. A bit value of 0 means the instruction is physically nonexistent from the agent's perspective |
| `8-9` | Protocol_Version | e.g., `0x0100` = v1.0 |
| `10-13` | Kernel_Hash | 4-byte kernel version digest for fast feature compatibility lookup |
| `14-17` | CPU_Static | `[2B core count] + [2B architecture code]` |
| `18-25` | Memory_Static | `[4B Total_RAM_MB] + [4B Total_Swap_MB]` |
| `26-31` | Storage_Static | `[4B Root_Size_MB] + [2B FS_Type_Code]` |
| `32` | RPI_Type | Pressure sensing type: `0x01`=NATIVE_KERNEL (kernel-native sampling, PSI-level precision), `0x02`=USER_SIMULATED (user-space simulation, inferred from load average), `0xFF`=NOT_AVAILABLE |
| `33` | Reserved | Reserved alignment byte |
| `34-35` | SW | `0x9000` |

#### 1.3.2 `0x01 SYS_HELLO` (Session Establishment and Clock Alignment)

A minimal session establishment primitive that answers "who are you" and "what time is it."

**Response layout (18 bytes)**:

| Byte | Field | Description |
|------|-------|-------------|
| `0-3` | Magic | `0x41535953` (ASCII: "ASYS") |
| `4-7` | Node_UID | Physical machine unique fingerprint |
| `8-15` | Server_Timestamp | Nanosecond Unix epoch, used for RTT and clock offset calculation |
| `16-17` | SW | `0x9000` |

#### 1.3.3 `0x02 SYS_STATUS` (Real-Time Vital Signs Snapshot)

Instantaneous system vital data for high-frequency calls (10Hz+), containing only dynamically changing physical quantities.

**Dependency note**: The `Mem_Dyn` field provides only the available value. The agent must hold the `Memory_Static` baseline from `SYS_CAPS` to calculate accurate memory utilization.

**Response layout (23 bytes)**:

| Byte | Field | Description |
|------|-------|-------------|
| `0-2` | CPU_Dyn | `[1B 1min load×10] + [1B 5min load×10] + [1B total usage%]` |
| `3-6` | Mem_Dyn | `[4B Available_MB]` |
| `7-11` | Store_Dyn | `[1B root partition usage%] + [4B IO_Wait_ms]` |
| `12-15` | Net_Dyn | `[2B Inbound_Mbps] + [2B Outbound_Mbps]` |
| `16` | RPI | Resource Pressure Index — a cross-platform normalized pressure indicator. `0x00`=no pressure, `0x64`=resources have caused complete task blocking (normalized ceiling, consistent semantics across all platforms), `0x65-0xFE` reserved, `0xFF`=NOT_SUPPORTED (only when `SYS_CAPS.RPI_Type=0xFF`). Both NATIVE_KERNEL and USER_SIMULATED types guarantee values in the `0x00-0x64` range; the agent should use `SYS_CAPS.RPI_Type` to determine trigger threshold precision |
| `17-20` | Reserve | 4-byte alignment padding, reserved for future pressure sensing extension fields |
| `21-22` | SW | `0x9000` |

#### 1.3.4 `0x03 SYS_PROCS` (Process Summary)

Used to quickly identify high-load target processes when the system is under abnormal pressure.

**Response layout (44 bytes)**:

| Byte | Field | Description |
|------|-------|-------------|
| `0-1` | Total_Procs | Current total number of processes on the system |
| `2-41` | Top 5 Slots | 5 process snapshots, 8 bytes each (see table below) |
| `42-43` | SW | `0x9000` |

**Individual slot structure (8 bytes)**:

| Byte | Field | Description |
|------|-------|-------------|
| `0-3` | PID | Process ID. `0x00000000` indicates an empty slot |
| `4-5` | CPU_Usage | Scaled by 100; precision 0.01% |
| `6` | MEM_Usage | Integer percentage |
| `7` | Status_Flag | `Bit0`=Zombie, `Bit1`=Unresponsive, `Bit2`=Privileged |

**Padding rule**: When fewer than 5 active processes exist, empty slots have their PID field filled with `0x00000000`.

### 1.4 Standard ISA and Vendor Extensions Overview

**Instruction layer summary:**

- **Protocol Control** (`0x10-0x1F`): Protocol-internal control instructions, reserved by the ASys protocol group; business use prohibited; no instruction-level signing required (`CLA.Sec=00`)
- **Standard ISA** (`0x20-0x8F`): Defined by the ASys protocol group with permanently locked semantics, covering general operations; instruction-level signing required (`CLA.Sec=01`)
- **Vendor Extensions** (`0xC0-0xFF`): Freely defined by domain administrators; effective after registration in the Capability Map

**Defined Standard ISA instructions (have side effects; require instruction-level signing):**

| Code | Name | Semantics | Scenario |
|------|------|-----------|----------|
| `0x20` | `PROC_THROTTLE` | Limit resource consumption of the target process; implementation determined by platform `asyd` | Emergency self-healing |
| `0x21` | `NET_ISOLATE` | Isolate network access of the target process; implementation determined by platform `asyd` | Emergency self-healing |
| `0x22` | `SVC_RESTART` | Restart the named service; implementation determined by platform `asyd` | Emergency self-healing |
| `0x40` | `LOG_SUMMARY` | Return high-priority system event summary | Diagnostics |
| `0x41` | `LOG_DETAIL` | Retrieve specific context by Event_ID | Diagnostics |
| `0x42` | `PROC_TREE` | Get parent-child relationships of a specific process | Diagnostics |
| `0x60` | `AGENT_ADD` | Register a new agent public key to the whitelist with inherited capability subset (`CLA.Sec=10`) | Identity management |
| `0x61` | `AGENT_REMOVE` | Remove an agent public key from the whitelist (`CLA.Sec=10`) | Identity management |
| `0x62` | `AGENT_LIST` | Query current whitelist summary (requires `CAP_DELEGATE`) | Identity management |

**Classification note**: `NET_ISOLATE` (`0x21`) is in the Process Control group rather than Network Control (`0x3x`) because its operation target is a **process** (isolating a process's network access), not network infrastructure itself. The Network Control group is reserved for instructions that operate on network entities (firewall rules, routing operations, port management).

`AGENT_ADD` / `AGENT_REMOVE` / `AGENT_LIST` (`0x60-0x62`) belong to the Security & Auth group. These three instructions together form ASys's **in-protocol identity management system** — allowing agents to autonomously manage the registration and permissions of other agents through the protocol, eliminating dependency on out-of-band SSH operations. Detailed design is in `docs/proposals/agent-auth-model.md`; full APDU layouts will be added in a subsequent release.

### 1.4.1 `0x20 PROC_THROTTLE` (Process Throttling)

Suspends or resumes execution of the target process. Execution mode is **synchronous** (`execution: sync`) — `0x9000` means the operation has completed; no Task_Handle is returned.

**Request layout:**

| Field | Value | Description |
|-------|-------|-------------|
| `CLA` | `0x04` | `Sec=01` (Signed); required for Standard ISA |
| `INS` | `0x20` | PROC_THROTTLE |
| `P1` | `0x00` | STOP: suspend the target process (sends SIGSTOP) |
|      | `0x01` | CONT: resume the target process (sends SIGCONT) |
| `P2` | `0x00` | Reserved |
| `Lc` | `0x08` | Seq(4B) + PID(4B) |
| `Data` | `[Seq(4B BE)][PID(4B BE)]` | Auth_Tag is stripped at the physical layer by the APDU parser; not counted in Lc |
| `Le` | `0x00` | Return SW only (fire-and-forget) |

**Response layout:**

Returns 2-byte SW only; no payload.

| Status | Meaning |
|--------|---------|
| `0x9000` | Success (SIGSTOP / SIGCONT delivered) |
| `0x6700` | Wrong Lc (must be `0x08`) |
| `0x6982` | Insufficient privileges (`CAP_KILL` not held, or target process rejected the signal) |
| `0x6A80` | Invalid target (PID=0, process does not exist, or P1 is invalid) |
| `0x6F00` | System error (other `kill()` failure) |

**Idempotency**: Sending SIGSTOP to an already-suspended process is a kernel-level no-op; sending SIGCONT to a running process is likewise harmless. Both directions satisfy the §1.5.2 idempotency constraint.

**Platform implementation note (Linux reference implementation)**: Currently implemented with `SIGSTOP` / `SIGCONT`. Compared to cgroup CPU quota approaches, the signal approach fully suspends the process rather than throttling it to a percentage. Production implementations can upgrade to cgroup v2 `cpu.max`; the semantic instruction remains unchanged, and the implementation is determined internally by `asyd`, transparent to the agent. See `asys-design-notes.md` ADR-19.

### 1.4.2 `0x22 SVC_RESTART` (Service Restart)

Restarts a named service. Execution mode is **asynchronous** (`execution: async`) — `0x9000` means the instruction was queued successfully; the response payload contains a 4-byte `Task_Handle`. The agent queries the final result using `0x11 TASK_QUERY`.

**Request layout:**

| Field | Value | Description |
|-------|-------|-------------|
| `CLA` | `0x04` | `Sec=01` (Signed); required for Standard ISA |
| `INS` | `0x22` | SVC_RESTART |
| `P1` | `0x00` | Reserved |
| `P2` | `0x00` | Reserved |
| `Lc` | `4 + N` | Seq(4B) + N bytes of service name (N ≤ 64) |
| `Data` | `[Seq(4B BE)][SvcName(NB)]` | See constraints below; Auth_Tag stripped at physical layer; not counted in Lc |
| `Le` | `0x06` | Expected response: Task_Handle(4B) + SW(2B) |

**SvcName constraints:**
- Character set: `[a-z0-9_\-.]` (valid systemd service name characters)
- Maximum length: 64 bytes
- **Must not include the `.service` suffix** — `asyd` appends it internally, eliminating path injection attack surface at the protocol layer
- Empty string or invalid characters return `0x6A80` (Wrong Data)

**Response layout:**

| Field | Length | Description |
|-------|--------|-------------|
| `Task_Handle` | 4B | `[Session_ID(16bit) | Random(16bit)]`; see lifecycle below |
| `SW` | 2B | `0x9000` = queued successfully |

**Idempotency guarantee:** If a Task_Handle with Pending status already exists for the same `SvcName` within the same session, `asyd` returns the existing handle directly without re-invoking `systemctl`, avoiding systemd unit lock contention.

### 1.4.3 `0x11 TASK_QUERY` (Task Status Query)

A Protocol Control group instruction; `CLA.Sec=00` (no signing required). The agent carries a `Task_Handle` to query the final execution result of an asynchronous task.

**Request layout:**

| Field | Value | Description |
|-------|-------|-------------|
| `CLA` | `0x00` | Plain; no signing required |
| `INS` | `0x11` | TASK_QUERY |
| `P1` | `0x00` | Reserved |
| `P2` | `0x00` | Reserved |
| `Lc` | `0x04` | Task_Handle length |
| `Data` | `[Task_Handle(4B BE)]` | Obtained from the async instruction response |
| `Le` | `0x03` | Expected response: Status(1B) + SW(2B) |

**Response layout:**

| Field | Length | Description |
|-------|--------|-------------|
| `Status` | 1B | Task status code (see table below) |
| `SW` | 2B | `0x9000` (the query itself succeeded; task status is expressed via Status) |

**Status codes:**

| Value | Meaning | Agent Handling Strategy |
|-------|---------|------------------------|
| `0x00` | Pending | Task is executing; retry later |
| `0x01` | Success | Execution complete; release handle |
| `0x02` | Failed | Execution failed (systemctl returned non-zero); raise alert |
| `0x03` | Timeout | Timed out (default 30 seconds); treat as failure |
| `0x04` | Cancelled | Task was cancelled (reserved for `0x12 TASK_CANCEL`) |
| `0xFF` | Handle Not Found | Handle is invalid, expired, or does not belong to the current session |

**Security boundary**: `asyd` verifies ownership via the Session_ID in the upper 16 bits of the Handle — querying a handle that does not belong to the current session always returns `0xFF`, leaking no task information.

**Interaction sequence example:**

```
1. Agent → asyd: SVC_RESTART("nginx") [Signed, Seq=42]
2. asyd  → Agent: Task_Handle=0x0001AABB, SW=0x9000  (queued; fork initiated)
3. Agent → asyd: TASK_QUERY(0x0001AABB) [Plain]       (poll after 3 seconds)
4. asyd  → Agent: Status=0x01 (Success), SW=0x9000   (systemctl exit code=0)
   → Handle released
```

### 1.4.4 Task_Handle Lifecycle

**Handle structure:** `uint32_t handle = (session_id << 16) | (rand() & 0xFFFF)`

- Upper 16 bits Session_ID: used for O(1) memory pool lookup and ownership verification
- Lower 16 bits random: prevents attackers from guessing handles belonging to other sessions

**Handle release conditions (any of the following triggers release):**
1. Released immediately when `TASK_QUERY` observes a terminal state (Success / Failed / Timeout / Cancelled)
2. Automatic release after 30-second timeout (regardless of whether it has been queried, regardless of state) — covers two scenarios: Pending timeout (the underlying operation is unresponsive) and terminal handle not retrieved in time (agent disconnected or logic stalled). After timeout, `TASK_QUERY` returns `Status=0xFF`
3. All handles belonging to a session are released immediately when that session's TCP connection closes

**Disconnect does not cancel semantics:** Handle expiry means only "abandoning the result retrieval," not canceling the underlying operation — once `fork/exec systemctl` is initiated, its execution proceeds independently of the transport layer connection state and cannot be aborted. After reconnecting, the agent cannot retrieve the result of that restart.

### 1.5 Execution Mode and Idempotency Constraints

#### 1.5.1 Synchronous and Asynchronous Execution Modes

Every Standard ISA instruction must declare its execution mode at definition time:

| Mode | Tag | Semantics |
|------|-----|-----------|
| Synchronous (Sync) | `execution: sync` | `0x9000` means the instruction has completed execution; the agent can immediately trust the result |
| Asynchronous (Async) | `execution: async` | `0x9000` means the instruction was queued successfully; the response payload contains a 4-byte `Task_Handle` |

**Follow-up for async instructions**: For `execution: async` instructions, the agent should use the Protocol Control group's `0x11 TASK_QUERY` instruction with the `Task_Handle` to query the final execution result.

**Why the distinction matters**: Many Standard ISA instructions (such as `SVC_RESTART`) are asynchronous at the kernel level — `asyd` returns immediately after calling the platform service manager, but the service may take several seconds to start or may fail. Without distinguishing execution modes, the agent's perception-decision loop would produce false readings because `SYS_STATUS` may not yet reflect the failure state.

#### 1.5.2 Idempotency Constraints

**All Standard ISA instructions must declare their idempotency at the protocol layer.**

Using `SVC_RESTART` as an example: when an agent retries due to network jitter, if the service is already running, a second invocation must not cause additional disruption.

Implementation strategy:
- Protocol layer: each Standard ISA instruction definition includes an `idempotent: true/false` tag
- Implementation layer: `asyd` checks the current system state before execution and only performs the operation when the state does not match the expected outcome

Idempotency constraints prevent agents from causing oscillating system state changes in high-frequency retry scenarios.

### 1.6 Status Word Specification (SW Status Word Specification)

The status word consists of 2 bytes (SW1, SW2) located at the end of every response frame. Its purpose is to allow agents to instantly determine whether "my instruction was wrong," "my permissions are insufficient," or "the system is struggling" — triggering different self-healing logic accordingly.

All status codes align with the ISO/IEC 7816 standard to reduce developer cognitive load.

| Status | Semantics | Agent Handling Strategy |
|--------|-----------|------------------------|
| `0x9000` | Success | Parse payload normally |
| `0x6400` | Execution Blocked | System transiently unavailable (buffer locked, self-protection triggered, etc.). Apply exponential backoff; distinguish transient from permanent failure |
| `0x6982` | Security: Access Denied | Agent identity is valid, but the operation on the target resource is unauthorized and was denied. Stop retrying; log security event |
| `0x6985` | Replay Detected | Within-session sequence number replay detected (`Seq <= last_seen_seq`). **Receiving this code does not mean the operation failed** — it means "this packet has already been received by the server." SDK retry handling: treat synchronous instructions as successfully executed; for asynchronous instructions (e.g., `SVC_RESTART`), query the most recently issued Task_Handle to confirm status rather than triggering error handling logic. See §2.2.4 |
| `0x6A80` | Wrong Data | Payload data is invalid (e.g., PID does not exist). Stop all retries for this parameter |
| `0x6A81` | Instruction Not Found | Instruction is not registered in the Capability Map; physically nonexistent. Trigger security audit; synchronize permission bitmap; stop all attempts |
| `0x6D00` | Instruction Not Supported | Instruction permission exists, but the current kernel/hardware lacks the capability to execute it. Graceful degradation; switch to fallback instruction |
| `0x6Fxx` | System Emergency | `asyd` execution layer encountered a kernel-level error; the low byte `xx` carries the specific error subcode (see table below). Activate circuit breaker; raise alert |

**`0x6Fxx` subcode definitions:**

| Status | Kernel Error | Semantics |
|--------|-------------|-----------|
| `0x6F00` | Generic system error | `asyd` internal error or unclassified system exception |
| `0x6F01` | `ENOMEM` | Kernel memory exhausted; node is near OOM |
| `0x6F02` | `EIO` | Underlying I/O error; storage or device failure |
| `0x6F03` | `ENOSPC` | Storage space exhausted |
| `0x6F04` | `ETIMEDOUT` | Kernel operation timed out (e.g., waiting for device response) |
| `0x6F05` | `EBUSY` | Resource locked by kernel; temporarily unavailable |
| `0x6FFF` | Unknown kernel error | Cannot be mapped to a known subcode; carries raw errno |

The `0x6Fxx` low byte allows agents to distinguish "protocol not supported" (`0x6D00`) from "underlying hardware/kernel failure" — the former warrants a graceful instruction switch; the latter warrants raising an infrastructure alert and suspending all operations on the node. `0x6F01` (ENOMEM) is the key signal for triggering a node emergency recovery procedure.

**Key distinction between `0x6982` and `0x6A81`:**

- `0x6A81` is a **physical boundary** — the instruction does not exist in the agent's view at all; triggers security audit
- `0x6982` is a **logical boundary** — the instruction exists but the operation on the target is unauthorized and was denied; triggers permission log
- The former means "I violated a boundary"; the latter means "the environment does not permit this"

### 1.7 Instruction Dispatcher Topology

The order in which status codes are triggered is not merely a return-value concern — it is a question of `asyd`'s core dispatch engine topology.

**Core principle: establish existence before verifying authorization.**

```c
void handle_request(agent_ctx *ctx, apdu_packet *pkt) {
    // First gate: existence check, O(1) bitmap comparison
    if (!is_instruction_in_bitmap(ctx->cap_map, pkt->ins_code)) {
        send_response(ctx, SW_NOT_FOUND);   // 0x6A81
        return;
    }

    // Second gate: fine-grained permission check
    if (!check_permission(ctx, pkt)) {
        send_response(ctx, SW_ACCESS_DENIED);  // 0x6982
        return;
    }

    // Third step: fully authorized; dispatch for execution
    instruction_handler handler = get_handler(pkt->ins_code);
    handler(ctx, pkt);
}
```

**Three strategic advantages:**

**1. Minimal compute overhead**: Bitmap comparison (bitwise AND) is a machine-code-level operation. Under large-scale malicious probing, `asyd` can reject 99% of unauthorized requests at minimal CPU cost.

**2. Side-channel attack prevention**: If permission were checked before existence, an attacker could infer which instructions "exist but are disabled" by observing subtle response time differences, thereby reverse-engineering the system's capability boundary. Checking existence first makes all unauthorized operations externally indistinguishable, eliminating the information leakage surface.

**3. Multi-tenant isolation**: Different agents can be deployed with completely different instruction spaces, achieving true multi-tenant isolation without any additional permission isolation layer.

### 1.8 Vendor Extension Specification

#### 1.8.1 Self-Describing Instruction Frame Format

When `INS >= 0xC0`, `asyd` forcibly parses in Vendor mode. `Vendor_ID` (4 bytes) is at the head of the payload; each instruction is fully self-describing with no session state switching required:

```
[CLA][INS][P1][P2][Lc][Vendor_ID(4B)][Actual_Data][Le]
                       └─ first 4 bytes of Payload are forced to be Vendor_ID ─┘
```

`asyd` dispatch logic: when `INS >= 0xC0` is detected, the first 4 bytes of the payload are read directly as `Vendor_ID`; the session's vendor whitelist is queried to locate the corresponding function table; O(1) dispatch is performed.

**Stateless guarantee**: Each Vendor instruction carries complete routing information; network jitter, packet reordering, or retransmission does not affect dispatch correctness.

#### 1.8.2 Vendor_ID Space Division

| Range | Name | Allocation |
|-------|------|------------|
| `0x00000000-0x000003FF` | Gold zone (1,024 IDs) | Manually allocated by ASys; zero-collision guaranteed |
| `0x00000400-0x0000FFFF` | Registered zone | Application-based; for core ecosystem vendors |
| `0x00010000-0xFFFFFFFF` | Hash zone | Self-derived: `CRC32("vendor-domain.com") OR 0x00010000` |

**Collision handling**: Agents verify during the `SYS_CAPS` handshake that the Vendor information returned by the node matches expectations. If a hash collision is detected, the connection is rejected and a report is raised.

#### 1.8.3 Dynamic Filtering Mechanism

`asyd`'s dispatch loop uses a **two-phase read** strategy when receiving Vendor instructions to prevent oversized payloads from overflowing the memory pool:

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

**Security guarantee**: Only Vendor data that has passed whitelist verification enters the memory buffer. Attackers cannot overflow `asyd`'s memory pool by constructing oversized payloads.

**Hard limit on Vendor payload memory quota:**

`asyd` must impose a hard upper bound on Vendor Extension payload size to prevent large payloads from competing with the Core/Standard ISA static memory pool:

- Standard frame (`CLA.Ext=0`): Lc ≤ 255 bytes; no additional constraint needed
- Extended frame (`CLA.Ext=1`): Vendor Extension Lc cap is **16,384 bytes (16KB)**; exceeding this returns `0x6700` (Wrong Length)

Vendor Extension payloads must be read and processed in a **separate, bounded memory region** and must not reuse the Core/Standard ISA static APDU buffer pool. Physical isolation ensures that Vendor extension memory pressure does not affect the execution path of core instructions. See `impl-notes.md` §1.3 for implementation details.

### 1.9 Protocol Evolution Principles

The following principles are mandatory constraints for all future ASys implementers and protocol maintainers, ensuring backward compatibility over decades of protocol evolution.

**Principle 1: Offset Immutability**

Unless a Major Version Bump occurs, the byte offsets of any existing Core ISA instruction fields must not be modified. New fields may only occupy Reserve space or extend at the end of the response (before SW).

**Principle 2: Silent Ignore**

Agents must be able to safely ignore undefined Reserve fields in responses; servers must be able to ignore undefined padding bits in requests. Neither party may close the connection or return an error upon encountering an unknown field. This is the foundation of forward compatibility.

**Principle 3: Atomic Replacement**

If a core metric becomes obsolete (e.g., an older kernel no longer supports a field), the server should fill it with a predefined sentinel value (`0xFF` or `0x0000` depending on field type) rather than removing the field or shortening the response. Total response byte length never changes within the same protocol version.

**Principle 4: Major Version Transition**

When breaking offset immutability is genuinely necessary, the new version number must be declared via the `Protocol_Version` field (bytes 8-9) in the `SYS_CAPS` response. Older version servers must continue to support the old format response for at least one complete major version cycle to provide a smooth migration window for agents.

---

## 2. Security Model

ASys's security architecture has four layers, forming defense in depth from transport to execution.

### 2.1 Transport Security: Noise Protocol IK

ASys foregoes mTLS's dependency on the PKI certificate infrastructure and uses **Noise Protocol Pattern IK** as the transport security mechanism. Its core advantage is zero certificate dependency, pure cryptographic primitives (Curve25519 + ChaCha20-Poly1305 + BLAKE2b), implementable via a single pure-C library on any POSIX-compatible system.

**Forward secrecy boundary**: Noise IK session keys are derived with the participation of the initiator's ephemeral key (`e`), generated independently for each handshake — compromising the server's static private key **does not decrypt historical session content**. The known limitation is that the agent's static public key is transmitted during the handshake encrypted under the server's static public key — if the static private key is compromised, the agent identities (static public keys) in historical handshake packets could theoretically be recovered. This is a known tradeoff of IK mode in exchange for 1-RTT handshake and early handshake identity verification, not an implementation defect. Future versions plan to introduce a Rekey mechanism to periodically refresh session keys, further narrowing the impact window of static key compromise.

#### 2.1.1 Server Key Management (asyd node side)

`asyd` automatically generates key material on first start, stored in `/etc/asyd/`:

```
/etc/asyd/                   # permissions 0700, owner: root (production)
├── id_curve25519            # Curve25519 static private key, permissions 0600; never leaves the node
├── id_curve25519.pub        # Curve25519 static public key, permissions 0644; actively pushed by asyd via Pre-Handshake Frame before the handshake
└── authorized_agents        # Agent public key whitelist; one hex public key per line; maintained manually by the administrator
```

Analogous to SSH host key management — the private key never leaves the node; the public key is actively pushed by `asyd` when a connection is established (see §3.3.0 Pre-Handshake Frame), requiring no out-of-band distribution.

**One machine, one identity**: `id_curve25519` is the node's identity root. When cloning a virtual machine, this file must be deleted — `asyd` will automatically generate a new key pair on first start, giving the cloned node an independent identity and preventing multiple nodes from sharing a public key fingerprint, which would cause Capability Map conflicts.

#### 2.1.2 Client Key Management (Agent Side)

Each agent generates its own Curve25519 static key pair at initialization, stored in `~/.asys/`:

```
~/.asys/                     # permissions 0700
├── id_curve25519            # Curve25519 static private key, permissions 0600; never leaves the agent environment
├── id_curve25519.pub        # Curve25519 static public key, permissions 0644
└── known_hosts              # Fingerprint records of trusted asyd nodes (analogous to SSH known_hosts)
```

**Comparison with SSH:**

```
SSH                              ASys
────────────────────             ────────────────────
~/.ssh/id_ed25519                ~/.asys/id_curve25519
~/.ssh/id_ed25519.pub            ~/.asys/id_curve25519.pub
~/.ssh/known_hosts               ~/.asys/known_hosts
ssh-keygen                       asys-keygen
~/.ssh/authorized_keys           /etc/asyd/authorized_agents
```

**`known_hosts` format**: One record per line, space-separated:

```
# <host>:<port>  <server_pub_key_hex_64chars>
192.168.0.217:7816  <server-public-key-hex>
10.0.1.42:7816      <server-public-key-hex>
```

**Significance at scale**: With 1,000 agents, each runs `asys-keygen` at initialization to generate an independent identity; the administrator writes the agent public keys to `/etc/asyd/authorized_agents` on each node; thereafter agents connect automatically using their keys. The administrator only needs to maintain `authorized_agents` — the same mental model as managing SSH `authorized_keys`.

#### 2.1.3 Agent Authentication

`asyd` uses a **public key whitelist** model: after the handshake completes, it checks whether the agent's static public key is in `/etc/asyd/authorized_agents`; if not, it returns `0x6982` and closes the connection.

**Agent registration flow:**

1. Agent runs `tools/client/asys_keygen.py` to generate the `~/.asys/` key pair
2. Administrator writes the agent public key to the node whitelist:
   ```bash
   # Direct append
   echo "<agent_pub_key_hex>" >> /etc/asyd/authorized_agents
   # Or copy via SSH
   cat ~/.asys/id_curve25519.pub | ssh user@host "cat >> /etc/asyd/authorized_agents"
   ```
3. The agent connects with its key and passes the handshake directly; no additional steps required

**Connection flow (Client-Speak-First, from v0.3.1):**

1. Client initiates TCP connection
2. **Agent sends 4-byte Magic** (`0x41535953`); 1-second timeout; mismatch causes `asyd` to silently disconnect
3. **`asyd` sends Pre-Handshake Frame (38 bytes, plaintext)**: `[Magic(4B)][Version(2B)][ServerPubKey(32B)]`
4. Client displays server public key fingerprint; on first connection, writes to `~/.asys/known_hosts` after confirmation; subsequent connections verify automatically
5. Client completes **Noise IK handshake**, establishing the encrypted channel
6. `asyd` checks whether the agent public key is in the whitelist; if not, returns `0x6982`
7. Verification passed; enter business instruction processing

**Analogy with SSH:**

```
SSH                              ASys
────────────────────             ────────────────────
First connect shows server       First connect shows server
  fingerprint                      public key fingerprint
User confirms → known_hosts      User confirms → ~/.asys/known_hosts
        ↓                                 ↓
ssh-copy-id writes public key    Admin writes to authorized_agents
        ↓                                 ↓
Subsequent passwordless login    Subsequent connections pass handshake directly
```

### 2.2 Instruction Security: CLA Security Marking and Replay Protection

#### 2.2.1 CLA Byte Security Bits (Derived from ISO 7816 Part 8)

Borrowing from ISO 7816's secure messaging mechanism, bits 3-2 of the CLA byte mark the security level of the instruction:

| CLA bit3-2 | Semantics | Applicable Scope |
|------------|-----------|-----------------|
| `00` | No additional signing; Noise channel encryption is sufficient | Core ISA / Protocol Control |
| `01` | Instruction is signed; must verify signature before execution | Standard ISA |
| `10` | Instruction is encrypted + signed; high-sensitivity operations | Vendor ISA / Security group |
| `11` | Reserved | — |

`asyd` can determine the signature verification path from the CLA when parsing the APDU frame header, without reading the payload — signature verification happens before any business logic.

#### 2.2.2 Secure Frame Data Field Layout

When `CLA bit3-2 = 01` or `10`, the `Data` field layout is mandated as follows:

```
Data = [Seq(4B BE)] + [Payload]
```

| Offset (within Data) | Length | Field | Description |
|----------------------|--------|-------|-------------|
| `+0` | 4 | `Seq` | 32-bit big-endian monotonically increasing sequence number; starts at 1 per session; must be greater than `Last_Seen_Seq` |
| `+4` | Lc-4 | `Payload` | Instruction business data |

Minimum `Lc = 0x04` (4 bytes: Seq only, no business data). Auth_Tag is not in the Data field — it is appended at the physical end of the frame (after the `Le` field) and is not counted in `Lc` (see §3.1.2).

**Note**: `Epoch_ID` is not transmitted in the frame; it is independently derived by both parties from the Noise IK handshake key (see §2.2.3) and participates only in Auth Tag computation.

#### 2.2.3 Instruction Signing Algorithm (Auth Tag)

**Epoch_ID derivation (performed immediately after handshake):**

```
Epoch_ID = HMAC-BLAKE2b(recv_key, "asys-epoch-v1")[:4]
```

- `Epoch_ID` is derived from the Noise IK handshake key and **is never transmitted over the network**; both parties independently compute the same value
- Each handshake produces a unique `Epoch_ID`; sessions have different `Epoch_IDs`; cross-session replay is cryptographically invalid
- The server derives it immediately after `noise_ik_write_msg2()` returns and stores it in SessionCtx

**Algorithm definition:**

```
Auth_Tag = HMAC-BLAKE2b(recv_key, CLA || INS || P1 || P2 || Lc || Epoch_ID || Seq || Payload)[:16]
```

- `recv_key`: the session key for the agent-to-server direction from the Noise IK handshake (i.e., `asyd`'s recv_key)
- `Epoch_ID`: 4 bytes, derived from recv_key; mixed into the HMAC to ensure cross-session replay is cryptographically invalid
- The signature covers the complete 5-byte header + Epoch_ID + Seq + Payload; any tampered field causes verification to fail
- The first 16 bytes are taken to match the Auth Tag placeholder length without changing the frame format

**Verification flow (asyd side):**

```
1. Check frame->sec != PLAIN; Plain frames skip verification
2. Extract fields: Header(5B), Epoch_ID(4B, read from SessionCtx), Seq(4B), Payload, Auth_Tag(16B)
3. Compute Expected_Tag = HMAC-BLAKE2b(recv_key, Header||Epoch_ID||Seq||Payload)[:16]
4. crypto_verify16(Expected_Tag, Received_Tag)  ← constant-time comparison; prevents timing attacks
5. Verification fails → return 0x6982, close connection (security event)
6. Verification passes → check Seq > last_seen_seq (SessionCtx in memory); otherwise return 0x6985
7. Update last_seen_seq; execute instruction
```

**Constant-time comparison (mandatory requirement):**

`crypto_verify16()` (built into Monocypher) must be used; `memcmp()` is prohibited. `memcmp()` returns early upon finding the first mismatched byte, allowing attackers to infer the Auth Tag byte by byte through response time differences.

#### 2.2.4 Replay Protection: Epoch_ID + Within-Session Monotonic Sequence Number

ASys uses a **two-layer replay protection mechanism — Epoch_ID + within-session Seq** — with no dependency on disk persistence.

**Replay protection layers:**

| Layer | Mechanism | Defense Target |
|-------|-----------|---------------|
| Cross-session | `Epoch_ID` mixed into Auth Tag | Captured packet from old session replayed in new session → HMAC verification fails directly (`0x6982`) |
| Within-session | `last_seen_seq` in-memory comparison | Captured packet from current session replayed in same session → returns `0x6985` |

**Seq semantics:**

- Seq starts at 1 and resets with each handshake (does not accumulate across sessions)
- Server maintains only `last_seen_seq` in memory (SessionCtx); not persisted to disk
- After a server crash and restart, the agent reconnects and obtains a new `Epoch_ID`; Seq restarts from 1; old packets automatically become invalid

**`0x6985` response format:**

Standard 2-byte response: `[SW1=0x69][SW2=0x85]`

Receiving `0x6985` means "this Seq has already been received by the server" — **it does not mean the operation failed**. Agents and SDKs must handle it differently based on instruction type:

- **Synchronous instructions** (`execution: sync`): treat as successfully executed; equivalent to receiving `0x9000`
- **Asynchronous instructions** (`execution: async`, e.g., `SVC_RESTART`): the previous send was received, but the response was lost in transit. The SDK should query the most recently issued Task_Handle to confirm execution status rather than triggering error handling or alerts

**Network retransmission scenario (most common trigger):**

```
① Agent sends SVC_RESTART (Seq=42)
② asyd queues and returns Task_Handle + 0x9000
③ Response packet is lost in transit; Agent does not receive it
④ SDK times out and retransmits; sends SVC_RESTART again (Seq=42)
⑤ asyd detects Seq=42 has already been seen; returns 0x6985
⑥ Agent SDK recognizes 0x6985 as "already delivered" semantics;
   queries the most recent Task_Handle → obtains execution status
```

The idempotency guarantee of `SVC_RESTART` (returning the existing handle when the same service name is sent within the same session) complements this scenario: if `asyd` does not trigger replay detection in step ④ (Seq has incremented), the idempotency guarantee prevents a second fork; if replay detection is triggered (Seq unchanged), the `0x6985` semantics direct the agent to check the handle — neither path produces additional side effects.

**Abnormal scenario handling:**

| Scenario | Behavior |
|----------|----------|
| Normal reconnect after disconnect | New handshake produces new `Epoch_ID`; Seq restarts from 1; passes automatically |
| Network retransmission (Seq unchanged) | Returns `0x6985`; SDK handles by instruction type (see above) |
| Genuine within-session replay | Same as above; `asyd` behavior is identical; agent-side semantics are the same |
| Cross-session replay | `Epoch_ID` differs; HMAC verification fails; returns `0x6982` |
| Server crash and restart | In-memory Seq lost; agent reconnects and obtains new `Epoch_ID`; old packets automatically invalid |

### 2.3 Permission Model: Capability Map

After the Noise handshake completes and identity is confirmed, `asyd` looks up the Capability Map corresponding to the agent's static public key.

- **Capability Map**: Each agent identity has a corresponding instruction bitmap with per-instruction permission granularity
- Instruction calls outside the Capability Map return `0x6A81` (Instruction Not Found)
- Unauthorized operations return `0x6982` (Access Denied)
- The dispatch topology follows §1.7: existence check → permission check → execution

> **Note**: The current implementation uses a single global bitmap (`CORE_CAPS_BITMAP` / `EXT_CAPS_BITMAP`); all agents that pass the whitelist share the same instruction set. Per-agent fine-grained bitmaps (different agents holding different instruction permissions) are planned for a future release. *(planned, not in v1.0)*

#### 2.3.1 Permission Check Timing: POSIX File Descriptor Model

ASys's permission check semantics align exactly with POSIX `open()` — **authorization at enqueue time; authorization is not retroactive**:

| Operation | Permission Check | Analogy |
|-----------|-----------------|---------|
| New instruction enqueue | Re-run `check_permission` | `open()` checks file permissions at call time |
| Task_Handle during execution | No re-check; continue executing | An already-opened fd is not affected by subsequent `chmod` |
| `0x12 TASK_CANCEL` instruction | Must hold cancel permission; re-check | `ioctl/close` requires a valid fd |

**Permission change effective point**: Affects only the permission check for newly enqueued instructions; does not retroactively affect in-progress tasks that have already obtained a Task_Handle. To forcibly interrupt an in-progress task, `0x12 TASK_CANCEL` must be used as an explicit intervention.

### 2.4 Three-Layer Execution Defense

**Layer 1: Semantic Isolation**

Agents operate on semantic instructions (`SVC_RESTART`), not command strings. `asyd` internally maintains a fixed mapping from semantic instructions to platform-native calls; the agent has no visibility into the backend implementation — command injection attack surface is eliminated by design.

**Layer 2: Behavioral Whitelist**

For instructions that require passing parameters, the parsing layer maintains strict parameter constraint tables, blocking path traversal, wildcards, shell metacharacters, and other invalid inputs.

**Layer 3: Resource Control Domain Sandbox**

When executing Standard ISA instructions, the operation context is strictly confined to the resource control domain bound to the Capability. The Linux reference implementation uses cgroup/namespace; other platforms have `asyd` map to equivalent mechanisms. Even if both previous layers fail simultaneously, the host system remains safe.

> **Note**: This layer is a design goal; it is not yet implemented in the current version and is planned for a future release. *(planned, not in v1.0)*

### 2.5 Audit Black Box

> **Note**: This section describes design goals; it is not yet implemented in the current version and is planned for a future release. *(planned, not in v1.0)*

**All APDU instruction streams form a tamper-proof operation ledger.**

#### 2.5.1 Append-Only Log

Audit logs are enforced as append-only via platform mechanisms:

- Linux: `chattr +a`
- FreeBSD: `flags sappnd`

No agent instruction can modify or delete already-written audit records, even if the agent holds elevated privileges.

#### 2.5.2 Write-Before-Execute Ordering

Audit shadow port push must occur before or synchronously with instruction execution:

```
1. Write audit entry (local append-only; fsync)
2. Push to shadow port (optional; see modes below)
3. Execute instruction
4. Record execution result
```

**Non-blocking write requirement (mandatory constraint):**

Audit write-to-disk operations **must never synchronously block the execution path**. Under extreme conditions where disk I/O is hung or the filesystem is read-only — precisely the scenarios where `asyd` is called as an emergency interface — synchronously waiting for disk writes would deadlock the execution path: the "emergency interface" would be killed by the very "disk hang" it was trying to help recover from.

Mandatory implementation requirements:
- Audit writes must use **non-blocking I/O** (`O_NONBLOCK`) or a separate write thread, with a write timeout ceiling of **100ms**
- If the timeout expires before completion, immediately fall back to an in-memory ring buffer (see §4.2 degradation mechanism); **do not block instruction execution**
- Core ISA instruction (`0x00-0x0F`) and Protocol Control instruction (`0x10-0x1F`) execution paths must not wait for any audit I/O

For specific non-blocking implementation details, see `impl-notes.md` §4.

**Audit modes by instruction group:**

| Instruction Range | Default Mode | Description |
|-------------------|-------------|-------------|
| `0x00-0x1F` Core + Protocol | Bypass mode | Low-risk operations; write local audit then execute immediately; push asynchronously |
| `0x20-0x8F` Standard ISA | Strict mode | Execute after push confirmation; push failure returns `0x6400` |
| `0x90-0xBF` Standard ISA Reserved | Strict mode | Same as above; cannot be downgraded to bypass mode |
| `0xC0-0xFF` Vendor Extensions | Strict mode | Same as above; cannot be downgraded to bypass mode |

Administrators may override the default mode for Standard ISA, but strict mode for Vendor Extensions is a mandatory constraint.

On push failure, `0x6400` (Execution Blocked) is returned with the semantics of "Audit Sync Failure" — the agent should apply exponential backoff, distinguishing transient audit system failures from permanent failures.

#### 2.5.3 Audit Degradation and AUDIT_DEGRADED Flag

When audit logs cannot be persistently stored (disk full, write failure, etc.), `asyd` must enter degraded mode; **all response frames must set the `AUDIT_DEGRADED` warning flag**, notifying the agent that it is currently operating under degraded auditing.

`asyd` implementers must provide at least one degradation mechanism (e.g., in-memory buffer, shadow port forwarding) to ensure the system can maintain an observable operational state when audit storage fails, rather than silently failing. For specific tiered degradation strategies, see `impl-notes.md` §4.

**Emergency exemption whitelist**: Administrators may define an emergency exemption instruction list via startup parameters (planned); these instructions can still be executed when audit storage has completely failed, but must be pushed synchronously to a shadow port.

#### 2.5.4 Audit Record Format

Each audit record contains:

```
[Timestamp(8B)][Agent_PubKey_Hash(4B)][INS(1B)][CLA(1B)][Seq(4B)][Param_Digest(4B)][SW(2B)]
Total: 24 bytes, fixed length
```

Binary fixed-length format prevents format injection from text logs; can integrate directly with SIEM systems.

---

## 3. Protocol Specification (ASys-APDU)

> **Deployment prerequisite**: ASys's low-latency advantage depends on direct connection to `asyd`'s dedicated port (default TCP 7816). In restricted network environments, ASys traffic can be carried over an SSH tunnel, but the double-encryption and tunnel buffering will significantly offset the protocol's latency advantage — SSH tunneling is an emergency compatibility mode, not the recommended production deployment approach.

ASys borrows the APDU structural layout from ISO/IEC 7816 but redefines the CLA byte bit fields to optimize machine-to-machine efficiency, and does not fully follow ISO 7816's industry classification semantics.

### 3.1 Frame Layout and CLA Bit Fields

#### 3.1.1 Standard Frame Format

```
[CLA][INS][P1][P2][Lc][Data][Le]
  1    1    1   1   1   var   1   (bytes)
```

| Field | Length | Description |
|-------|--------|-------------|
| `CLA` | 1 byte | Instruction class; bit fields defined below |
| `INS` | 1 byte | Instruction code (see §1 encoding space) |
| `P1` | 1 byte | Parameter 1 |
| `P2` | 1 byte | Parameter 2 |
| `Lc` | 1 byte | Byte count of the Data field (standard frame, excluding Auth Tag) |
| `Data` | var | Instruction data (includes Seq, Vendor_ID, and other security fields) |
| `Le` | 1 byte | Expected response length. `0x01-0xFE`=expect N bytes; `0xFF`=expect maximum length (255 bytes); `0x00`=return SW only; no data expected (fire-and-forget) |

#### 3.1.2 CLA Byte Bit Field Definitions

| Bit | Name | Semantics |
|-----|------|-----------|
| `7-5` | Ver | Protocol major version; currently `000` (v1.x) |
| `4` | M | More Data chaining flag. `1`=more fragments follow; `0`=last frame or single frame |
| `3-2` | Sec | Secure messaging mark. `00`=Plain, `01`=Signed, `10`=Enc+Sign, `11`=Reserved |
| `1` | Ext | Extended frame flag. `1`=extended frame (Lc is followed by 2-byte actual length); `0`=standard frame |
| `0` | RFU | Reserved; always `0` |

**Auth Tag position and MAC coverage**: When `Sec != 00`, the 16-byte Auth Tag (HMAC-BLAKE2b, see §2.2.3) is **always appended at the physical end of the entire frame** (after the `Le` field) and is not counted in `Lc`:

```
Secure frame:   [CLA][INS][P1][P2][Lc][Data][Le][Auth Tag(16B)]
Standard frame: [CLA][INS][P1][P2][Lc][Data][Le]
```

MAC coverage is the complete 5-byte header (`CLA||INS||P1||P2||Lc`) + `Epoch_ID` (4B, derived value, not transmitted in the frame) + `Seq` + `Payload`:

```
HMAC-BLAKE2b(recv_key, CLA||INS||P1||P2||Lc||Epoch_ID||Seq||Payload)[:16]
```

The `Le` field is not within MAC coverage. Placing Auth Tag at the end completely eliminates the risk of `Le` field tampering leading to out-of-bounds reads, while also enabling **zero-copy** forwarding.

### 3.2 Length Encoding Switching

#### 3.2.1 Standard Frame (Lc ≤ 255 bytes)

```
[CLA][INS][P1][P2][Lc(1B)][Data(Lc bytes)][Le(1B)]
```

`Lc` directly represents the byte count of the Data field; maximum 255 bytes.

#### 3.2.2 Extended Frame (CLA.Ext = 1, explicitly triggered)

When the Data field exceeds 255 bytes, the sender sets `CLA bit1 = 1`:

```
[CLA(Ext=1)][INS][P1][P2][0x00][Lc_high][Lc_low][Data][Le_high][Le_low]
```

- The `Lc` field is fixed at `0x00` (placeholder); the actual length is represented by the following `Lc_high`, `Lc_low`
- Maximum Data field: 65,535 bytes
- Extended frame `Le` is expanded to 2 bytes; `0x0000` means "return SW only"

### 3.3 Connection Establishment and Authentication

#### 3.3.0 Pre-Handshake Frame (Server Identity Broadcast Before Handshake)

**Connection establishment flow (Client-Speak-First, from v0.3.1):**

```
TCP handshake complete
  → Agent sends 4-byte Magic (0x41535953)
  → asyd verifies Magic (1-second timeout, hardcoded)
  → asyd sends 38-byte Pre-Handshake Frame
  → Noise IK handshake
```

After `accept()`, `asyd` waits for the client to send the Magic; the timeout is hardcoded at **1 second**. A mismatched or timed-out Magic causes an immediate disconnect without sending any data. This design reduces the likelihood of generic port scanners triggering a server response; fundamental defense against connection exhaustion attacks relies on the network layer (configuring `iptables` rate limiting is recommended).

After TCP connection establishment and before the Noise IK handshake, `asyd` sends a **38-byte plaintext frame** to the agent:

```
[Magic(4B)][Version(2B)][ServerPubKey(32B)]
```

| Field | Length | Description |
|-------|--------|-------------|
| `Magic` | 4B | `0x41535953` (ASCII: "ASYS"); prevents accidental connection to non-ASys services |
| `Version` | 2B | Protocol version number; e.g., `0x0100` = v1.0; client should disconnect if incompatible |
| `ServerPubKey` | 32B | Server Curve25519 static public key raw bytes |

**Client processing flow:**

1. Verify `Magic == 0x41535953`; disconnect if mismatched (accidentally connected to wrong port)
2. Verify `Version` compatibility; disconnect if incompatible
3. Check `~/.asys/known_hosts`:
   - No record (first connection): display public key fingerprint; wait for user confirmation; write to `known_hosts`
   - Record present and matching: silently proceed
   - Record present but mismatched: print warning; reject connection (man-in-the-middle prevention)
4. Use `ServerPubKey` as the server static public key for the Noise IK handshake

**Security note**: Transmitting `ServerPubKey` in plaintext carries no security risk — public keys are public by definition; security depends on the fingerprint confirmation step. This is exactly the same mechanism as SSH transmitting its public key in plaintext during first connection.

> **SDK mandatory constraint**: The "wait for user confirmation" in step 3 **must not be automated by the SDK** (automatic TOFU is prohibited). When `known_hosts` has no record, the SDK must abort the connection and raise an exception, leaving the decision of how to handle first-connection trust establishment to the caller. Automatically writing an unconfirmed fingerprint means in-network ARP spoofing or DNS poisoning is sufficient to hijack the connection. In production, it is recommended to pre-inject node public keys into `known_hosts` via configuration management tools (Ansible / K8s Secret / Vault), eliminating the need for interactive first-connection confirmation.

#### 3.3.1 Noise IK Handshake Sequence

The Noise IK handshake occurs immediately after TCP connection establishment; it consists of 2 messages (1-RTT):

```
Agent → asyd:  [e, es, s, ss]
                 ↑   ↑  ↑  ↑
                 Agent ephemeral public key
                     DH with asyd static key
                        Agent static public key (encrypted)
                           DH of both static keys

asyd → Agent:  [e, ee, se]
                 ↑   ↑  ↑
                 asyd ephemeral public key
                     DH of both ephemeral keys
                        DH of asyd static and agent ephemeral
```

After the handshake, both parties hold symmetric session keys; all subsequent APDU frames are transmitted within this encrypted channel.

**Handshake first-packet replay defense (Bloom Filter deduplication)**

> **Note**: Not yet implemented in the current version; planned for a future release. *(planned, not in v1.0)*

```c
if (bloom_filter_check(e_pub_hash)) {
    close_connection();  // silently discard; allocate no resources
    return;
}
bloom_filter_add(e_pub_hash);
```

**Segmented dual-filter (prevents false positive rate accumulation)**

```
Maintain two filters: Current and Previous
Query: Current OR Previous → if present, reject (covers 2.5–5 minute window)
Write: only to Current
Rotate every 2.5 minutes: Previous = Current, Current = new empty filter
```

#### 3.3.2 SYS_HELLO ABANDON_ALL Cleanup Flag

> **Note**: Not yet implemented in the current version; planned for a future release. *(planned, not in v1.0)*

The `SYS_HELLO` request payload carries a 1-byte Flags field:

```
SYS_HELLO request payload:
[Client_Timestamp(8B)][Flags(1B)]
                        bit0 = ABANDON_ALL
```

When `ABANDON_ALL=1`, `asyd` immediately releases zombie buffers matching the agent's static public key hash, completing this before returning `0x9000`, ensuring that the agent has a clean memory environment from the first millisecond after reconnecting.

### 3.4 Chained Transport Specification

> **Note**: Not yet implemented in the current version; planned for a future release. *(planned, not in v1.0)*

#### 3.4.1 M-Bit State Machine

```
Frame 1: CLA.M=1, INS=target, Lc=65535, Data=[first chunk]
         → asyd returns Task_Handle(4B) + SW=0x9000
Frame 2: CLA.M=1, INS=0x10, Data=[Task_Handle(4B)][next chunk]
         → asyd returns SW=0x9000 (continue waiting)
Frame N: CLA.M=0, INS=0x10, Data=[Task_Handle(4B)][last chunk]
         → asyd triggers execution; returns final result
```

`Task_Handle` is strictly bound to the originating session; internal data structures are described in `impl-notes.md` §5. The final status of async tasks is queried via `0x11 TASK_QUERY` with `Task_Handle` as the payload.

#### 3.4.2 Timeout and Packet Loss Handling

- Default timeout: **30 seconds** (planned to be configurable via `--chain-timeout` startup parameter)
- If the agent sends a continuation after timeout: returns `0x6A80` (Invalid Handle)

### 3.5 Exception Handling Priority

| Priority | Check | Status Word |
|----------|-------|-------------|
| 1 (highest) | CLA version not supported | `0x6E00` |
| 2 | Lc/Le length invalid | `0x6700` |
| 3 | Auth Tag verification failed | `0x6982` |
| 4 | Sequence number replay detected | `0x6985` |
| 5 | Instruction not found (bitmap query) | `0x6A81` |
| 6 | Insufficient permission | `0x6982` |
| 7 | Invalid parameter | `0x6A80` |
| 8 (lowest) | Execution layer error | `0x6Fxx` (low byte carries kernel error subcode; see §1.6) |

### 3.6 Version Negotiation and Migration

- **CLA.Ver**: carried in every frame; `asyd` selects the parsing path accordingly
- **Protocol_Version**: returned via `SYS_CAPS` after the handshake

Backward compatibility strategy: when an older node receives a frame with a higher CLA.Ver, it returns `0x6E00`; the agent should retry with a downgraded version.

### 3.7 Byte Order and Alignment Requirements

**Mandatory big-endian (network byte order)**: All 2B/4B/8B multi-byte fields must be encoded in big-endian.

**No implicit padding**: All frame structures must be manually padded to 4-byte or 8-byte boundaries at definition time; relying on compiler-automatic alignment is prohibited.

**Verification requirement**: The test specification must include cross-language byte order verification test cases — the same frame constructed by both a C client and a Python client must produce identical parse results in `asyd`.

---

*This specification is continuously updated as the project evolves. Protocol version v1.0.*
