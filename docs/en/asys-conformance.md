# ASys Conformance Test Guide
## Agentic System Interface — Conformance Test Guide

> This document defines "what constitutes an ASys-compliant implementation."
> Third-party implementations (e.g., asyd-rust, asyd-go) must pass all tests defined in this document
> to use the "ASys Certified" label.
> Related document: [asys-spec.md](asys-spec.md)
> Last updated: 2026-05-28

---

## Table of Contents

1. [Conformance Level Definitions](#1-conformance-level-definitions)
2. [Test Environment Requirements](#2-test-environment-requirements)
3. [Frame Parsing Conformance](#3-frame-parsing-conformance)
4. [Byte Order Verification](#4-byte-order-verification)
5. [Security Model Verification](#5-security-model-verification)
6. [Status Word Verification](#6-status-word-verification)
7. [Core ISA Behavior Verification](#7-core-isa-behavior-verification)
8. [Cross-Language Interoperability Verification](#8-cross-language-interoperability-verification)
9. [Standard ISA Behavior Verification](#9-standard-isa-behavior-verification)
10. [End-to-End Integration Tests](#10-end-to-end-integration-tests)
11. [Test Vector Index](#11-test-vector-index)

---

## 1. Conformance Level Definitions

| Level | Requirements | Label |
|-------|-------------|-------|
| **Level 0** | Pass §3 (Frame Parsing) + §4 (Byte Order) + §6 (Status Words) | ASys Compatible |
| **Level 1** | Level 0 + §5 (Security Model) + §7 (Core ISA) | ASys Certified |
| **Level 2** | Level 1 + §8 (Cross-Language Interoperability) | ASys Full Certified |

**Minimum requirement**: Any implementation claiming "ASys protocol support" must reach Level 0. Level 1 is recommended for production deployments.

---

## 2. Test Environment Requirements

**Toolchain:**
- C implementation: gcc 9.0+ or clang 10.0+, `-O2 -pthread`
- Python implementation: Python 3.8+, dependencies `pip install noiseprotocol cryptography`; client key persisted at `~/.asys/id_curve25519`
- Other languages: must provide corresponding big-endian and HMAC-BLAKE2b support

**Reference implementation (baseline):**
- `src/asyd/asyd.c` (v0.3.1) + corresponding handlers; build command in `CLAUDE.md`
- Python client: `examples/client_core_isa.py`
- **Note**: All APDU frames are transmitted within a Noise IK encrypted channel. End-to-end tests (§7, §8) require completing the Noise IK handshake first; unit tests (`test_noise_ik`, `test_whitelist`, `test_apdu_parser`, `test_handlers`) call module interfaces directly without a handshake.

**Running tests:**
```bash
# Run from the tests/conformance/ directory
# Noise IK handshake tests
gcc -O2 -Wall test_noise_ik.c \
    ../../src/asyd/core/monocypher.c \
    ../../src/asyd/core/noise_ik.c \
    -I../../src/asyd/core -o test_noise_ik && ./test_noise_ik

# Agent public key whitelist tests
gcc -O2 -Wall test_whitelist.c \
    ../../src/asyd/core/whitelist.c \
    ../../src/asyd/core/monocypher.c \
    -I../../src/asyd/core -o test_whitelist && ./test_whitelist

# APDU parser tests
gcc -O2 -Wall test_apdu_parser.c \
    ../../src/asyd/core/apdu_parser.c \
    -I../../src/asyd/core -o test_apdu_parser && ./test_apdu_parser

# Core ISA handler tests
gcc -O2 -Wall test_handlers.c \
    ../../src/asyd/core/apdu_parser.c \
    ../../src/asyd/core/dispatcher.c \
    ../../src/asyd/handlers/sys_caps.c \
    ../../src/asyd/handlers/sys_hello.c \
    ../../src/asyd/handlers/sys_status.c \
    ../../src/asyd/handlers/sys_procs.c \
    -I../../src/asyd/core -o test_handlers && ./test_handlers

# Task Handle memory pool tests
gcc -O2 -Wall test_task_pool.c \
    ../../src/asyd/core/task_pool.c \
    -I../../src/asyd/core -o test_task_pool && ./test_task_pool

# PROC_THROTTLE handler tests
gcc -O2 -Wall test_proc_throttle.c \
    ../../src/asyd/core/apdu_parser.c \
    ../../src/asyd/core/dispatcher.c \
    ../../src/asyd/core/task_pool.c \
    ../../src/asyd/handlers/proc_throttle.c \
    -I../../src/asyd/core -o test_proc_throttle && ./test_proc_throttle

# SVC_RESTART + TASK_QUERY handler tests
gcc -O2 -Wall test_svc_restart.c \
    ../../src/asyd/core/apdu_parser.c \
    ../../src/asyd/core/dispatcher.c \
    ../../src/asyd/core/task_pool.c \
    ../../src/asyd/handlers/svc_restart.c \
    ../../src/asyd/handlers/task_query.c \
    -I../../src/asyd/core -ldl -o test_svc_restart && ./test_svc_restart

# Auth Tag verification tests
gcc -O2 -Wall test_auth_verify.c \
    ../../src/asyd/core/crypto_utils.c \
    ../../src/asyd/core/auth_verify.c \
    ../../src/asyd/core/apdu_parser.c \
    ../../src/asyd/core/monocypher.c \
    -I../../src/asyd/core -o test_auth_verify && ./test_auth_verify

# Seq replay detection tests
gcc -O2 -Wall test_seq_replay.c \
    ../../src/asyd/core/crypto_utils.c \
    ../../src/asyd/core/monocypher.c \
    -I../../src/asyd/core -o test_seq_replay && ./test_seq_replay

# Client-Speak-First Magic verification tests (v0.3.1; no asyd required)
gcc -O2 -Wall -pthread test_client_magic.c -o test_client_magic && ./test_client_magic
```

**Verified reference results:**

| Test Suite | Cases | Status |
|-----------|-------|--------|
| `test_noise_ik` | all | ✓ ALL TESTS PASSED |
| `test_whitelist` | 16 | ✓ 16/16 |
| `test_apdu_parser` | 58 | ✓ 58/58 |
| `test_handlers` | 25 | ✓ 25/25 |
| `test_task_pool` | 30 | ✓ 30/30 |
| `test_proc_throttle` | 7 | ✓ 7/7 |
| `test_svc_restart` | 16 | ✓ 16/16 |
| `test_task_query` | 19 | ✓ 19/19 |
| `test_auth_verify` | 19 | ✓ 19/19 |
| `test_seq_replay` | 21 | ✓ 21/21 |
| `test_client_magic` | 5 | ✓ 5/5 (v0.3.1) |
| `client_multi_agent.py` | 19 | ✓ 19/19 (Windows → RHEL E2E) |

---

## 3. Frame Parsing Conformance

### TC-FRAME-001: Minimal Standard Frame Parsing

- **Input**: `00 01 00 00 00 00` (6 bytes; CLA=0x00, INS=0x01, P1=0x00, P2=0x00, Lc=0x00, Le=0x00)
- **Expected**:
  - `cla=0x00`, `ins=0x01`, `p1=0x00`, `p2=0x00`
  - `data_len=0`, `data=NULL`, `auth_tag=NULL`
  - `ext=0`, `sec=0` (PLAIN)
  - `total_size=6`
- **Corresponding test**: `test_apdu_parser.c` TC-1

### TC-FRAME-002: Standard Frame with Data

- **Input**: `00 02 01 02 03 AA BB CC FF` (9 bytes; Lc=3, Data=AA BB CC, Le=FF)
- **Expected**:
  - `data_len=3`, `data[0]=0xAA`, `data[2]=0xCC`
  - `le=0xFF`, `total_size=9`
- **Corresponding test**: `test_apdu_parser.c` TC-2

### TC-FRAME-003: Extended Frame Parsing (CLA.Ext=1)

- **Input**: `02 03 00 00 00 01 00 [256 bytes of data] 00 00`
  - CLA=0x02 (bit1=1, Ext=1), INS=0x03
  - Lc placeholder=0x00, Lc_high=0x01, Lc_low=0x00 (= 256 bytes)
- **Expected**:
  - `ext=1`, `data_len=256`
  - `total_size=7+256+2=265`
- **Corresponding test**: `test_apdu_parser.c` TC-5

### TC-FRAME-004: Invalid Lc Rejected

- **Input**: `00 01 00 00 FF 00` (declares Lc=255 but only 1 actual Data byte)
- **Expected**: `APDU_NEED_MORE` (waiting for more data; no crash, no hang)
- **Corresponding test**: `test_apdu_parser.c` TC-7 (half-packet handling)

### TC-FRAME-005: Extended Lc Placeholder Validation

- **Input**: `02 01 00 00 FF 00 01 AA 00 00` (Ext=1 but Lc placeholder byte=0xFF instead of 0x00)
- **Expected**: `APDU_ERR_EXT_LC`
- **Corresponding test**: `test_apdu_parser.c` TC-11

### TC-FRAME-006: CLA Version Error

- **Input**: `20 01 00 00 00 00` (CLA bit7-5=001; unsupported version)
- **Expected**: `APDU_ERR_VERSION`
- **Corresponding test**: `test_apdu_parser.c` TC-9

### TC-FRAME-007: CLA RFU Bit Rejected

- **Input**: `01 01 00 00 00 00` (CLA bit0=1; RFU bit set)
- **Expected**: `APDU_ERR_RFU`
- **Corresponding test**: `test_apdu_parser.c` TC-10

### TC-FRAME-008: Secure Frame Auth Tag Position

- **Input**: `04 01 00 00 02 DE AD 00 [16-byte Auth Tag]` (CLA Sec=01, Signed)
- **Expected**:
  - `sec=1` (SIGNED)
  - `auth_tag` points to the 16 bytes after Le
  - `auth_tag` is not counted in `data_len`
  - `total_size=5+2+1+16=24`
- **Corresponding test**: `test_apdu_parser.c` TC-3

### TC-FRAME-009: Pipelined Frame Reassembly

- **Input**: two frames written consecutively into the buffer (Frame A + Frame B)
- **Expected**:
  - First `try_parse` returns Frame A
  - After `consume()`, second `try_parse` returns Frame B
  - After `consume()`, `filled=0`
- **Corresponding test**: `test_apdu_parser.c` TC-8

---

## 4. Byte Order Verification

### TC-ENDIAN-001: Multi-Byte Fields Are Big-Endian

All multi-byte fields must be encoded in big-endian; verification method:

```python
# Python verification script
import struct

# Construct SYS_HELLO request
req = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x00])

# Parse SYS_HELLO response (18 bytes)
resp = recv(18)
magic = struct.unpack('>I', resp[0:4])[0]   # big-endian uint32
assert magic == 0x41535953, f"Magic should be 0x41535953, got {magic:#010x}"

ts_ns = struct.unpack('>Q', resp[8:16])[0]  # big-endian uint64
assert ts_ns > 0, "Timestamp should be non-zero"
```

### TC-ENDIAN-002: Cross-Language Consistency

The same APDU frame constructed independently by a C client and a Python client, when sent to `asyd`, must produce completely identical parse results.

**Verification steps:**
1. C client constructs a `SYS_STATUS` request frame; record the raw bytes
2. Python client constructs the same frame; record the raw bytes
3. Both byte sequences must be identical byte-for-byte
4. `asyd`'s responses to both must be completely identical

**Test vector**: see `tests/vectors/endian_sys_hello_req.bin`

---

## 5. Security Model Verification

### TC-SEC-001: Unknown Public Key Rejected (Whitelist Mode)

- **Input**: an agent public key not in `/etc/asyd/authorized_agents` initiates a Noise IK handshake
- **Expected**: returns `0x6982` during the handshake phase; connection immediately terminated; no business logic entered
- **Corresponding test**: `test_whitelist.c` TC-WL-004

### TC-SEC-002: Auth Tag Tampering Detected

- **Input**: flip the first byte of the Auth Tag (`auth_tag[0] ^= 0xFF`)
- **Expected**: decryption/verification fails; returns `NOISE_ERR_AUTH`; no business logic executed
- **Corresponding test**: `test_noise_ik.c` (MAC Tamper Detection)

### TC-SEC-003: Sequence Number Replay Detection

- **Input**: resend a signed frame with sequence number ≤ `Last_Seen_Seq`
- **Expected**: returns 2-byte `0x6985` (Replay Detected)
- **Related specification**: `asys-spec.md` §2.2.4

---

## 5.1 Agent Public Key Whitelist Verification (`test_whitelist.c`)

> Corresponding test file: `tests/conformance/test_whitelist.c`
> Dependencies: `whitelist.c`, `monocypher.c`

### TC-WL-001: Missing File → WL_OK, count=0

- **Input**: `whitelist_load()` target path does not exist
- **Expected**: returns `WL_OK`, `wl.count == 0` (empty whitelist; no crash)

### TC-WL-002: Valid File → Correct Count

- **Input**: file contains 2 valid hex public keys
- **Expected**: returns `WL_OK`, `wl.count == 2`

### TC-WL-003: Known Public Key → WL_OK

- **Input**: `whitelist_check(&wl, KEY_A)`; KEY_A is in the whitelist
- **Expected**: returns `WL_OK`

### TC-WL-004: Unknown Public Key → WL_ERR_DENIED

- **Input**: `whitelist_check(&wl, KEY_C)`; KEY_C is not in the whitelist
- **Expected**: returns `WL_ERR_DENIED` (corresponds to protocol-layer `0x6982`)

### TC-WL-005: Comment Lines and Blank Lines Skipped

- **Input**: file contains `# comment line`, blank lines, and 2 valid public keys
- **Expected**: `wl.count == 2` (only valid entries counted)

### TC-WL-006: Optional Label Parsing

- **Input**: entry format is `<64-char hex>  my-agent-label`
- **Expected**: `wl.entries[0].label == "my-agent-label"`

### TC-WL-007: NULL Arguments → WL_ERR_DENIED, No Crash

- **Input**: `whitelist_check(NULL, KEY_A)` and `whitelist_check(&wl, NULL)`
- **Expected**: both return `WL_ERR_DENIED`; no crash, no segfault

### TC-WL-008: whitelist_wipe() Zeroes All Key Material

- **Input**: 1 public key loaded; call `whitelist_wipe(&wl)`
- **Expected**: `wl.count == 0`; `wl.entries[0].pub` is all zero bytes

---

## 5.2 Auth Tag Verification Tests (`test_auth_verify.c`)

> Corresponding test file: `tests/conformance/test_auth_verify.c`
> Dependencies: `crypto_utils.c`, `auth_verify.c`, `apdu_parser.c`, `monocypher.c`

### TC-AUTH-001: Correct Auth Tag Passes Verification

- **Input**: construct a Signed frame (`CLA=0x04`); compute the correct Auth Tag using a known `recv_key`
- **Expected**: `verify_auth_tag()` returns 1

### TC-AUTH-002: Incorrect Auth Tag Rejected

- **Input**: correct frame, but flip byte 0 of Auth Tag (`auth_tag[0] ^= 0xFF`)
- **Expected**: `verify_auth_tag()` returns 0

### TC-AUTH-003: All-Zero Auth Tag Rejected

- **Input**: Auth Tag is 16 zero bytes (placeholder)
- **Expected**: `verify_auth_tag()` returns 0

### TC-AUTH-004: Plain Frame Skips Verification

- **Input**: `CLA=0x00` (`sec=PLAIN`)
- **Expected**: `asyd.c` does not call `verify_auth_tag()`; proceeds directly to dispatch
- **Verification**: construct a Plain frame; confirm `dispatch()` is called normally

### TC-AUTH-005: HMAC Coverage Integrity

- **Input**: correct frame; modify the INS byte but keep the original Auth Tag
- **Expected**: `verify_auth_tag()` returns 0 (INS is in the Header and is covered by HMAC)

### TC-AUTH-006: HMAC Covers Lc Field

- **Input**: correct frame; modify the Lc byte but keep the original Auth Tag
- **Expected**: `verify_auth_tag()` returns 0 (Lc is in the Header and is covered by HMAC)

### TC-AUTH-007: Zero-Length Payload

- **Input**: `data_len=4` (Seq only; no payload); Auth Tag is correct
- **Expected**: `verify_auth_tag()` returns 1 (empty payload is valid)

### TC-AUTH-008: `crypto_verify16` Constant-Time Comparison

- **Note**: strict timing verification is not possible in unit tests, but use of `crypto_verify16()` rather than `memcmp()` must be confirmed
- **Verification**: code review confirms `memcmp` does not appear in `auth_verify.c`

---

## 5.3 Seq Replay Detection Tests (`test_seq_replay.c`)

> Corresponding test file: `tests/conformance/test_seq_replay.c`
> Dependencies: `crypto_utils.c`, `monocypher.c`

### TC-SEQ-001: First Signed Instruction Passes

- **Precondition**: `last_seen_seq = 0`
- **Input**: Seq = 1
- **Expected**: `1 > 0`; passes; `last_seen_seq` updated to 1

### TC-SEQ-002: Seq=0 Rejected (Sentinel Value)

- **Precondition**: `last_seen_seq = 0`
- **Input**: Seq = 0
- **Expected**: `0 <= 0`; returns 2-byte `0x6985` (Replay Detected)

### TC-SEQ-003: Normal Increment Passes

- **Precondition**: `last_seen_seq = 100`
- **Input**: Seq = 101
- **Expected**: passes; `last_seen_seq` updated to 101

### TC-SEQ-004: Replay Detection — Equal to Last_Seen_Seq

- **Precondition**: `last_seen_seq = 100`
- **Input**: Seq = 100
- **Expected**: `100 <= 100`; returns 2-byte `0x6985` (Replay Detected)

### TC-SEQ-005: Replay Detection — Less Than Last_Seen_Seq

- **Precondition**: `last_seen_seq = 100`
- **Input**: Seq = 50
- **Expected**: `50 <= 100`; returns 2-byte `0x6985` (Replay Detected)

### TC-SEQ-006: New Connection Resets last_seen_seq

- **Input**: new session (`last_seen_seq` initialized to 0); send Seq=1
- **Expected**: `check_and_advance` returns 1; `last_seen_seq` updated to 1

### TC-SEQ-007: Sequential Increments Pass; Embedded Replay Rejected

- **Operations**: Seq 1→2→3 all pass; then Seq=2 (replay) is rejected; Seq=4 continues to pass
- **Expected**: `last_seen_seq = 4`; Seq=2 returns 0

### TC-SEQ-008: Seq=0 Always Rejected

- **Input A**: new session (`last_seen_seq = 0`); send Seq=0
- **Expected**: `check_and_advance` returns 0; `last_seen_seq` remains 0
- **Input B**: after normal progression (`last_seen_seq = 5`); send Seq=0
- **Expected**: returns 0; `last_seen_seq` remains 5

---

## 5.4 Client-Speak-First Magic Verification (`test_client_magic.c`)

> Corresponding test file: `tests/conformance/test_client_magic.c`
> Dependencies: none (POSIX sockets only); uses `socketpair(2)` to simulate TCP connection within the process; no asyd required
> Introduced: v0.3.1

**Background**: From v0.3.1 onward, `asyd` switches to Client-Speak-First connection mode. After the TCP handshake completes, `asyd` no longer sends any data proactively but instead waits for the agent to send a 4-byte Magic (`0x41535953`, ASCII "ASYS") first; the timeout is hardcoded at 1 second. A mismatched or timed-out Magic causes a silent disconnect with no response sent to the client.

### TC-MAG-001: Valid Magic Passes Verification

- **Precondition**: socketpair established; server calls `wait_for_client_magic(fd)`
- **Input**: client sends `0x41535953` (big-endian, 4 bytes)
- **Expected**: function returns 0 (accepted)

### TC-MAG-002: Invalid Magic Rejected

- **Precondition**: socketpair established; server calls `wait_for_client_magic(fd)`
- **Input**: client sends `0xDEADBEEF` (any non-ASYS value)
- **Expected**: function returns -1 (rejected); server sends no response

### TC-MAG-003: Timeout Rejected (~1 second)

- **Precondition**: socketpair established; server calls `wait_for_client_magic(fd)`
- **Input**: client sends no data
- **Expected**: function returns -1; actual wait time ≥ 900ms and < 3000ms

---

## 6. Status Word Verification

### TC-SW-001: Nonexistent Instruction Returns `0x6A81`

- **Input**: an INS code not registered in the Capability Map (e.g., `0xEE`)
- **Expected**: returns `0x6A81`; response is exactly 2 bytes; no system information leaked
- **Corresponding test**: `test_handlers.c` TC-1

### TC-SW-002: Unimplemented Core Slot Returns `0x6A81`

- **Input**: `INS=0x04` (within Core ISA encoding space but not registered in the Capability Map)
- **Expected**: returns `0x6A81` (not in bitmap; physically nonexistent)
- **Corresponding test**: `test_handlers.c` TC-2

### TC-SW-003: Platform Not Supported Returns `0x6D00`

- **Scenario**: the platform lacks the atomic primitives required to execute the instruction
- **Expected**: returns `0x6D00`; fuzzy simulation is strictly prohibited
- **Related specification**: `asys-spec.md` §1.2 platform neutrality principle

### TC-SW-004: Status Word Position Verification

For each Core ISA instruction, verify that the SW bytes are the last 2 bytes of the response:

| Instruction | Response Length | SW Position |
|-------------|----------------|-------------|
| `SYS_CAPS (0x00)` | 36 bytes | `resp[34-35]` |
| `SYS_HELLO (0x01)` | 18 bytes | `resp[16-17]` |
| `SYS_STATUS (0x02)` | 23 bytes | `resp[21-22]` |
| `SYS_PROCS (0x03)` | 44 bytes | `resp[42-43]` |

---

## 7. Core ISA Behavior Verification

### TC-CORE-001: SYS_CAPS Response Format

- **Response length**: 36 bytes
- **Field validation**:

| Byte | Field | Validation Condition |
|------|-------|---------------------|
| `0-3` | Core Bitmap | `(value & 0xF) == 0xF` (bits 0-3 must all be 1, corresponding to the 4 implemented instructions) |
| `4-7` | Ext Bitmap | `0x00000005` (bits 0, 2 = `PROC_THROTTLE(0x20)`, `SVC_RESTART(0x22)` implemented in Ext ISA) |
| `8-9` | Protocol Version | `== 0x0100` (v1.0) |
| `10-13` | Kernel Hash | non-zero |
| `14-15` | CPU Count | `> 0` |
| `16-17` | Arch Code | one of the known architecture codes (`0x0001`=x86_64, `0x0002`=aarch64, `0xFFFF`=unknown) |
| `18-21` | Total RAM MB | `> 0` |
| `26-29` | Root Size MB | `> 0` |
| `32` | RPI Type | `0x01` (NATIVE_KERNEL) or `0x02` (USER_SIMULATED) |
| `33` | Reserved | `== 0x00` |
| `34-35` | SW | `== 0x9000` |

- **Corresponding tests**: `test_handlers.c` TC-3 through TC-12

### TC-CORE-002: SYS_HELLO Response Format

- **Response length**: 18 bytes
- **Field validation**:

| Byte | Field | Validation Condition |
|------|-------|---------------------|
| `0-3` | Magic | `== 0x41535953` (ASCII: "ASYS") |
| `4-7` | Node_UID | any value (non-zero preferred) |
| `8-15` | Server_Timestamp | `> 0` (nanosecond Unix epoch) |
| `16-17` | SW | `== 0x9000` |

- **Corresponding tests**: `test_handlers.c` TC-13 through TC-16

### TC-CORE-003: SYS_STATUS Response Format

- **Response length**: 23 bytes
- **Field validation**:

| Byte | Field | Validation Condition |
|------|-------|---------------------|
| `0` | Load 1min × 10 | `0-255` (load average × 10; max ~25.5) |
| `1` | Load 5min × 10 | `0-255` |
| `2` | CPU % | `0-100` |
| `3-6` | Mem Available MB | `> 0` |
| `7` | Root Disk % | `0-100` |
| `8-11` | IO Wait ms | `>= 0` |
| `12-13` | Inbound Mbps | `>= 0` |
| `14-15` | Outbound Mbps | `>= 0` |
| `16` | RPI | `0x00-0x64` or `0xFF` (NOT_SUPPORTED) |
| `17-20` | Reserve | `== 0x00000000` |
| `21-22` | SW | `== 0x9000` |

- **Cache behavior verification**: two consecutive calls; the second RTT must be < 200ms (cache hit)
- **Corresponding tests**: `test_handlers.c` TC-17 through TC-20

### TC-CORE-004: SYS_PROCS Response Format

- **Response length**: 44 bytes
- **Field validation**:

| Byte | Field | Validation Condition |
|------|-------|---------------------|
| `0-1` | Total_Procs | `> 0` (system has at least one process) |
| `2-41` | Top 5 Slots | see slot validation below |
| `42-43` | SW | `== 0x9000` |

**Individual slot validation (8 bytes)**:

| Slot Offset | Field | Validation Condition |
|------------|-------|---------------------|
| `0-3` | PID | `> 0` for non-empty slots; `== 0x00000000` for empty slots |
| `4-5` | CPU Usage × 100 | `0-65535` |
| `6` | MEM Usage % | `0-100` |
| `7` | Status Flag | `0x00-0x07` (3 valid bits) |

- **Empty slot padding verification**: when fewer than 5 processes exist, empty slots must have PID `0x00000000` and the entire slot must be all zeros
- **Corresponding tests**: `test_handlers.c` TC-21 through TC-25

---

## 8. Cross-Language Interoperability Verification

### TC-INTEROP-001: C ↔ Python Frame Construction Consistency

**Verification steps:**
1. Python client constructs a `SYS_STATUS` request frame (`00 02 00 00 00 00`)
2. Record the raw bytes sent
3. Compare with the same frame constructed by the C client; verify byte-for-byte
4. Both must be completely identical

**Expected byte sequence**: `00 02 00 00 00 00`

### TC-INTEROP-002: Response Parsing Consistency

**Verification steps:**
1. `asyd` returns a `SYS_STATUS` response
2. C client parses each field value
3. Python client parses the same response byte sequence
4. Both parse results (field values) must be completely identical

---

## 9. Standard ISA Behavior Verification

> Corresponding test files: `tests/conformance/test_task_pool.c`, `test_proc_throttle.c`, `test_svc_restart.c`, `test_task_query.c`

### 9.1 Task Handle Memory Pool (`test_task_pool.c`)

#### TC-POOL-001: Basic alloc / free Cycle

- **Operation**: `task_pool_alloc(session=1, svc="nginx", pid=100)`
- **Expected**: returns non-zero handle; upper 16 bits == 1 (session_id); lower 16 bits non-zero
- **Follow-up**: `task_pool_free(handle)` → `task_pool_find_handle(handle, 1)` returns NULL

#### TC-POOL-002: Handle Ownership Isolation

- **Operation**: `task_pool_alloc(session=1, ...)` obtains handle
- **Expected**: `task_pool_find_handle(handle, session=2)` returns NULL
- **Verification**: cross-session queries leak no task information

#### TC-POOL-003: Idempotent Lookup

- **Operation**: `task_pool_alloc(session=1, svc="nginx", pid=100)` obtains handle_A
- **Follow-up**: `task_pool_find_pending(session=1, svc="nginx")`
- **Expected**: returns handle_A (same session + same service name returns existing Pending handle)

#### TC-POOL-004: Different Service Name Does Not Trigger Idempotency

- **Operation**: `task_pool_alloc(session=1, svc="nginx", ...)` obtains handle_A
- **Follow-up**: `task_pool_find_pending(session=1, svc="redis")`
- **Expected**: returns 0 (different service name; no reuse)

#### TC-POOL-005: Different Session Does Not Trigger Idempotency

- **Operation**: `task_pool_alloc(session=1, svc="nginx", ...)` obtains handle_A
- **Follow-up**: `task_pool_find_pending(session=2, svc="nginx")`
- **Expected**: returns 0 (different session; no reuse)

#### TC-POOL-006: alloc Returns 0 When Pool Is Full

- **Operation**: call `task_pool_alloc` 64 consecutive times to fill all slots
- **Expected**: the 65th call returns 0
- **Verification**: `task_pool_available()` returns 0 when full; returns 1 when a slot is free

#### TC-POOL-007: `update_by_pid` Updates Status

- **Operation**: after alloc, call `task_pool_update_by_pid(pid=100, TASK_SUCCESS)`
- **Expected**: `task_pool_find_handle(handle, session)` has `status == TASK_SUCCESS`

#### TC-POOL-008: `update_by_pid` Ignores Nonexistent pid

- **Operation**: `task_pool_update_by_pid(pid=99999, TASK_SUCCESS)` (pid does not exist)
- **Expected**: no crash, no side effects; pool state unchanged

#### TC-POOL-009: Timeout Sweep

- **Operation**: alloc a slot; manually set `created_at` to `time(NULL) - 31`; call `task_pool_sweep_timeouts()`
- **Expected**: the slot's `status == TASK_TIMEOUT`

#### TC-POOL-010: `release_session` Cleanup

- **Operation**: alloc 3 slots with session=1, 1 slot with session=2; call `task_pool_release_session(1)`
- **Expected**: the 3 session=1 slots all become TASK_EMPTY; the session=2 slot is unaffected

#### TC-POOL-011: Fields Zeroed After free

- **Operation**: alloc → `task_pool_free(handle)`
- **Expected**: the slot has `handle_id==0`, `child_pid==0`, `svc_name[0]=='\0'`, `status==TASK_EMPTY`

---

### 9.2 PROC_THROTTLE (`test_proc_throttle.c`)

#### TC-PROC-001: CLA.Sec Validation

- **Input**: `CLA=0x00` (Plain, not Signed), `INS=0x20`, `P1=0x00`, `Lc=0x08`, Data=[Seq(4B)][PID(4B)]
- **Expected**: returns `0x6982` (Access Denied)

#### TC-PROC-002: Lc Length Validation

- **Input**: `CLA=0x04`, `INS=0x20`, `Lc=0x04` (fewer than 8 bytes)
- **Expected**: returns `0x6700` (Wrong Length)

#### TC-PROC-003: Invalid P1 Value Rejected

- **Input**: `CLA=0x04`, `P1=0x02` (not 0x00 or 0x01)
- **Expected**: returns `0x6A80` (Wrong Data)

#### TC-PROC-004: PID=0 Rejected

- **Input**: valid request; PID field in Data is `0x00000000`
- **Expected**: returns `0x6A80` (Wrong Data)

#### TC-PROC-005: Valid STOP Request

- **Input**: `CLA=0x04`, `P1=0x00` (STOP), PID is the process's own PID (`getpid()`)
- **Expected**: returns `0x9000`
- **Note**: must send CONT immediately after the test to resume, or use a child process for testing

#### TC-PROC-006: Valid CONT Request

- **Input**: `CLA=0x04`, `P1=0x01` (CONT), PID of an already-suspended process
- **Expected**: returns `0x9000`

#### TC-PROC-007: Target Process Does Not Exist

- **Input**: PID = `0xFFFFFFFF` (nonexistent process)
- **Expected**: returns `0x6A80` (Wrong Data, corresponding to ESRCH)

---

### 9.3 SVC_RESTART (`test_svc_restart.c`)

> **Note**: `handler_svc_restart` performs a real `fork/exec`; unit tests require mocking or running in an isolated environment. The test file should provide a `fork_mock` stub function, replacing the real `fork` via a compile-time macro.

#### TC-SVC-001: CLA.Sec Validation

- **Input**: `CLA=0x00` (Plain)
- **Expected**: returns `0x6982`

#### TC-SVC-002: Minimum Lc Length Validation

- **Input**: `CLA=0x04`, `Lc=0x04` (only Seq 4B; no service name bytes; data_len < MIN_DATA_LEN=5)
- **Expected**: returns `0x6700` (length check triggers before data validation)

#### TC-SVC-003: Invalid Character Rejected (Minimum Valid Length)

- **Input**: `Lc=0x05` (data_len=5, name_len=1); service name is `"A"` (uppercase; invalid character)
- **Expected**: returns `0x6A80` (length is valid; data validation fails)
- **Note**: distinguished from TC-SVC-002 — here Lc satisfies the minimum length; the error comes from character set validation, not length check

#### TC-SVC-004: Invalid Character Rejected

- **Input**: SvcName = `"Nginx"` (contains uppercase)
- **Expected**: returns `0x6A80`

#### TC-SVC-005: Invalid Character Rejected (Path Separator)

- **Input**: SvcName = `"../etc/passwd"`
- **Expected**: returns `0x6A80`

#### TC-SVC-006: `.service` Suffix Rejected

- **Input**: SvcName = `"nginx.service"`
- **Expected**: returns `0x6A80` (rejected directly at the protocol layer; `asyd` appends `.service` internally; clients must not add it in advance)
- **Note**: `svc_name_valid()` explicitly checks for a `.service` suffix after character set validation and rejects it, preventing `nginx.service.service`

#### TC-SVC-007: Service Name Maximum Length Boundary

- **Input**: SvcName exactly 64 bytes (valid characters)
- **Expected**: returns `0x9000` (valid handle)

#### TC-SVC-008: Service Name Too Long Rejected

- **Input**: SvcName 65 bytes
- **Expected**: returns `0x6A80`

#### TC-SVC-009: Idempotency — Returns Existing Handle

- **Precondition**: session=1; svc="nginx" already has Pending handle_A
- **Input**: send `SVC_RESTART("nginx")` again with session=1
- **Expected**: returns handle_A; no new handle created; no new process forked

#### TC-SVC-010: Does Not Fork When Pool Is Full

- **Precondition**: `task_pool_available()` returns 0 (pool is full)
- **Input**: valid `SVC_RESTART("nginx")`
- **Expected**: returns `0x6400` (Blocked); no child process created

#### TC-SVC-011: Returned Handle Upper 16 Bits Equal session_id

- **Input**: valid `SVC_RESTART("nginx")`; session_id = 1
- **Expected**: 6-byte response; `Task_Handle[31:16] == 1`; `SW=0x9000`
- **Verification purpose**: confirms Handle format complies with spec §1.4.2 (Session_ID embedded in upper 16 bits; used by TASK_QUERY for cross-session isolation checks)

#### TC-SVC-012: `fork()` Returns ENOMEM

- **Precondition**: define a `fork()` override symbol inside the test_svc_restart binary, controlled by the `g_mock_fork_enomem` flag; call the real fork via `dlsym(RTLD_NEXT, "fork")`; compile with `-ldl`
- **Input**: valid `SVC_RESTART("nginx")`; mock fork activated (`errno=ENOMEM`, returns -1)
- **Expected**: returns `0x6F01` (System Emergency: ENOMEM); **does not hang; does not return `0x6F00`**
- **Verification purpose**: confirms `handler_svc_restart` explicitly distinguishes `ENOMEM` from other fork failure reasons and returns the precise subcode

---

### 9.4 TASK_QUERY (`test_task_query.c`)

#### TC-QUERY-001: Lc Length Validation

- **Input**: `Lc=0x02` (fewer than 4 bytes)
- **Expected**: returns `0x6700`

#### TC-QUERY-002: Handle Not Found

- **Input**: `handle=0x00001234` (nonexistent handle)
- **Expected**: `Status=0xFF`, `SW=0x9000`

#### TC-QUERY-003: Cross-Session Query Rejected

- **Precondition**: session=1 has allocated handle_A
- **Input**: session=2 queries handle_A
- **Expected**: `Status=0xFF` (no task information leaked)

#### TC-QUERY-004: Pending State Query

- **Precondition**: a Pending-state handle exists in the task pool
- **Expected**: `Status=0x00`, `SW=0x9000`; handle **is not released**

#### TC-QUERY-005: Success State Query and Release

- **Precondition**: manually set task pool slot status to TASK_SUCCESS
- **Expected**: `Status=0x01`, `SW=0x9000`; handle **is released** (subsequent query returns 0xFF)

#### TC-QUERY-006: Failed State Query and Release

- **Precondition**: manually set task pool slot status to TASK_FAILED
- **Expected**: `Status=0x02`, `SW=0x9000`; handle **is released**

#### TC-QUERY-007: Timeout State Query and Release

- **Precondition**: manually set task pool slot status to TASK_TIMEOUT
- **Expected**: `Status=0x03`, `SW=0x9000`; handle **is released**

#### TC-QUERY-008: Sweep Triggers Timeout

- **Precondition**: a Pending slot exists; `created_at = time(NULL) - 31`
- **Operation**: call `handler_task_query` (which internally calls `sweep_timeouts`)
- **Expected**: `Status=0x03` (Timeout); handle released

#### TC-QUERY-009: Cancelled State Query

- **Precondition**: manually set task pool slot status to `TASK_CANCELLED`
- **Expected**: `Status=0x04`, `SW=0x9000`
- **Verification purpose**: confirms `to_wire()` correctly maps TASK_CANCELLED → 0x04 (reserved for TASK_CANCEL 0x12 instruction)

#### TC-QUERY-010: Lc > 4 Silently Accepted

- **Input**: `data_len=5` (handle 4 bytes + 1 redundant byte); handle unknown
- **Expected**: handler reads only `data[0..3]`; returns `Status=0xFF`, `SW=0x9000` (not rejected)
- **Verification purpose**: confirms upper bound is lenient (`data_len < 4` errors; `> 4` silently ignores redundant bytes), aligned with spec

#### TC-QUERY-011: Terminal Handle Reclaimed After TTL Expires

- **Precondition**: manually set a slot status to `TASK_SUCCESS`; `created_at = time(NULL) - 31` (TTL exceeded)
- **Operation**: call `handler_task_query` (which internally calls `sweep_timeouts`)
- **Expected**: `Status=0xFF` (Not Found) — terminal handles beyond TTL are also reclaimed; results are not preserved
- **Verification purpose**: confirms TTL reclamation covers all states (including terminal), preventing terminal slots from permanently occupying the static pool when the agent disconnects

#### TC-QUERY-012: Terminal Handle Immediately Invalidated After Session Disconnect

- **Precondition**: session=1 has a `TASK_SUCCESS` slot
- **Operation**: call `task_pool_release_session(1)`
- **Expected**: slot becomes `TASK_EMPTY`; querying with the original handle returns `Status=0xFF`
- **Verification purpose**: confirms that on session disconnect, **all states** (including terminal) are immediately zeroed, not just Pending states

---

## 10. End-to-End Integration Tests

> Corresponding test script: `tests/interop/test_e2e.py` (to be implemented)
> Prerequisites: `asyd` is running; Python client is registered; target service exists

### TC-E2E-001: SVC_RESTART Normal Path

1. Send `SVC_RESTART("nginx")` (Signed, CLA=0x04)
2. Verify response: Task_Handle(4B) + SW=0x9000
3. Poll `TASK_QUERY(handle)` until Status != Pending (max 30 seconds)
4. Verify Status == 0x01 (Success)
5. Verify nginx actually restarted: `systemctl status nginx` shows updated ActiveEnterTimestamp

### TC-E2E-002: TASK_QUERY Idempotent Polling

1. Send `SVC_RESTART("nginx")` to obtain handle
2. Send `TASK_QUERY(handle)` 10 consecutive times before the task completes
3. Verify all responses have SW=0x9000; handle is not released while Pending
4. After completion, query again: Status=Success; handle released

### TC-E2E-003: SVC_RESTART Idempotency

1. Send `SVC_RESTART("nginx")` to obtain handle_A
2. Immediately send `SVC_RESTART("nginx")` again
3. Verify the second response's handle == handle_A (same handle)
4. Verify nginx was restarted only once (confirmed via journal log)

### TC-E2E-004: Nonexistent Service Name

1. Send `SVC_RESTART("nonexistent-service-xyz")`
2. Receive handle, SW=0x9000 (queued successfully)
3. Poll TASK_QUERY; verify final Status=0x02 (Failed)

### TC-E2E-005: Handle Invalidated After Session Disconnect

1. Send `SVC_RESTART("nginx")` to obtain handle
2. Immediately disconnect the TCP connection
3. Reconnect; query `TASK_QUERY` with the old handle
4. Verify Status=0xFF (Not Found)

### TC-E2E-006: PROC_THROTTLE End-to-End (OODA Loop)

1. Start a CPU stress process (`stress-ng --cpu 1` or a simple busy loop script)
2. Obtain its PID via `SYS_PROCS`
3. Send `PROC_THROTTLE(pid, P1=0x00)` STOP
4. Verify `SYS_STATUS` CPU utilization decreases
5. Send `PROC_THROTTLE(pid, P1=0x01)` CONT
6. Verify CPU utilization recovers
7. All SW=0x9000 throughout

---

## 10.1 Agent Simulator Scenario Verification

> Corresponding test script: `examples/client_multi_agent.py`
> Run with: `python3 client_multi_agent.py <host> [port]`
> Verification target: per-session lock correctness, cross-session isolation, disconnect recovery

### TC-SIM-001: Concurrent Core ISA

- **Scenario**: 4 agents concurrently each send 5 `SYS_STATUS` requests
- **Expected**: all SW=0x9000; first round each triggers a cold sample (~50ms); subsequent calls are cache hits (< 1ms); no serial blocking
- **Verification point**: `s_cache_lock` correctly protects the cache; multi-threaded concurrent read/write produces no race conditions

### TC-SIM-002: Cross-Session TASK_QUERY Isolation

- **Scenario**: Agent-B1 sends `SVC_RESTART` and obtains a handle; Agent-B2 queries that handle
- **Expected**: Agent-B2's query returns `Status=0xFF` (no info leak); Agent-B1's query of its own handle returns non-0xFF
- **Verification point**: handle upper-16-bit Session_ID check is correct; different sessions cannot query each other

### TC-SIM-003: Concurrent SVC_RESTART + TASK_QUERY Polling

- **Scenario**: 3 agents simultaneously restart 3 different services (crond / rsyslog / sshd); each polls to terminal state
- **Expected**: 3 Task_Handles are all distinct; all eventually reach Status=Success; no handle cross-contamination
- **Verification point**: `task_pool` concurrent alloc is correct; session isolation is correct

### TC-SIM-004: Disconnect Recovery

- **Scenario**: Agent-D-bad abruptly disconnects (no handshake); Agent-D-stable operates normally simultaneously
- **Expected**: Agent-D-stable has SW=0x9000 both before and after the disruption; new connections can handshake normally
- **Verification point**: `task_pool_release_session` does not affect other sessions; `g_cslots` slot is correctly released

---

## 11. Test Vector Index

Test vectors are stored in `tests/vectors/`; each file corresponds to one expected parse result.

| File | Description | Expected Result |
|------|-------------|----------------|
| `vector_sys_hello_req.bin` | `SYS_HELLO` request frame (6 bytes) | `00 01 00 00 00 00` |
| `vector_sys_hello_resp.bin` | `SYS_HELLO` response frame (18 bytes) | Magic=`41535953`, SW=`9000` |
| `vector_sys_status_req.bin` | `SYS_STATUS` request frame (6 bytes) | `00 02 00 00 00 00` |
| `vector_sys_status_resp.bin` | `SYS_STATUS` response frame (23 bytes) | fields per TC-CORE-003 |
| `vector_sys_caps_req.bin` | `SYS_CAPS` request frame (6 bytes) | `00 00 00 00 00 00` |
| `vector_sys_caps_resp.bin` | `SYS_CAPS` response frame (36 bytes) | fields per TC-CORE-001 |
| `vector_sys_procs_req.bin` | `SYS_PROCS` request frame (6 bytes) | `00 03 00 00 00 00` |
| `vector_invalid_lc.bin` | Invalid Lc length frame | `APDU_ERR_LENGTH` or `APDU_NEED_MORE` |
| `vector_ext_frame_256.bin` | Extended frame (Lc=256) | `ext=1`, `data_len=256`, `total=265` |
| `vector_bad_version.bin` | CLA version error frame | `APDU_ERR_VERSION` |
| `vector_auth_tag_tampered.bin` | Secure frame with tampered Auth Tag | `NOISE_ERR_AUTH` |
| `vector_unknown_ins.bin` | Unknown instruction code frame | SW=`0x6A81` |

> **Note**: Test vector files are being populated incrementally. The test cases currently in `tests/conformance/` (`test_apdu_parser.c`, `test_whitelist.c`, `test_handlers.c`) already cover most of the above scenarios; the vector files are the binary-fixed form of these tests, used for cross-language interoperability verification.

---

*This document is continuously updated as the protocol implementation evolves. Test cases must be updated in sync when new instructions or security mechanisms are added.*
