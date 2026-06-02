# ASys — Agentic System Interface

> The binary system interface protocol for AI Agents —
> port 7816, zero shell parsing, deterministic semantics.

English | [中文](README.zh.md) 

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/vincentping/asys)](https://github.com/vincentping/asys/releases/latest)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://github.com/vincentping/asys)

---

## Table of Contents

- [Why ASys](#why-asys)
- [Architecture](#architecture)
- [Instruction Set](#instruction-set)
- [Quick Start](#quick-start)
- [Security](#security)
- [Documentation](#documentation)
- [Changelog](#changelog)

---

## Why ASys

SSH was designed for humans. Agents don't need a terminal.

When an AI agent runs `ps aux | grep nginx` over SSH, it parses free-form text that varies by OS, locale, and tool version. But when agents call ASys's `SYS_PROCS` instruction, they receive a fixed 44-byte binary frame: total process count, top-5 PIDs, CPU%, memory%, status flags — typed, unambiguous, the same on every node.

ASys is an experiment: what if you designed a system interface specifically for AI agents, from first principles? Binary frames instead of text. A long-lived encrypted connection instead of per-command sessions. Instruction-level capability grants instead of broad SSH access. Built-in audit trail instead of shell history.

It's not a replacement for SSH, Ansible, or Kubernetes operators — those tools are well-suited for their intended users (humans and orchestration pipelines). ASys is an additional option for the case where the operator is an AI agent and you want an interface designed for that from the ground up.

To understand the full design rationale and where ASys fits in the agent infrastructure landscape, start with the [**whitepaper**](docs/en/asys-whitepaper.md).

---

## Architecture

```
  AI Agent (LLM)
       │
       │  Tool calls
       ▼
  Python SDK  (~/.asys/id_curve25519)
       │
       │  Noise_IK_25519_ChaChaPoly_BLAKE2b
       │  TCP port 7816
       ▼
  asyd  (C daemon, zero dependencies)
       │
       │  POSIX syscalls
       ▼
  Linux
```

---

## Instruction Set

### Core ISA (0x00–0x0F) — read-only, zero side effects

| INS  | Name       | Response | Description                                       |
|------|------------|----------|---------------------------------------------------|
| 0x00 | SYS_CAPS   | 36B      | Static capabilities: CPU, RAM, disk, ISA bitmap   |
| 0x01 | SYS_HELLO  | 18B      | Node UID + nanosecond timestamp                   |
| 0x02 | SYS_STATUS | 23B      | Load avg, CPU%, available RAM, disk, network, RPI |
| 0x03 | SYS_PROCS  | 44B      | Total procs + top-5 by CPU (PID, CPU%, MEM%)      |

### Protocol Control (0x10–0x1F)

| INS  | Name       | Response | Description                           |
|------|------------|----------|---------------------------------------|
| 0x11 | TASK_QUERY | 3B       | Poll async task status by Task_Handle |

### Standard ISA — Process Control (0x20–0x2F) — signed, require elevated capabilities

| INS  | Name          | Response | Description                                 |
|------|---------------|----------|---------------------------------------------|
| 0x20 | PROC_THROTTLE | SW only  | SIGSTOP / SIGCONT a process by PID          |
| 0x21 | NET_ISOLATE   | —        | Isolate process network access *(planned)*  |
| 0x22 | SVC_RESTART   | 6B       | Restart a named systemd service (async)     |

**Measured RTT** (Noise IK encrypted, RHEL on VirtualBox, Windows Python client):

| Instruction   | RTT             | Notes                                          |
|---------------|-----------------|------------------------------------------------|
| SYS_HELLO     | < 1ms           |                                                |
| SYS_CAPS      | < 1ms           | No cache; static data read once at startup     |
| SYS_STATUS    | < 1ms / ~51ms   | Cache hit / cold sample (50ms CPU dual-sample) |
| SYS_PROCS     | ~6ms / ~200ms   | Warm calls; first call blocks 200ms cold sample |
| PROC_THROTTLE | ~200µs dispatch |                                                |
| SVC_RESTART   | ~200µs dispatch | Async; poll result with TASK_QUERY             |

---

## Quick Start

### Prerequisites

- Linux (RHEL/Fedora/Ubuntu/Debian), x86_64
- `gcc`, `make`
- Python 3.8+ with `pip install noiseprotocol cryptography` (client only)

### Build and run

```bash
git clone https://github.com/vincentping/asys
cd asys
make
sudo bin/asyd
```

`asyd` listens on TCP 7816. On first start it generates a key pair at
`/etc/asyd/id_curve25519`.

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--port <n>` | 7816 | TCP listen port |
| `--listen <addr>` | 0.0.0.0 | Bind address |
| `--debug` | off | Run in foreground with verbose logging to stderr |
| `--version` | — | Print version and exit |
| `--help` | — | Print usage and exit |

```bash
# Example: custom port, local-only
sudo bin/asyd --port 8816 --listen 127.0.0.1

# Example: debug mode (foreground, verbose)
sudo bin/asyd --debug
```

### Register an agent

```bash
# On the client machine — generate agent identity
python3 tools/client/asys_keygen.py

# On the server — add the agent's public key to the whitelist
echo "<pubkey_hex>" | sudo tee -a /etc/asyd/authorized_agents
```

The agent public key is printed by `asys_keygen.py`. It also generates the client key pair at
`~/.asys/id_curve25519` used during the Noise IK handshake.
Connections from agents not in `/etc/asyd/authorized_agents` are rejected with SW=0x6982.

On first connection, the client will prompt you to confirm the server's public key fingerprint
and save it to `~/.asys/known_hosts` — see [First connection](#first-connection) below.

Reload the whitelist without restarting (existing connections are not affected):

```bash
sudo kill -HUP $(pidof asyd)
```

### First connection

On first connect, the client displays the server's public key fingerprint:

```
ASys server fingerprint (SHA256): a3:f1:2c:...
Connect to localhost:7816? [yes/no]: yes
Fingerprint saved to ~/.asys/known_hosts
```

Subsequent connections verify the fingerprint automatically. A mismatch aborts
the connection — same model as SSH `known_hosts`.

### Run the demos

All client scripts run on any machine (including Windows) and connect to a remote
`asyd` over the network. No SSH. No shell. Signed binary instructions over an
encrypted channel.

#### 1. Core ISA — verify the full connection stack

Connects to `asyd`, completes the Noise IK handshake, then exercises all four
Core ISA instructions (SYS_CAPS, SYS_HELLO, SYS_STATUS, SYS_PROCS) and runs
a cache timing test.

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

#### 2. SVC_RESTART — async instruction pattern

Sends a `SVC_RESTART` instruction, receives a `Task_Handle`, then polls
`TASK_QUERY` until the service restart completes.

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

#### 3. Multi-agent — concurrent session isolation

Spawns four independent agents concurrently to validate per-session locking:
concurrent reads don't interleave, cross-session `TASK_QUERY` leaks no handle
information, and an abrupt disconnect does not affect other sessions.

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

> **Note on Scenario 3 failures:** `Status=Failed` for `crond`/`rsyslog` means
> `systemctl restart` returned non-zero — those services are not installed or not
> running on the test node. The ASys protocol path (dispatch → fork → SIGCHLD →
> handle update) is exercised correctly regardless; `Status=Failed` is the expected
> response when the underlying system operation fails.

#### 4. PROC\_THROTTLE — observe and control a live process

The demo uses two machines to show what ASys is actually for: a remote operator
observing and controlling a Linux node over the network.

**On the server (RHEL/Linux) — start a CPU hog:**

```bash
python3 examples/server_cpu_hog.py
```

```
CPU hog started  PID=2644
Press Ctrl+C to stop.
```

**On the client (any machine, e.g. Windows) — connect and throttle:**

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

The client runs on Windows. The process being throttled is on RHEL.
No SSH. No shell. One signed binary instruction over an encrypted channel.

---

## Security

**Transport:** Noise IK (Curve25519 + ChaCha20-Poly1305 + BLAKE2b) — 1-RTT mutual
authentication. No passwords. No certificates. No CA. Session content has forward
secrecy (session keys are derived from per-handshake ephemeral keys; compromising
the static private key does not expose past session content). Known boundary: the
agent's static public key is encrypted under the server's static public key during
the handshake — a static private key compromise would theoretically allow recovery
of agent identities from recorded handshake traffic.

**Server identity:** on every new connection, `asyd` sends a 38-byte
Pre-Handshake Frame (`[Magic][Version][ServerPubKey]`) before the Noise handshake.
The client verifies the server's public key fingerprint against `~/.asys/known_hosts`
(SSH-style: confirm on first connect, reject on mismatch thereafter). The public key
is public by definition; security relies on fingerprint confirmation, not secrecy.

**Replay protection:** signed instructions carry an **Epoch_ID**
(`HMAC-BLAKE2b(recv_key, "asys-epoch-v1")[:4]`), derived post-handshake and never
transmitted. Each session produces a unique Epoch_ID; cross-session replay is
cryptographically impossible without breaking the session key. Within a session,
a monotonic sequence number (`Seq`) prevents replay with `0x6985`.

**Privilege containment:** `asyd` runs as **Caged Root** under systemd:
`CapabilityBoundingSet` limits privileges to exactly what each instruction needs
(`CAP_KILL`, `CAP_SYS_RESOURCE`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH`). `NoNewPrivileges=true` prevents
escalation even if the process is compromised.

**Instruction security levels** (CLA byte, bits 3–2):

| Level | Applies to         | Mechanism                          |
|-------|--------------------|------------------------------------|
| Plain | Core ISA           | Noise channel encryption only      |
| Signed | Standard ISA      | HMAC-BLAKE2b Auth Tag per frame    |

---

## Documentation

| Document | Description |
|----------|-------------|
| [`docs/en/asys-whitepaper.md`](docs/en/asys-whitepaper.md) | Background, design rationale, available options, and where ASys fits |
| [`docs/en/asys-spec.md`](docs/en/asys-spec.md) | Protocol specification: ISA, security model, APDU frame format |
| [`docs/en/asys-design-notes.md`](docs/en/asys-design-notes.md) | Architecture decision records (why not JSON / mTLS / shell) |
| [`docs/en/asys-conformance.md`](docs/en/asys-conformance.md) | Conformance testing guide |
| [`sdk/definitions/asys.isa`](sdk/definitions/asys.isa) | Machine-readable ISA definition (TOML) |

---

## Changelog

> **Version numbers**: `asyd` software versions (v0.3.x) and the ASys protocol version (v1.0, `0x0100`) are managed independently. The protocol version increments only when the wire format or instruction semantics change.

### v0.3.1 — 2026-05-28

- **Client-Speak-First** (ADR-22): after TCP connect, `asyd` waits for the client to send a 4-byte Magic (`0x41535953`) before sending anything; 1-second hardcoded timeout; mismatch or timeout → silent close, no response. Reduces exposure to generic port scanners.
- `--help` and `--version` flags added to `asyd`
- Conformance: `test_client_magic.c` (TC-MAG-001/002/003) added to `make check`

### v0.3.0 — 2026-05-27 (initial open-source release)

- `asyd` C daemon, zero external dependencies, static memory pool, zero `malloc` on the request path
- Noise IK (Curve25519 + ChaCha20-Poly1305 + BLAKE2b) transport, 1-RTT mutual authentication
- Agent public key whitelist (`/etc/asyd/authorized_agents`), SSH-style fingerprint verification
- Pre-Handshake Frame: server broadcasts public key before handshake, `~/.asys/known_hosts` management
- HMAC-BLAKE2b Auth Tag verification + Epoch_ID cross-session replay protection
- Core ISA: `SYS_CAPS`, `SYS_HELLO`, `SYS_STATUS`, `SYS_PROCS`
- Standard ISA: `PROC_THROTTLE`, `SVC_RESTART` (async, with `TASK_QUERY`)
- Per-session concurrency, 60s idle timeout, journald logging, systemd Caged Root deployment

---

## License

Apache 2.0 — Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)

Monocypher (cryptography library): CC-0 / ISC dual license.
