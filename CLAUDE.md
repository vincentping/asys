# CLAUDE.md

> Claude Code project context for the ASys repository.
> Read this file before starting any task.

---

## Project Overview

**ASys** (Agentic System Interface) — a typed binary protocol for AI agents to control Linux systems directly, without shell parsing.

- **asyd**: C daemon running on the managed node; accepts, authenticates, and executes ASys instructions
- **Protocol port**: TCP 7816 (homage to ISO 7816)
- **Core value**: skip shell text parsing; let AI agents interface with the system via a strongly-typed binary instruction set
- **Versions**: protocol v1.0 (`0x0100` in Pre-Handshake Frame) and software version (asyd v0.3.x) are managed independently

---

## Documentation

| Document | Description |
|----------|-------------|
| `docs/en/asys-spec.md` | Protocol specification: ISA, security model, APDU frame format |
| `docs/en/asys-design-notes.md` | Architecture decision records |
| `docs/en/asys-conformance.md` | Conformance testing guide |
| `docs/en/asys-whitepaper.md` | Background, design rationale, available options, and where ASys fits |

---

## Key Design Constraints (never violate)

**Protocol frame**
- Frame format: `[CLA][INS][P1][P2][Lc][Data][Le]` (ISO/IEC 7816 APDU)
- All multi-byte fields: **big-endian**, no exceptions
- No implicit padding; structs manually aligned to 4-byte boundaries
- **No floating point** in the protocol; percentages are integer × 100

**Transport security**
- Transport: **Noise Protocol IK** (Curve25519 + ChaCha20-Poly1305 + BLAKE2b)
- Auth Tag (16 bytes) appended at physical end of frame, not counted in Lc

**Key paths**
- Server: `/etc/asyd/id_curve25519` (private), `/etc/asyd/id_curve25519.pub`
- Client: `~/.asys/id_curve25519`, `~/.asys/id_curve25519.pub`
- Agent whitelist: `/etc/asyd/authorized_agents`

**Memory**
- **Zero malloc** on the core request path; all memory statically pre-allocated at startup

**Status words**
- `0x9000` = Success, `0x6D00` = Instruction Not Supported (never simulate)

---

## Directory Structure

```
src/asyd/
├── core/          ← apdu_parser.c  dispatcher.c  noise_ik.c  whitelist.c  auth_verify.c  task_pool.c
├── handlers/      ← one file per instruction (sys_caps/hello/status/procs  proc_throttle  svc_restart  task_query)
└── asyd.c
tests/conformance/ ← conformance tests (make check runs all)
examples/          ← E2E client scripts
tools/client/      ← asys_keygen.py (analogous to ssh-keygen)
```

---

## Build

```bash
make          # asyd + all conformance tests
make asyd     # daemon only → bin/asyd
make check    # build and run all conformance tests
make clean
```

**Dependencies**: none (C standard library only). Python client: `pip install noiseprotocol cryptography`

---

## Adding a New Instruction

1. Confirm the instruction code is defined in `docs/en/asys-spec.md` §1
2. Create a new `.c` file in `src/asyd/handlers/`
3. Register the handler in `src/asyd/core/dispatcher.c`
4. Update `CORE_CAPS_BITMAP` / `EXT_CAPS_BITMAP` in `dispatcher.h`
5. **Update the ISA print line in `asyd.c` startup log** (static printf, does not update automatically)
6. Update ISA definition in `sdk/definitions/`
7. Add conformance tests in `tests/conformance/`

---

## Code Discipline

- Only modify what the task explicitly requires — no opportunistic cleanup of surrounding code
- Preserve existing code style
- Clean up any dead imports / variables / functions introduced by your own changes; leave pre-existing dead code unless asked
- Report unrelated issues; do not fix them
