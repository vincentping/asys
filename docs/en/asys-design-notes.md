# ASys Architecture Decision Records (ADR)
## Agentic System Interface — Design Notes

> This document records the "why" behind ASys's key design decisions — why each choice was made, and why alternatives were rejected.
> Intended for core contributors, to prevent repeating mistakes already made.
> Last updated: 2026-05-27

---

## Table of Contents

**Protocol Design Foundations**
1. [Why Binary over JSON/Text?](#1-why-binary-over-jsontext)
2. [Why Big-Endian?](#2-why-big-endian)
3. [Why No Floating Point?](#3-why-no-floating-point)
5. [Why APDU Frame Format?](#5-why-apdu-frame-format)
12. [Why High Nibble Paging?](#12-why-high-nibble-paging)
6. [Why Port 7816?](#6-why-port-7816)
28. [Core ISA vs. Extensions Layering Analogy: USB Protocol](#28-core-isa-vs-extensions-layering-analogy-usb-protocol)

**Security Architecture**
4. [Why Noise IK over mTLS?](#4-why-noise-ik-over-mtls)
7. [Why Monocypher over libsodium/noise-c?](#7-why-monocypher-over-libsodium--noise-c)
9. [Why Public Key Whitelist?](#9-why-public-key-whitelist)
14. [Why HMAC-BLAKE2b over keyed BLAKE2b?](#14-why-hmac-blake2b-over-keyed-blake2b)
16. [Why "Privileged Daemon, Unprivileged Interface"?](#16-why-privileged-daemon-unprivileged-interface)
22. [Pre-Handshake Frame DoS Risk and Client-Speak-First (implemented in v0.3.1)](#22-pre-handshake-frame-dos-risk-and-client-speak-first-implemented-in-v031)
23. [0x6985 Network Retransmission Semantics: Replay Detection vs. Already-Delivered Confirmation](#23-0x6985-network-retransmission-semantics-replay-detection-vs-already-delivered-confirmation)
24. [Vendor Extension Memory Boundaries and Static Pool Isolation](#24-vendor-extension-memory-boundaries-and-static-pool-isolation)
25. [Non-Blocking Constraint on Audit Write-Before-Execute: The Emergency Interface Cannot Be Blocked by Disk I/O](#25-non-blocking-constraint-on-audit-write-before-execute-the-emergency-interface-cannot-be-blocked-by-disk-io)
26. [Identity Management in Cloud-Native Elastic Environments: Known Applicability Boundaries](#26-identity-management-in-cloud-native-elastic-environments-known-applicability-boundaries)
27. [Task_Handle TTL and Memory Reclamation Strategy](#27-task_handle-ttl-and-memory-reclamation-strategy)

**Implementation Decisions**
8. [Why C over Rust/Go?](#8-why-c-over-rustgo)
10. [Why Static Memory Pool over malloc?](#10-why-static-memory-pool-over-malloc)
11. [Why Instruction Bitmap over ACL?](#11-why-instruction-bitmap-over-acl)
13. [Why Append-Only Audit Log?](#13-why-append-only-audit-log)
17. [Why TCP_NODELAY on Every Accepted Connection?](#17-why-tcp_nodelay-on-every-accepted-connection)
18. [Why Pre-Handshake Frame for Server Identity Broadcast?](#18-why-pre-handshake-frame-for-server-identity-broadcast)
19. [Why SIGSTOP/SIGCONT for PROC_THROTTLE?](#19-why-sigstopsigcont-for-proc_throttle)
20. [Why fork/exec systemctl for SVC_RESTART?](#20-why-forkexec-systemctl-for-svc_restart)
21. [Why Command-Line Arguments over Config File?](#21-why-command-line-arguments-over-config-file)

**Cross-Language Interoperability**
15. [Noise IK Cross-Language Interoperability Pitfalls (C ↔ Python)](#15-noise-ik-cross-language-interoperability-pitfalls-c--python)

---

## 1. Why Binary over JSON/Text?

**Decision**: Protocol frames use strongly-typed binary; JSON / YAML / XML / plain text are not used.

**Background**: When AI agents call system interfaces, traditional tools (Ansible, SSH) return human-readable text output. Agents must parse this text using regex or another LLM, creating a risk of "parsing hallucinations."

**The fundamental problems with text formats:**

- **Format drift**: The output format of `ps`, `free`, `df`, and similar commands varies across distributions, locale settings, and version updates. A single Minor Version upgrade can silently break an agent's regex.
- **LLM token waste**: Agents spend compute parsing text format instead of making decisions. At high sampling frequencies (10Hz+), parsing overhead is non-trivial.
- **OOM-edge behavior**: At the critical edge of resource exhaustion, JSON parsers may crash because they cannot allocate memory — precisely the moment when agent intervention is most needed.
- **Ambiguity**: Text is designed for humans and is inherently ambiguous. Is "1.5" a CPU load or a version number? Context determines meaning; machines cannot reliably judge.

**Advantages of binary:**

- **Byte offsets permanently locked**: `SYS_STATUS`'s CPU load is always at offset 0, regardless of whether the underlying system is RHEL 9 or 10. The agent's parsing logic is a single `struct.unpack` call, not a regex.
- **Fixed-length structure**: Total response byte length never changes within the same protocol version (see `asys-spec.md` §1.9 Principle 3); parsing requires no state machine.
- **Zero-copy feasible**: Fixed-length binary structures can be mapped directly to C structs; the memory written by `recv()` is the final data, with no intermediate parsing buffer.

**Conclusion**: Determinism over debuggability. Debugging tools (`asys-inspect`) can be built on top of binary, but parsing hallucinations cannot be eliminated from text protocols.

---

## 2. Why Big-Endian?

**Decision**: All multi-byte fields are mandatorily big-endian (network byte order); little-endian is prohibited.

**Background**: `asyd` is implemented in C; SDKs are implemented in Python and Elixir; they run on platforms with different native byte orders.

**Why not little-endian (host byte order):**

- x86_64 is little-endian, but ARM, RISC-V, and other platforms have varying byte orders. Using little-endian would require byte-swapping every field on non-x86 platforms, actually increasing code complexity.
- The protocol's goal is cross-platform consistency, not optimization for any specific platform.

**Why big-endian (network byte order):**

- Big-endian is the industry standard for network protocols (TCP/IP, ISO 7816, all IETF RFCs); the entire network stack ecosystem defaults to big-endian.
- Python's `struct.pack('>H', value)` and Elixir's `<<value::big-16>>` both have native big-endian support.
- Cross-language interoperability is the primary goal: a C client and a Python client constructing the same frame must produce parse results in `asyd` that are completely identical (see `asys-spec.md` §3.7 verification requirements).

**Performance impact**: On x86_64, the `bswap` instruction completes byte-swapping in 1 clock cycle; overhead is negligible.

**Conclusion**: Cross-platform consistency takes priority over single-platform performance optimization.

---

## 3. Why No Floating Point?

**Decision**: Floating point is prohibited in the protocol; all percentages and load values are expressed as scaled integers and restored by the consumer.

**Background**: System monitoring data (CPU utilization, load averages) are inherently finite-precision sampled values.

**Problems with floating point:**

- **Cross-platform precision differences**: IEEE 754 floating point can produce minor precision differences on different platforms and compilers (especially at different optimization levels). This is fatal for protocol determinism — the same value may serialize to different bytes on the C side versus the Python side.
- **Alignment issues**: Floating-point numbers (especially `double`) have strict alignment requirements that easily introduce implicit padding, violating the "no implicit padding" principle (see `asys-spec.md` §3.7).
- **Unfriendly to binary protocols**: Floating point has special values like NaN, Inf, and denormals, introducing unnecessary complexity in a fixed-length binary protocol.

**Integer scaling approach:**

| Field | Scale Factor | Precision | Restoration |
|-------|-------------|-----------|-------------|
| Load average | ×10 | 0.1 | `value / 10.0` |
| CPU utilization | integer % | 1% | direct use |
| Process CPU usage | ×100 | 0.01% | `value / 100.0` |
| Network rate | integer Mbps | 1 Mbps | direct use |

Precision fully meets operations monitoring requirements.

**Conclusion**: Integer scaling is completely adequate for system monitoring scenarios; it eliminates cross-platform floating-point precision problems and serialization inconsistency risks.

---

## 4. Why Noise IK over mTLS?

**Decision**: Transport security uses Noise Protocol Pattern IK; mTLS is not used.

**Background**: `asyd`'s design goal is zero external dependencies, runnable on any POSIX system.

**Problems with mTLS:**

- **PKI dependency**: mTLS requires CAs, certificates, revocation lists (CRL/OCSP), and certificate rotation mechanisms. On edge nodes and embedded systems, maintaining PKI infrastructure is extremely costly.
- **Operational complexity**: Certificate expiry is a common cause of production incidents. As an emergency system interface, `asyd` cannot go dark due to certificate management errors.
- **Library dependency**: OpenSSL/BoringSSL is a heavyweight dependency, introducing significant code and potential vulnerability surface.

**Advantages of Noise IK:**

- **Zero certificate dependency**: Pure cryptographic primitives (Curve25519 + ChaCha20-Poly1305 + BLAKE2b); no CA required; no certificate management.
- **Single-file pure C implementation**: Based on Monocypher; the entire cryptographic layer is approximately 2,000 lines of C code — auditable with no external dependencies.
- **IK mode is a natural fit**: IK mode (Initiator Knows responder's static key) perfectly matches `asyd`'s deployment model — the agent knows the node's public key in advance; the handshake completes in 1-RTT, more efficient than mTLS's multiple round trips.
- **Identity binding**: After the handshake, the agent's static public key serves as its identity, directly indexing the Capability Map without any additional identity layer.

**Why IK and not other Noise patterns (NN, NK, XX):**

| Pattern | Characteristics | Problem |
|---------|----------------|---------|
| NN | Both parties anonymous | Cannot verify agent identity |
| NK | Only server has static public key | Client is anonymous; Capability Map is not possible |
| XX | Exchanges both parties' public keys during handshake; full forward secrecy | Requires extra RTT; cannot verify initiator identity early in handshake; cannot reject unauthorized agents at handshake start |
| **IK** | Client knows server's public key; 1-RTT | **Perfect fit; agent identity can be verified and the connection decision made from the first handshake message** |

**Forward secrecy tradeoff**: IK session content is protected by the initiator's ephemeral key (generated independently for each handshake); static private key compromise does not expose historical session content. Known limitation: the agent's static public key (identity) is encrypted under the server's static public key during the handshake — if the static private key is compromised, agent identities from historical handshake packets could theoretically be recovered. This is a known tradeoff of IK in exchange for 1-RTT and early identity verification — for `asyd`'s scenario of needing to reject unauthorized agents early in the handshake, XX mode would actually be a step backward. Future versions plan to introduce the **Rekey mechanism** natively supported by the Noise specification, periodically refreshing session keys during long-lived connections to narrow the impact window of static key compromise.

**Conclusion**: Noise IK achieves equivalent security strength while dramatically reducing implementation and operational complexity, fully consistent with ASys's zero-dependency design philosophy.

---

## 5. Why APDU Frame Format?

**Decision**: The frame format is derived from ISO/IEC 7816 APDU (`[CLA][INS][P1][P2][Lc][Data][Le]`) rather than designing a new format from scratch.

**Background**: ASys's founder has a smartcard industry background; APDU is a binary instruction frame format validated over decades.

**APDU's natural fit:**

- **Instruction semantics naturally aligned**: APDU's design philosophy of "instruction + parameters + expected response length" perfectly matches ASys's "atomic instruction" model. The `INS` byte directly corresponds to ASys instruction codes; `P1/P2` are parameters; `Le` is the expected response length.
- **Status word (SW) mechanism**: ISO 7816's SW1/SW2 two-byte status word is a mature error classification system; `0x9000` = Success is industry convention, reducing developer cognitive load. ASys extends this with the `0x6Fxx` subcode system.
- **Battle-tested**: Billions of smart cards worldwide run the APDU protocol; its edge cases and security properties have been validated under the most demanding conditions.
- **Extended frame support**: APDU's extended frame mechanism provides a smooth expansion path from 255 bytes to 65,535 bytes; ASys triggers it explicitly via the `CLA.Ext` bit, eliminating format inference ambiguity.

**Differences from ISO 7816:**

ASys redefines the CLA byte bit fields and does not fully follow ISO 7816's industry classification semantics (see `asys-spec.md` §3.1.2). The core is borrowing APDU's frame structure and SW system, not wholesale copying the entire protocol.

**Conclusion**: Standing on the shoulders of giants. APDU's design philosophy aligns closely with ASys's needs; decades of battle-testing is the best security credential.

---

## 6. Why Port 7816?

**Decision**: `asyd` listens on TCP port 7816 by default.

**Rationale:**

- **Homage to ISO 7816**: ASys's APDU frame format is directly derived from the ISO/IEC 7816 standard; the port number is an explicit acknowledgment of this technical heritage.
- **Community signal**: 7816 sends a clear technical signal to the smartcard/security engineering community — this is intentional, not coincidental. Anyone who knows the standard immediately understands this protocol's technical lineage from the port number alone.
- **Port availability**: 7816 is within the IANA registered port range (1024-49151) and is not occupied by any well-known service; there is no port conflict risk.

---

## 7. Why Monocypher over libsodium / noise-c?

**Decision**: Cryptographic primitives use Monocypher rather than libsodium or the noise-c library.

**Background**: Implementing Noise IK requires three cryptographic primitives: Curve25519, ChaCha20-Poly1305, and BLAKE2b.

**Problems with libsodium:**

- Requires system-level installation (`dnf install libsodium-devel`), introducing an external dependency and violating the zero-dependency design principle.
- Not usable in embedded or minimal environments without a package manager.

**Problems with noise-c:**

- A complete Noise Protocol framework library containing many protocol variants ASys does not need.
- Larger footprint, complex to compile, not suitable for embedding in a project.

**Advantages of Monocypher:**

- **Single-file integration**: Only `monocypher.c` + `monocypher.h` are needed; drop them directly into `src/asyd/core/`; zero system dependencies.
- **Approximately 2,000 lines of code**: Small enough to fully audit.
- **Covers required primitives**: Curve25519 (X25519 DH), ChaCha20-Poly1305 (AEAD), BLAKE2b (hash/KDF) — exactly what Noise IK needs.
- **CC0 public domain**: No copyright restrictions; fully compatible with ASys's open-source strategy.
- **No libc dependency**: Does not even depend on the C standard library; can run in extreme environments.

**Tradeoff**: We implemented the Noise IK state machine ourselves (`noise_ik.c`) on top of Monocypher rather than using an existing Noise framework. This adds approximately 300 lines of code but provides complete transparency and control — every line of cryptographic logic is in our codebase, auditable and debuggable.

**Conclusion**: Monocypher is the "just enough" minimalist cryptographic library, perfectly fitting ASys's zero-dependency philosophy.

---

## 8. Why C over Rust/Go?

**Decision**: The `asyd` reference implementation is written in C rather than Rust, Go, or other modern languages.

**Background**: ASys's core design constraint is zero runtime dependencies, runnable on any POSIX-compatible system.

**Problems with Go:**

- The Go runtime includes a GC and goroutine scheduler; binary size is typically 10MB+.
- GC pauses affect response latency determinism, conflicting with ASys's < 1ms target.

**Problems with Rust:**

- The Rust toolchain (rustup, cargo) is not standard on all Linux distributions, especially older embedded systems.
- Although Rust can achieve zero runtime, the compilation toolchain installation barrier is much higher than gcc.

**Advantages of C:**

- **Universally available**: `gcc` is standard on all Linux distributions; `gcc -O2 -pthread asyd.c -o asyd` compiles on any POSIX system with one command.
- **Zero runtime**: A C program's runtime is the operating system itself; no additional runtime layer.
- **Static memory control**: C allows complete control over memory layout, enabling a zero-malloc static pre-allocation pool.
- **Technical lineage consistency**: ASys draws from smartcard (C) and POSIX (C); a C reference implementation is a natural continuation of this lineage.

**Note**: SDK layers (Python, Elixir) are not subject to this constraint and use the languages most suitable for agent developers. C is only the implementation language for the `asyd` daemon.

**Conclusion**: C is the only viable choice for achieving "zero dependencies, runnable on any POSIX system."

---

## 9. Why Public Key Whitelist?

**Decision**: Agent authentication uses a **public key whitelist**; administrators write agent public keys directly to `/etc/asyd/authorized_agents`.

**Two trust directions:**

```
Client trusts server: SSH-style fingerprint verification
  First connection → asyd sends Pre-Handshake Frame (38B plaintext, containing server public key; see §18)
                  → client displays fingerprint; user confirms and saves to ~/.asys/known_hosts
  Subsequent connections automatically compare against known_hosts; reject on mismatch

Server trusts client: public key whitelist (pre-configured before connection)
  Administrator pre-writes agent public keys to /etc/asyd/authorized_agents
  After handshake completes, asyd checks whether the public key is in the whitelist;
  if not, returns 0x6982 and disconnects
```

**Registration and connection sequence:**

```
1. Administrator writes agent public key to server whitelist
   echo "<agent_pub_key_hex>" >> /etc/asyd/authorized_agents
   (or: cat ~/.asys/id_curve25519.pub | ssh user@host "cat >> /etc/asyd/authorized_agents")

2. Agent connects for the first time; confirms server fingerprint and writes to known_hosts

3. Subsequent connections pass the handshake directly
```

**Analogy with SSH:**

```
SSH                                    ASys
──────────────────────────────         ──────────────────────────────
Admin writes to authorized_keys        Admin writes to authorized_agents

First connect shows server             First connect shows server
  fingerprint                            public key fingerprint
User confirms → ~/.ssh/known_hosts     User confirms → ~/.asys/known_hosts

Subsequent passwordless login          Subsequent connections pass handshake directly
```

---

## 10. Why Static Memory Pool over malloc?

**Decision**: `asyd`'s core request path uses zero malloc; all runtime memory is statically pre-allocated at startup.

**Background**: One of `asyd`'s core missions is to remain responsive under extreme resource exhaustion — OOM, disk at 100%, CPU saturation.

**Problems with malloc under extreme conditions:**

- Under OOM, `malloc` returns NULL; if unchecked, this leads to null pointer dereference crashes.
- Even with NULL checks, runtime memory allocation failure means inability to handle new requests — precisely the moment when agent intervention is most needed.
- Dynamic allocation causes memory fragmentation; performance becomes unpredictable during long-term operation.
- `malloc`'d memory may be swapped out to disk under memory pressure, introducing indeterminate latency.

**Static pre-allocation + the triangle combination:**

```
mlockall(MCL_CURRENT)     → lock allocated memory; prevent swapping to disk
oom_score_adj = -1000     → OOM Killer cleans up asyd last
static memory pool        → one-time allocation at startup; zero malloc at runtime
```

All three are required:
- Static pool without mlockall: memory can still be swapped out; latency is indeterminate under pressure
- mlockall without static pool: dynamic allocation can still fail under OOM
- oom_score_adj without static pool: process survives but cannot handle requests

**Meaning of APDU_POOL_SIZE:**

```c
#define APDU_POOL_SIZE 8  // APDU parse buffer pool size
```

Currently three related constants are bound together:

```c
LISTEN_BACKLOG  = 8   // kernel TCP accept queue
MAX_CLIENTS     = 8   // maximum simultaneous connections
APDU_POOL_SIZE  = 8   // APDU parse buffer pool; one slot per connection
```

**The three values should be configured separately (TD-07):**

- `LISTEN_BACKLOG`: kernel parameter; independent of concurrent connections; can be set independently (recommended 16-128)
- `MAX_CLIENTS`: runtime concurrent connection limit; production environments may need 64+; should support compile-time override
- `APDU_POOL_SIZE`: should equal `MAX_CLIENTS`; the two can be bound together

The current `APDU_POOL_SIZE=8` is sufficient for development and testing; production deployments with multiple agents will need to increase this. See `CLAUDE.md` TD-07.

**Conclusion**: Static memory pre-allocation is the physical guarantee for `asyd` as the "last interface before the system dies" — not a performance optimization, but a survivability design.

---

## 11. Why Instruction Bitmap over ACL?

**Decision**: The Capability Map implements permission checks using an instruction bitmap (bitwise AND) rather than an ACL rule table.

**Background**: Each agent identity needs to correspond to a set of instructions it is permitted to invoke. The two mainstream implementation options are bitmaps and ACLs.

**Problems with ACL:**

- O(n) lookup, where n is the number of rules. CPU consumption grows linearly under large-scale malicious probing.
- Rule tables need parsing, introducing injection and format error risks.
- "Existence" and "permission" are mixed together in rules, making it difficult to implement "physically nonexistent" semantics.

**Advantages of bitmap:**

**1. O(1) lookup**: `(bitmap >> ins) & 1` is a single machine instruction; lookup time is constant regardless of instruction space size.

**2. Side-channel attack prevention**:
```
Wrong order: check permission → check existence
  Attacker can infer "present but disabled" instructions via response time differences

Correct order (ASys): check existence (bitmap) → check permission
  All unauthorized operations have identical response times; information leakage surface eliminated
```

**3. Multi-tenant isolation**: Different agents hold different bitmaps; agent A's `0x20` and agent B's `0x20` can be completely different. This is true multi-tenant isolation with no additional isolation layer. (Note: the current implementation uses a single global bitmap; per-agent fine-grained bitmaps are planned for a future release.)

**4. "Physically nonexistent" semantics**: An instruction with a 0 bit in the bitmap literally does not exist for that agent — it is not "denied," it is "void." Attackers cannot probe the system's capability boundary.

**Conclusion**: Bitmaps are the optimal data structure for achieving "instruction-level least privilege" and "side-channel defense"; O(1) lookup is an additional performance benefit.

---

## 12. Why High Nibble Paging?

**Decision**: The ISA encoding space uses the high nibble (upper 4 bits) of the INS byte as a logical page index, with 16 instructions per page.

**Background**: 256 instruction slots (0x00-0xFF) need to be reasonably distributed among Core ISA, Protocol Control, Standard ISA, and Vendor Extensions.

**Why the high nibble (rather than other divisions):**

- **Intuitive**: `0x2x` immediately identifies Process Control; `0x3x` is Network Control. Any developer can determine an instruction's group from its code without consulting a table.
- **Natural alignment**: 16 instructions per group corresponds exactly to one hexadecimal digit, perfectly matching how humans read hexadecimal.
- **Adequate expansion space**: Each group has 16 slots; most groups currently use only 2-3, leaving plenty of room for future expansion.

**Encoding space allocation logic:**

```
0x00-0x0F  Core ISA (16 slots)          → protocol constitution; defined instructions permanently locked
0x10-0x1F  Protocol Control (16 slots)  → protocol-internal; 0x10=continuation, 0x11=TASK_QUERY, 0x12=TASK_CANCEL
0x20-0x8F  Standard ISA (112 slots)     → 7 functional groups, 16 slots each; defined by protocol group
0x90-0xBF  Standard ISA Reserved (48)   → 3 pages; reserved by protocol group for future standard instruction groups; no Major Version required
0xC0-0xFF  Vendor Extensions (64 slots) → 4 pages; unlimited vendor reuse via Vendor_ID
```

**Vendor space design philosophy**: Vendor Extensions only need 4 pages / 64 INS slots because `Vendor_ID` (4 bytes) already provides a theoretically unlimited namespace — different vendors can reuse the same INS slot and are distinguished by Vendor_ID without conflict. Allocating more INS slots to Vendor is wasteful; reserving them for Standard ISA is more valuable.

**Significance of Standard ISA Reserved**: The 3 pages / 48 slots of `0x90-0xBF` give the protocol group room to add new standard instruction groups in the future without a Major Version bump — a buffer zone for long-term protocol evolution.

**Conclusion**: High Nibble Paging is optimal across three dimensions — readability, extensibility, and governance clarity — meeting the design goal of "anyone seeing an instruction code immediately knows its semantics."

---

## 13. Why Append-Only Audit Log?

> **Note**: This section describes design goals; it is not yet implemented in the current version and is planned for a future release.

**Decision**: Audit logs are enforced as append-only (`chattr +a` / `chflags sappnd`), written before execution, in a 24-byte fixed-length format.

**Background**: One of ASys's design philosophies is "all APDU instruction streams form a tamper-proof operation ledger" — this is the foundation for compliance auditing in the agent era.

**Why append-only:**

- Agents may hold high-privilege instructions but should not be able to modify their own operation records. Append-only is enforced through filesystem attributes, not agent self-discipline.
- Even if an agent is compromised or hallucinating, historical operation records remain complete and queryable.
- Meets the tamper-proof audit requirements of compliance scenarios in finance, healthcare, etc.

**Why write-before-execute (record first, then execute):**

```
Wrong order: execute instruction → write audit record
  If execution succeeds but logging fails, the operation is untraceable

Correct order (ASys): write audit record → execute instruction
  Even if execution fails, the audit record already exists; "what was attempted" is always recoverable
```

**Why the 24-byte fixed-length format:**

```
[Timestamp(8B)][Agent_PubKey_Hash(4B)][INS(1B)][CLA(1B)][Seq(4B)][Param_Digest(4B)][SW(2B)]
```

- **Fixed length**: No parser needed; can be directly `mmap`'d for random access; SIEM systems can consume directly.
- **Injection-proof**: Text logs can be "polluted" by carefully crafted parameter content; fixed-length binary format is completely immune.
- **Compact**: 24 bytes per record; a 4MB memory buffer can hold approximately 170,000 records — fully adequate for in-memory buffering during degraded scenarios.

**Rationale for the AUDIT_DEGRADED flag:**

When the audit system fails, `asyd` does not silently continue — it marks every response frame with `AUDIT_DEGRADED`, letting the agent know it is currently in degraded audit mode and leaving the decision of whether to continue executing high-risk instructions to the agent. This is the design philosophy of "transparent failure" rather than "silent failure."

**Conclusion**: Append-only + write-before-execute + fixed-length format together constitute ASys's audit black box — the foundational compliance guarantee for agent-controlled systems.

---

## 14. Why HMAC-BLAKE2b over keyed BLAKE2b?

**Decision**: Both Epoch_ID derivation and Auth Tag computation use **HMAC-BLAKE2b** rather than keyed BLAKE2b or HMAC-SHA256.

**Background**: ASys needs a keyed hash function (MAC) for:
- `Epoch_ID = HMAC-BLAKE2b(recv_key, "asys-epoch-v1")[:4]`
- `Auth_Tag = HMAC-BLAKE2b(recv_key, Header||Epoch_ID||Seq||Payload)[:16]`

The initial design used keyed BLAKE2b (Monocypher's `crypto_blake2b_keyed`), but cross-platform implementation validation exposed compatibility problems, leading to the standardization on HMAC-BLAKE2b.

**Why not HMAC-SHA256:**

- The C side of `asyd` already uses Monocypher, which has BLAKE2b built in. Using HMAC-SHA256 would require introducing a SHA256 implementation on the C side, breaking the zero-dependency principle.
- HMAC-BLAKE2b outperforms HMAC-SHA256 (BLAKE2b is approximately 3× faster than SHA256).

**Why changed from keyed BLAKE2b to HMAC-BLAKE2b:**

The initial design used keyed BLAKE2b, which is simple on the C side (`crypto_blake2b_keyed`). But during validation of the Python implementation on RHEL, every viable path was blocked:

| Python approach | Result | Reason |
|----------------|--------|--------|
| `hashlib.blake2b(key=...)` | ❌ | RHEL's hashlib uses OpenSSL under the hood; does not support the `key=` parameter |
| `hashlib.blake2b(..., usedforsecurity=False)` | ❌ | RHEL hashlib goes entirely through OpenSSL; no built-in implementation |
| `pyblake2` library | ❌ | Requires C build environment; build failed on RHEL |

**Solution**: Change the C side rather than the Python side — reuse the `hmac_blake2b()` helper function already implemented in `noise_ik.c`, with no new dependencies required. The Python side uses the `cryptography` library's `hmac.HMAC(key, hashes.BLAKE2b(64))`, validated on RHEL.

**Additional benefit**: HMAC-BLAKE2b uses the same underlying function (`hmac_blake2b()`) as Noise IK's KDF; the entire `asyd` cryptographic layer has a single MAC construction, reducing the audit surface.

**Lesson**: Cross-platform cryptographic implementations must be validated on the actual target platform; one cannot assume standard library API behavior is consistent across all distributions. RHEL's OpenSSL backend limitation is a real pitfall that could not have been predicted from documentation at design time.

**Conclusion**: HMAC-BLAKE2b is the only viable choice under the three constraints of "zero dependencies," "cross-platform compatibility," and "algorithm consistency."

---

## 15. Noise IK Cross-Language Interoperability Pitfalls (C ↔ Python)

> Recorded 2026-03-20. Source: interoperability debugging between `noise_ik.c` v0.4 and the `noiseprotocol` Python library.

When implementing Noise_IK_25519_ChaChaPoly_BLAKE2b interoperability between the C implementation (Monocypher) and the Python `noiseprotocol` library, three categories of subtle implementation differences were discovered. **All of these differences cancel out in single-language C tests; only cross-language testing can expose them.**

---

### Pitfall 1: BLAKE2b Construction Method for HKDF

**Symptom**: Handshake key derivation results are inconsistent; both sides derive different session keys.

**Root cause**: The Noise protocol specification requires HKDF to use an HMAC construction. The `noiseprotocol` library correctly uses **HMAC-BLAKE2b** (standard HMAC construction, block size = 128 bytes). Monocypher provides **keyed BLAKE2b**, which is a different cryptographic construction and produces different output.

```
HMAC-BLAKE2b(key, data) ≠ BLAKE2b-keyed(key, data)
```

**Fix**: Implement an `hmac_blake2b()` helper function in `noise_ik.c` (block size = 128 bytes), replacing all BLAKE2b calls in `mix_key()` and `split()`.

**Impact on community SDKs**: If the community contributes an Elixir SDK, confirm that its Noise library uses HMAC-BLAKE2b (HMAC construction, block size = 128 bytes), not keyed BLAKE2b. For any new language SDK integration, confirm that the Noise library uses the HMAC construction rather than the keyed construction.

---

### Pitfall 2: ChaCha20-Poly1305 Variant Selection

**Symptom**: AEAD encryption/decryption fails in both handshake and transport layers; MAC verification fails.

**Root cause**: The Noise protocol specification specifies **IETF ChaCha20-Poly1305** (RFC 8439) with a 12-byte nonce (4 zero bytes + 8-byte little-endian counter). The `noiseprotocol` library correctly implements this variant. Monocypher's `crypto_aead_lock` defaults to **XChaCha20-Poly1305** with a 24-byte nonce — a different algorithm.

**Fix**: Replace all AEAD operations in `noise_ik.c` from `crypto_aead_lock` / `crypto_aead_unlock` with Monocypher's `crypto_aead_init_ietf` + `crypto_aead_write` / `crypto_aead_read`.

**Impact on community SDKs**: When integrating any new language, confirm use of IETF ChaCha20 (12-byte nonce), not XChaCha20 (24-byte nonce) or other ChaCha20 variants.

---

### Pitfall 3: Noise IK DH Token Direction and split Key Assignment

**Symptom**: All pure-C tests pass, but decryption fails during Python interoperability. Two errors cancel each other out in C-only tests; cross-language testing is needed to expose them.

**Root cause**: Two DH direction errors + one split assignment error.

**Error 1**: DH computation direction for the `se` token in `write_msg2` is wrong.

```c
// Wrong: DH(s_priv, re_pub)
// Correct: DH(e_priv, rs_pub)
// Noise spec: responder's se token = server_ephemeral × client_static
```

**Error 2**: DH computation direction for the `se` token in `read_msg2` is wrong.

```c
// Wrong: DH(e_priv, rs_pub)
// Correct: DH(s_priv, re_pub)
// Noise spec: initiator's se token = client_static × server_ephemeral
```

**Error 3**: Output key assignment direction in `split()` is wrong.

```c
// Responder (asyd):  output1 → recv_key,  output2 → send_key
// Initiator (Agent): output1 → send_key,  output2 → recv_key
// Both ends must mirror each other; otherwise encryption and decryption directions are swapped
```

**Core lesson**: Single-language tests using the same implementation to play both initiator and responder cannot detect symmetry errors — errors cancel out on both sides. **Noise IK correctness verification must include cross-language or cross-implementation interoperability tests.**

---

### Checklist: Must Verify When Integrating a New Language SDK

Before a new language SDK (e.g., Elixir) integrates with `noise_ik.c`, verify each item:

| Item | Requirement | Common Error |
|------|-------------|--------------|
| HKDF construction | HMAC-BLAKE2b, block size = 128 bytes | Incorrectly using keyed BLAKE2b |
| AEAD variant | IETF ChaCha20-Poly1305, nonce = 12 bytes | Incorrectly using XChaCha20 (24-byte nonce) |
| DH token direction | Strictly follow initiator/responder roles per Noise spec | Direction swap cancels out in single-language tests |
| Interoperability test | Cross-language handshake + encryption/decryption verification; single-language self-testing is insufficient | Single-language tests cannot detect symmetry errors |

---

## 16. Why "Privileged Daemon, Unprivileged Interface"?

**Decision**: `asyd` adopts the "privileged daemon, unprivileged interface" pattern — running with restricted root privileges, but exposing only a strictly-structured binary APDU interface externally, with no shell or script execution capability.

**Background**: Standard ISA side-effect instructions (`PROC_THROTTLE`, `NET_ISOLATE`, `SVC_RESTART`) require kernel-level operational capabilities. This means `asyd` must hold certain privileges, but running with full root is dangerous.

**Why privileges are needed:**

| Capability | Purpose | Corresponding Instruction |
|------------|---------|--------------------------|
| `CAP_KILL` | Send signals to arbitrary processes | `PROC_THROTTLE` |
| `CAP_SYS_RESOURCE` | Adjust OOM score, mlockall | OOM protection |
| `CAP_NET_ADMIN` | Network namespace operations | `NET_ISOLATE` |
| `CAP_SYS_PTRACE` | Read detailed `/proc/<pid>/` information | `PROC_TREE` |
| `CAP_DAC_READ_SEARCH` | Read any user's `/proc/<pid>/stat`, `/proc/<pid>/status` | `SYS_PROCS` |

**Why not full root:**

Full root means that if `asyd` is compromised, an attacker can load kernel modules, modify hardware drivers, and restart the system. Through Linux Capabilities, precisely the four capabilities in the table above can be granted while explicitly excluding dangerous ones (`CAP_SYS_MODULE`, `CAP_SYS_RAWIO`, `CAP_SYS_BOOT`).

**The "unprivileged interface" neutralizes privilege risk:**

`asyd` holds privileges, but the external interface is strictly-structured binary APDU frames, not a shell. This means:

- **No command injection surface**: Agents operate on semantic instructions (`SVC_RESTART`), not command strings. `asyd` internally maintains a fixed mapping from semantic instructions to platform-native calls; the agent has no way to inject any shell metacharacters.
- **No buffer overflow path**: The frame format explicitly declares `Lc` in the header; `asyd` reads strictly according to `Lc` — it is physically impossible to read beyond the declared length.
- **Deterministic attack surface**: The parsing path is deterministic; there are no dynamic branches dependent on runtime state, dramatically reducing the risk of obtaining a root shell through buffer overflow.

**Two operating modes:**

| Mode | Privileges | Available Instruction Set | Use Case |
|------|-----------|--------------------------|----------|
| `full` | Restricted root (Capabilities) | Core ISA + Standard ISA | Production environment |
| `monitor` | Regular user | Core ISA only (observation instructions; no Standard ISA side-effect instructions) | Restricted environments, containers (**planned, not yet implemented**) |

**Note**: Core ISA includes observation instructions (`SYS_CAPS`, `SYS_HELLO`, `SYS_STATUS`, `SYS_PROCS`) with no side effects, as well as Protocol Control group instructions like `TASK_QUERY` (no side effects but not read-only system information). The phrase "read-only, zero side effects" is imprecise; the accurate description is "no Standard ISA side-effect instructions."

`asyd` self-checks effective Capabilities at startup, automatically degrades, and accurately reflects the currently available instruction set in the `SYS_CAPS` response bitmap. Agents sense the node mode through the bitmap without requiring additional protocol support. The `monitor` mode is planned for a future release.

**Correspondence with whitepaper §3.3:**

> "In ASys's world, agents have no 'denied' operations — only 'undefined' void. Operations that do not exist have no attack surface."

In monitor mode, Standard ISA instructions are 0 in the bitmap and physically do not exist for the agent; attackers cannot probe them.

**"Caged Root" implementation strategy:**

Rather than choosing between "full root" and "regular user," ASys takes a third path — **start as root, but lock root's capability boundary through kernel mechanisms**:

```ini
User=root                    # identity is root; authorized to execute SVC_RESTART and other high-privilege instructions
CapabilityBoundingSet=...    # retain only necessary capabilities; dangerous capabilities physically do not exist
NoNewPrivileges=true         # even if compromised, cannot escalate further via setuid or similar
```

The combined effect of three locks:
- **First lock (CapabilityBoundingSet)**: logical permission boundary — what can be done
- **Second lock (NoNewPrivileges)**: privilege escalation path sealed — cannot escape even if compromised
- **Third lock (Seccomp, see `impl-notes.md` §9.5)**: system call boundary — how to communicate with the kernel

Child processes from `fork/exec systemctl` inherit the parent's restricted capability set; `SVC_RESTART` can execute normally while no privilege escalation path exists.

**Tradeoff vs. "privilege separation (dual-process)" approach:**

A dual-process approach (worker + monitor) provides stronger theoretical isolation but introduces IPC complexity and additional process management overhead. Caged Root achieves equivalent security through kernel boundaries while maintaining single-process simplicity — for `asyd`'s threat model, this is the more appropriate tradeoff.

**Conclusion**: Privilege is a tool, not a goal. The Caged Root strategy lets `asyd` do its job with minimum capability, while the deterministic binary interface neutralizes privilege risk — this is the essential difference between "a controlled backdoor" and "a secure system agent."

---

## 17. Why TCP_NODELAY on Every Accepted Connection?

**Decision**: `asyd` sets `TCP_NODELAY` on every client socket immediately after `accept()`.

**Background**: ASys response frames are sent in two `send()` calls — first a 2-byte length prefix, then the encrypted payload. This is an inherent structure of the "length prefix + ciphertext" protocol frame format.

**How Nagle's algorithm interferes:**

TCP enables Nagle's algorithm by default — when there are unacknowledged small packets in flight, the kernel buffers subsequent data and waits for an ACK before sending together. With two `send()` calls:

```
send(prefix, 2B)    → kernel sends; waits for ACK
send(enc_buf, NB)   → kernel buffers; waits for ACK before sending
wait time = one network RTT
```

On loopback (RTT ≈ 0) this is invisible; on a real network, every frame waits an extra RTT, completely negating cache hit benefits.

**Asymmetry caused by language idioms:**

The same protocol design produces different behavior with different language idioms — a lesson worth heeding:

```python
# Python client (send_apdu): naturally merged; no Nagle issue
ciphertext = noise.encrypt(plaintext)
prefix = struct.pack('>H', len(ciphertext))
sock.sendall(prefix + ciphertext)   # string concatenation is Python idiom; one send
```

```c
/* C server (asyd.c): two sends; triggers Nagle */
send(ctx->fd, prefix, 2, 0);          // send 2-byte prefix first
send(ctx->fd, enc_buf, enc_len, 0);   // send payload; kernel waits for ACK
```

String concatenation is natural for Python developers, inadvertently avoiding the Nagle issue; two `send()` calls is natural for C developers, but triggers a 40ms wait. **The same protocol design with different language idioms produces dramatically different performance — completely invisible in loopback testing.**

**Measured data (before and after fix, Windows → RHEL VM, ping RTT < 1ms):**

| Scenario | Before Fix | After Fix |
|----------|-----------|-----------|
| SYS_STATUS cache hit | ~40ms | < 1ms |
| SYS_STATUS cold sample | ~90ms | ~51ms |
| SYS_PROCS | ~45ms | ~6ms |

**Why not merge the two send() calls:**

Merging requires copying prefix and enc_buf into a new buffer, introducing an extra memory copy and violating the zero-copy design principle. `TCP_NODELAY` solves the problem in one line with no side effects.

**Fix:**

```c
/* Set immediately after accept(); disable Nagle's algorithm */
int flag = 1;
setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
```

**Warning to future implementers:**

Any `asyd` port (Rust, Go, Elixir) that uses "length prefix + payload" split-send framing must disable Nagle's algorithm. This issue is completely invisible in loopback testing; only cross-network testing exposes it. **If the port language's idiom is merged sending (e.g., Python string concatenation, Elixir `IO.binwrite`), the problem is naturally avoided; if the idiom is split sending (e.g., C's two `send()` calls), Nagle must be explicitly disabled.**

**Conclusion**: The protocol frame structure mandates disabling Nagle's algorithm. This is not an optimization option; it is a correctness requirement.

---

## 18. Why Pre-Handshake Frame for Server Identity Broadcast?

**Decision**: After TCP connection establishment and before the Noise IK handshake, `asyd` proactively sends a 38-byte plaintext frame (`[Magic(4B)][Version(2B)][ServerPubKey(32B)]`) to the client. The client uses this to complete fingerprint verification and `known_hosts` management before initiating the Noise IK handshake.

**Background**: Noise IK mode (IK = Initiator Knows responder's static key) requires the client to know the server's public key before the handshake. The original implementation required users to manually extract the public key fingerprint from the RHEL node with `xxd` and paste it into the command line:

```bash
python3 client_core_isa.py <64-hex-pubkey> <host> 7816
```

This was a poor experience and inconsistent with the design goal of "simpler than SSH" — ASys has no username or password and should be more streamlined than SSH.

**Why not switch to Noise XX:**

Noise XX mode exchanges both parties' public keys during the handshake, eliminating the client's need to know the server's public key in advance. But the cost is:

- `noise_ik.c` would need to be completely rewritten; significant effort
- Three cross-language interoperability pitfalls have already been encountered (HKDF construction, AEAD variant, DH direction); XX mode would go through the same risks again
- XX has one more RTT than IK (2-RTT vs. 1-RTT)

**Why not embed a SYS_HELLO frame in the handshake:**

There was a suggestion to use the `SYS_HELLO (0x01)` frame format when the server sends its public key. This violates protocol layering principles — `SYS_HELLO` is a Core ISA business instruction belonging to the instruction layer within the encrypted channel; it should not appear in the plaintext transmission phase before the handshake. Semantic contamination would give `SYS_HELLO` two different meanings in two different contexts, increasing parsing complexity.

**Pre-Handshake Frame design:**

An independent 38-byte fixed-length structure, not using APDU format:

```
[Magic(4B): 0x41535953]["ASYS"][Version(2B)][ServerPubKey(32B)]
```

- `Magic` prevents accidental connection to non-ASys ports (e.g., accidentally connecting to SSH or another service)
- `Version` enables pre-handshake version negotiation; incompatible clients can disconnect before wasting a Noise IK handshake
- `ServerPubKey` is the necessary input for the client to initiate the Noise IK handshake

**Security analysis:**

Transmitting the server public key in plaintext carries no security risk — public keys are public by definition and do not need secrecy. Security depends on the fingerprint confirmation step (`known_hosts` mechanism). This is completely consistent with SSH's security model: SSH also transmits the server's public key in plaintext on first connection, allowing users to confirm the fingerprint before writing it to `~/.ssh/known_hosts`.

The client public key's protection is not affected — it is still encrypted in Noise IK msg1, exactly as before.

**User experience comparison:**

```
Before:
python3 client_core_isa.py <64-hex-pubkey> <host> 7816   ← required out-of-band key retrieval

After:
python3 client_core_isa.py <host> 7816                   ← as simple as SSH
→ asyd proactively sends public key
→ displays fingerprint; user confirms
→ written to known_hosts; automatic verification thereafter
```

**Conclusion**: The Pre-Handshake Frame achieves a user experience fully aligned with SSH at minimal implementation cost (one additional `send()` in `asyd.c`; `noise_ik.c` untouched), while maintaining clear protocol layer boundaries.

---

## 19. Why SIGSTOP/SIGCONT for PROC_THROTTLE?

**Decision**: `PROC_THROTTLE` (`0x20`) is currently implemented with `SIGSTOP/SIGCONT` rather than cgroup CPU throttling.

**Comparison of the two approaches:**

| | SIGSTOP/SIGCONT | cgroup CPU throttling |
|---|---|---|
| Capability | `CAP_KILL` | `CAP_SYS_RESOURCE` |
| Effect | Fully suspends the process | Limits CPU quota; process continues running |
| Side effects | Blunt; may disrupt process internal state | Graceful; process is unaware |
| Rollback | `SIGCONT` is sufficient | Remove cgroup configuration |
| Implementation complexity | Minimal (one `kill()` call) | Requires cgroup v2 filesystem operations |
| Demo visual impact | CPU drops to zero immediately; very visible | CPU gradually decreases; less noticeable |

**Why SIGSTOP was chosen initially:**

- The current goal is completing the OODA loop demo; SIGSTOP is trivial to implement; CPU drops to zero immediately during recording, creating a strong visual impact.
- `CAP_KILL` is already held; no additional Capability needed.
- The protocol semantics (`PROC_THROTTLE` = limit resource consumption) allow implementation choice — SIGSTOP is a valid platform mapping that does not violate the specification.

**Future evolution path:**

cgroup CPU throttling is the production-grade correct implementation — process-transparent, controllable side effects, clean rollback. Once the OODA loop demo is complete, the implementation can be upgraded to cgroup v2 `cpu.max` configuration; the external protocol interface remains completely unchanged.

**Conclusion**: Use SIGSTOP to close the loop first; use cgroup for production hardening later. A two-step approach; no rework needed.

---

## 20. Why fork/exec systemctl for SVC_RESTART?

**Decision**: `SVC_RESTART` (`0x22`) uses `fork/exec systemctl` to interact with systemd rather than calling the D-Bus API directly.

**Comparison of the two approaches:**

| | fork/exec systemctl | D-Bus API |
|---|---|---|
| External dependency | None (systemctl is a system standard) | Requires libdbus or sd-bus |
| Zero-dependency principle | Satisfied | Violated |
| Implementation complexity | Simple | High (D-Bus protocol is complex) |
| Memory impact | After fork, child process is independent; parent unaffected | Direct in-process call; no additional process |
| Error handling | Via child process exit code | Via D-Bus return value |

**On the boundary of the "zero malloc" principle:**

`fork` occurs at the edge of the request handling path — `asyd` forks and immediately execs; the child process runs independently; the parent does not wait and holds no reference to the child's memory. This is a boundary case for the "zero malloc" principle, not a core violation. The goal of zero malloc is to prevent dynamic allocation failure under high-pressure scenarios; the child process memory from `fork/exec` is completely isolated from the parent process, not affecting `asyd`'s main process memory determinism.

**Why not D-Bus:**

Introducing `libdbus` or `sd-bus` would break ASys's zero external dependency design principle. One of `asyd`'s core values is "`gcc -O2 asyd.c -o asyd` compiles in one command on any POSIX system" — a D-Bus dependency breaks this promise.

**Zombie process handling:**

"The parent does not wait" does not mean child process reclamation can be ignored — unreclaimed child processes become zombies, occupying PID table entries until `asyd` exits. Three handling approaches:

| Approach | Mechanism | Blocks request path | Complexity |
|----------|-----------|-------------------|------------|
| `waitpid()` blocking wait | Parent waits for child exit | Yes (not viable) | Low |
| `SIGCHLD = SIG_IGN` | Kernel automatically reclaims zombie processes | No | Minimal |
| double-fork | Let init adopt the grandchild process | No | High |

**Correction: `SIGCHLD = SIG_IGN` cannot be used**

`SVC_RESTART` needs to know `systemctl`'s exit code (success=0, failure≠0) to update the Task_Handle status to `Success(0x01)` or `Failed(0x02)`. `SIG_IGN` lets the kernel automatically reclaim child processes but also discards the exit code — it becomes impossible to distinguish restart success from failure; Task_Handle would remain in Pending state indefinitely.

**Choice: Register SIGCHLD handler; non-blocking reclamation**

```c
/* asyd initialization phase */
signal(SIGCHLD, sigchld_handler);

/* SIGCHLD handler: loop non-blocking reclamation of all exited child processes */
static void sigchld_handler(int sig) {
    (void)sig;
    int status;
    pid_t pid;
    /* WNOHANG: non-blocking; returns immediately; does not block request path */
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        /* look up pid in task_pool; update corresponding handle status */
        int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        task_pool_update_by_pid(pid, exit_code == 0 ? TASK_SUCCESS : TASK_FAILED);
    }
}
```

**Why WNOHANG does not block the request path**: `waitpid(-1, &status, WNOHANG)` returns immediately without waiting for the child to exit. The handler is called asynchronously when the signal is delivered, not occupying the dispatch thread.

**Conclusion**: `fork/exec systemctl` accomplishes the task while maintaining zero dependencies. SIGCHLD handler + WNOHANG accurately captures exit codes without blocking the request path — this is the only correct solution for child process reclamation and status tracking.

---

## 21. Why Command-Line Arguments over Config File?

**Decision**: `asyd`'s runtime parameters are passed via command-line arguments; no independent config file (INI/TOML) is provided.

**Background**: As a system-level daemon, `asyd` needs to allow administrators to adjust the listen port, bind address, and operating mode after deployment without recompilation.

**Problems with config files:**

- **Introduces parser code**: Any config file format (INI, TOML, JSON) requires a parser, violating the zero-dependency philosophy — the parser itself is code and a potential attack surface.
- **Redundant configuration layer**: `asyd`'s standard deployment method is a systemd unit; systemd itself is the configuration management layer. `ExecStart` is the config file; modifying parameters means modifying the unit file; administrator tooling (`systemctl edit`, `systemctl daemon-reload`) already covers this scenario.
- **Hot-reload limitations**: Port and bind address changes require restarting the daemon (re-`bind()`); config file + SIGHUP hot reload has no meaning for these parameters. The thing that genuinely needs hot reload (the whitelist) is already handled separately via SIGHUP.

**Advantages of command-line arguments:**

- **Zero parser**: `getopt_long` is the POSIX standard library; no external dependencies introduced.
- **Native systemd integration**: `ExecStart=/usr/local/bin/asyd --port 8816 --listen 127.0.0.1` completes configuration inline, consistent with Linux service management conventions.
- **Manageable parameter count**: The current number of configurable items is small (≤ 6); command line is entirely adequate.

**Currently supported parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--port <n>` | 7816 | Listen port |
| `--listen <addr>` | 0.0.0.0 | Bind address |
| `--debug` | off | Foreground execution + verbose stderr logging |

**Future expansion reserved:**

If the number of configurable items later exceeds 6, or "grouped configuration" requirements emerge (e.g., per-instruction-class timeout settings), config file support can be introduced at that time. Command-line arguments and config files are not mutually exclusive — command line is sufficient for the current stage; no premature over-engineering.

**Conclusion**: Command-line arguments are the simplest solution at the current parameter count, natively integrated with the systemd deployment model, with zero additional code — consistent with ASys's zero-dependency design philosophy.

---

## 22. Pre-Handshake Frame DoS Risk and Client-Speak-First (implemented in v0.3.1)

**Background**: In v0.3.0's initial design, after TCP connection establishment, `asyd` immediately and proactively pushed the 38-byte Pre-Handshake Frame (Server-Speak-First). This mechanism solved the key distribution problem functionally but introduced two known security risks. v0.3.1 adopted the improvement described in this section and implemented Client-Speak-First.

**Risk 1: Port scanning triggers outbound traffic**

Any scanner that completes the TCP three-way handshake will cause `asyd` to proactively send a 38-byte response. Although 38 bytes alone does not constitute an amplification attack (the response is not much larger than the request), Server-Speak-First breaks the firewall's default defensive posture — a scanner needs to send no application-layer data to trigger a server response, increasing passive exposure.

**Risk 2: Concurrent incomplete handshakes consume CPU**

An attacker can initiate a large number of TCP connections and advance to the first stage of the Noise IK handshake (sending `[e, es, s, ss]`), forcing `asyd` to perform Curve25519 point multiplication. In `asyd`'s role as an "emergency interface of last resort," having CPU exhausted by handshake computation is as dangerous as having it exhausted by OOM.

**Existing mitigation**

The `MAX_CLIENTS=8` static connection pool is a natural rate-limiting mechanism — connections beyond the limit queue at the `accept()` level without consuming unlimited handshake computation resources. The current risk is manageable under the static connection pool's protection.

**Improvement: Client-Speak-First**

The lowest-cost improvement: the agent sends a 4-byte Magic (`0x41535953`) after the TCP connection; `asyd` verifies it before pushing the Pre-Handshake Frame.

```
Before (Server-Speak-First):
  TCP handshake complete → asyd immediately pushes Pre-Handshake Frame (38B)

After (Client-Speak-First):
  TCP handshake complete → Agent sends Magic (4B) → asyd verifies → pushes Pre-Handshake Frame (38B)
```

**Timeout for waiting on Magic: hardcoded 1 second**

`asyd`'s timeout for waiting on Magic after `accept()` is hardcoded at **1 second** and not exposed as a startup parameter. Reasoning:

- A legitimate agent sending 4 bytes of Magic is a memory operation, taking microseconds; even with 200ms wide-area network latency, this is well within 1 second
- `asyd`'s primary deployment scenario is local or near-local networking (same DC / VPC); high-latency WAN is not the target scenario
- There is no reasonable production scenario that requires setting this value to 2 seconds or 500ms; exposing it as a parameter only adds configuration burden
- Compared to the 60-second session idle timeout, 1 second significantly shortens the time an invalid connection occupies a slot

**Honest statement of defense boundary**

The real value of Client-Speak-First is **reducing CPU and I/O cost per connection**:
- **Generic port scanners** (unaware of the ASys protocol) cannot trigger any response — this is the primary defense target
- Protocol-aware attackers can send the correct Magic, but Noise IK handshake CPU consumption is still rate-limited by `MAX_CLIENTS`
- **Connection exhaustion attacks** (repeatedly establishing TCP connections) cannot be fully defended at the application layer with either approach; fundamental defense relies on the network layer: it is recommended to deploy with `iptables` rate limiting on port 7816 per source IP and to enable `net.ipv4.tcp_syncookies=1`

**On WireGuard's Cookie/Puzzle mechanism**

WireGuard's Cookie mechanism (requiring clients to solve a hash puzzle under high load) is a more complete defense, but introduces additional protocol state and implementation complexity, conflicting with ASys's minimalist design philosophy. With the `MAX_CLIENTS` static connection pool already providing basic rate limiting, this is not adopted for now.

**Conclusion**: Client-Speak-First has minimal implementation cost and reduces resource consumption from invalid connections; fundamental defense against connection exhaustion is at the network layer, not the protocol layer.

## 23. 0x6985 Network Retransmission Semantics: Replay Detection vs. Already-Delivered Confirmation

**Background**: `0x6985` (Replay Detected) was originally designed to intercept within-session sequence number replay attacks. But in actual deployment, the most common trigger is not an attack but **network retransmission** — the SDK automatically resending the same Seq instruction packet after a response packet is lost.

**Problem**: The original specification's description of the agent handling strategy for `0x6985` was insufficient, only noting "re-increment Seq on rollover." If the SDK treats `0x6985` as an error (e.g., triggering an alert or marking the node as abnormal), it produces incorrect self-healing logic — even though the instruction was successfully received by `asyd`.

**Specific scenario (async instruction):**

```
① Agent sends SVC_RESTART (Seq=42)
② asyd queues successfully; returns Task_Handle + 0x9000
③ Response packet is lost in transit; Agent does not receive it
④ SDK times out and retransmits; sends SVC_RESTART again (Seq=42)
⑤ asyd detects Seq=42 has been seen; returns 0x6985
⑥ SDK incorrectly treats as "operation failed" → triggers unnecessary alert or node offline
   SDK correctly treats as "already delivered" → queries Task_Handle → obtains execution result
```

**Design decision: revised semantics of `0x6985`**

`0x6985`'s semantics are extended from "replay attack interception" to **"this Seq has already been processed by the server"** — regardless of whether the trigger was an attack replay or network retransmission, the server-side behavior is identical, and the agent-side semantics should also be identical:

- **Synchronous instructions**: treat as successfully executed; equivalent to receiving `0x9000`
- **Async instructions**: the previous send was received; query the most recent Task_Handle to confirm status

**Why not introduce a new status code (e.g., `0x9001 TASK_ALREADY_RUNNING`):**

Introducing a new status code would require the agent to carry business context (e.g., SvcName) during retransmission so `asyd` could return the corresponding Handle, increasing protocol complexity. The idempotency guarantee of `SVC_RESTART` (returning the existing Handle when the same service name is called again within the same session) already covers the business-layer duplicate call scenario. The two mechanisms combined fully handle retransmission scenarios without needing a new status code.

**Complementary relationship with idempotency guarantee:**

| Scenario | Triggering Mechanism | Result |
|----------|---------------------|--------|
| SDK retransmit; Seq unchanged | `0x6985` intercept | Agent queries existing Handle |
| SDK retransmit; Seq incremented | Idempotency guarantee | `asyd` returns existing Handle; no duplicate fork |
| Genuine replay attack; Seq unchanged | `0x6985` intercept | Same as network retransmission; attacker cannot distinguish |

Neither path produces additional side effects.

**Specification update**: Agent handling strategy for `0x6985` has been updated in `asys-spec.md` §1.6 status word table and §2.2.4 replay protection section.

## 24. Vendor Extension Memory Boundaries and Static Pool Isolation

**Background**: Core ISA and Standard ISA responses are all fixed-length structures; the static APDU buffer pool size can be precisely budgeted. But Vendor Extensions support extended frames (up to 65,535 bytes), creating tension between dynamic payloads and the static memory pool.

**Problem**: If Vendor Extensions' large payloads share the static pool with Core/Standard ISA:
- Vendor extension memory pressure could crowd out core instruction buffers
- Under extreme conditions (concurrent large-payload Vendor instructions), Core ISA's "emergency" capability is impaired
- Two-phase reading already prevents unauthorized payloads from entering memory, but where authorized large payloads land was not previously specified

**Decision: Physical isolation + hard payload limit**

1. **Vendor Extensions use an independent memory region** and do not reuse the Core/Standard ISA static APDU pool
2. **Hard Vendor payload limit of 16KB** (extended frame Lc > 16,384 returns `0x6700`) — sufficient for complex business data (SQL scripts, BGP configurations) while preventing memory runaway
3. **Vendor pool exhaustion returns `0x6400`** (Execution Blocked); does not affect Core/Standard ISA paths

**Why 16KB rather than larger:**

16KB can accommodate the business payload for the vast majority of operations scenarios (a SQL segment, a routing configuration, a shell script snippet). Scenarios requiring larger data transfers should use chained transport (`CLA.M=1`) with fragmentation rather than a single oversized frame — this is also a safer design, with each fragment independently authenticated.

**Conclusion**: Two-layer isolation (independent memory pool + hard payload limit) ensures that any Vendor Extension behavior cannot affect Core ISA's emergency capability.

---

## 25. Non-Blocking Constraint on Audit Write-Before-Execute: The Emergency Interface Cannot Be Blocked by Disk I/O

**Background**: ASys's audit design requires "write before execute" — the audit record is committed to disk before the instruction executes. This ensures operation traceability under normal conditions.

**Conflict**: One of `asyd`'s core missions is to serve as an emergency interface when disk I/O is 100% hung. If audit writes synchronously block the execution path, emergency instructions like `PROC_THROTTLE` will deadlock while waiting for audit writes — the emergency interface is killed by the very failure scenario it was called to help recover.

**Decision: Mandatory non-blocking audit writes**

- Audit writes are implemented via a separate thread or `O_NONBLOCK`, with a write timeout ceiling of **100ms**
- On timeout, immediately fall back to an in-memory ring buffer; **do not block instruction execution**
- Core ISA (`0x00-0x0F`) and Protocol Control (`0x10-0x1F`) execution paths may only call lock-free `audit_ring_push()`; they must not wait for any disk I/O

**Revision to the "write-before-execute" principle:**

The original semantics of "write to disk first, then execute" are not viable under extreme conditions. Revised to: **write to the audit queue (in memory) first, then execute; the audit queue is asynchronously persisted to disk.** The "write-before" guarantee is "written to the in-memory queue," not "written to disk" — when disk has failed and the system is in degraded state, the in-memory ring buffer is the temporary carrier for audit records; the `AUDIT_DEGRADED` flag notifies the agent that it is currently in degraded audit mode.

**Conclusion**: Non-blocking audit is a necessary condition for the "emergency interface" role, not an optional optimization.

---

## 26. Identity Management in Cloud-Native Elastic Environments: Known Applicability Boundaries

**Background**: ASys v0.3.0's identity model requires each machine to hold an independent Curve25519 key pair; agents confirm the server fingerprint and write it to `known_hosts` on first connection; administrators write agent public keys to `authorized_agents`.

**Known limitations**: This model has significant operational burden in the following scenarios:

- **K8s / public cloud high-frequency elasticity**: Node lifetimes may be only minutes; each scale-up produces a new key; the agent-side `known_hosts` and server-side `authorized_agents` need frequent synchronization
- **Ten-thousand-node initialization**: In batch deployments, the degree of automation in public key registration determines operational cost

**Why not introduce a CA-signed trust chain:**

Introducing a CA (even a self-signed enterprise CA) would re-introduce the very problems that motivated abandoning mTLS: certificate management, revocation mechanisms, and certificate rotation. This directly conflicts with the core rationale of ADR-4's choice of Noise IK — "`asyd` as an emergency system interface cannot go dark due to certificate management errors." Under the design priority of an emergency interface, operational convenience cannot come at the cost of introducing certificate dependencies.

**Pragmatic improvement directions (without introducing CA):**

- **Node startup script automation**: In cloud-native deployments, nodes automatically run `asys-keygen` at startup and push the public key to a centralized key management service (e.g., Vault, etcd); administrators maintain the key management service rather than each node's `authorized_agents`
- **Agent-side `known_hosts` automation**: Through deployment scripts, pre-populate `known_hosts` when the agent starts up, rather than relying on first-connection interactive confirmation
- **SIGHUP batch hot reload**: The orchestration layer (Ansible, K8s DaemonSet) uniformly distributes `authorized_agents` updates and triggers hot reload

**Conclusion**: ASys v0.3.0's identity model is well-suited for long-term stable nodes (physical machines, long-lifecycle VMs). High-frequency elastic cloud-native scenarios are a known boundary of applicability; the improvement direction is operational automation scripts, not introducing a certificate infrastructure.

**Mandatory constraint at the SDK implementation layer**: Regardless of deployment scenario, SDK implementations **must never perform automatic TOFU** (automatically trusting and writing unconfirmed fingerprints). When `known_hosts` has no record, the SDK must raise an exception and leave the trust establishment decision to the caller. This is a security boundary that cannot be enforced at the handshake byte level but must be clearly stated at the documentation level — an SDK that performs automatic TOFU transforms the plaintext public key transmission in the Pre-Handshake Frame from "a well-designed security mechanism" into "an entry point for man-in-the-middle attacks."

---

## 27. Task_Handle TTL and Memory Reclamation Strategy

**Background**: `asyd` uses static memory pre-allocation (`task_pool` with a fixed number of slots); a Task_Handle corresponds to one slot in the pool. If slots cannot be reclaimed promptly, new async instructions will return `0x6400` (Execution Blocked) once the static pool is exhausted.

**Two categories of scenarios requiring reclamation:**

1. **Pending timeout**: The underlying operation (e.g., `systemctl restart`) is unresponsive; the child process does not exit for an extended period. Without forced timeout, the slot is permanently occupied.
2. **Terminal handle not retrieved**: `asyd` has recorded Success/Failed, but the agent never sends `TASK_QUERY` due to hallucination, network interruption, or logic stall. The connection is still alive (maintained by TCP keepalive), but the slot would never be released by condition 1 (query reaching terminal state).

**Decision: Unified 30-second TTL covering all states**

Rationale for choosing unified TTL (rather than per-state TTL):

- **Simple implementation**: `task_pool_sweep_timeouts()` only needs to compare `time(NULL) - created_at > 30`; one condition covers all states with no state machine branching
- **Clear semantics**: The agent has a 30-second window to query any terminal Handle; 30 seconds is more than sufficient for any normal polling strategy (recommended polling interval: 1-3 seconds)
- **Static pool protection**: 30 seconds × maximum concurrent tasks = static pool peak occupancy ceiling; can be precisely calculated

**Why 30 seconds rather than shorter or longer:**

- `SVC_RESTART`'s execution timeout is itself 30 seconds (`TASK_TIMEOUT` triggers after 30 seconds); aligning TTL with execution timeout means "the agent must retrieve the result within 60 seconds of enqueue (30s execution + 30s result wait)" — a reasonable end-to-end SLA
- Shorter (e.g., 5 seconds) could cause Handles to expire while the agent is still in normal polling on high-latency networks
- Longer (e.g., 300 seconds) would occupy static pool slots for extended periods when the agent has disconnected

**Immediate reclamation on session disconnect (takes priority over TTL):**

TCP disconnect is the strongest signal that "the agent has gone away." When a session disconnects, `task_pool_release_session(session_id)` immediately zeros all slots belonging to that session (regardless of state), without waiting for TTL. This is the most common reclamation path and covers the vast majority of agent disconnection scenarios.

**Unified semantics of `0xFF`:**

Handle expired (TTL triggered), session mismatch, Handle never existed — all three cases uniformly return `Status=0xFF` (Not Found), with no distinction of specific reason and no leakage of slot state information.

**Conclusion**: 30-second unified TTL + immediate reclamation on session disconnect are complementary paths that ensure the static memory pool is promptly reclaimed under any agent behavior (normal, disconnected, hallucinating) without relying on active cooperation from the agent.

---

## 28. Core ISA vs. Extensions Layering Analogy: USB Protocol

Core ISA's relationship to Standard ISA + Vendor Extensions is analogous to the USB core protocol's relationship to device descriptors — USB's power management, handshake, and enumeration logic are the eternally unchanging core; whether the connected device is a mouse, a hard drive, or a graphics card is determined by each device's descriptor. This guarantees that any host (Agent) connecting to any device (Node) can complete the initial handshake immediately, while placing no limits on the device's functional boundary.

USB's Enumeration and Descriptor mechanism is nearly isomorphic to ASys's `SYS_CAPS` handshake process: the host does not need to know the device type in advance — it simply reads the descriptor through the standard handshake to understand the device's capabilities and load the corresponding driver. This is exactly the relationship ASys aims to establish between agents and nodes.

---

*This document is continuously updated; every significant design decision should be recorded here.*
