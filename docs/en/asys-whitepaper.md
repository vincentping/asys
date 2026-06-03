# ASys Whitepaper
## Agentic System Interface

**ASys** (Agentic System Interface) is an exploratory protocol that provides AI agents with a binary-native channel for system control — interacting directly with the system through strongly-typed APDU binary frames rather than shell text. The protocol is open to all POSIX-compatible systems; the reference implementation `asyd` targets Linux as its primary platform.

The daemon **asyd** (ASys Daemon) runs on the managed node and is responsible for accepting, authenticating, and executing ASys instructions.

> Protocol version: v1.0 (`0x0100`) | Reference implementation: asyd v0.3.1 | 2026-06-01
>
> Protocol version and software version are managed independently. v1.0 covers the stable, implemented portions; features defined in the specification but not yet implemented are marked *planned*.
>
> Related documents: [asys-spec.md](asys-spec.md) | [asys-design-notes.md](asys-design-notes.md) | [asys-conformance.md](asys-conformance.md)

---

1. [Background and Motivation](#1-background-and-motivation)
2. [Design Philosophy](#2-design-philosophy)
3. [Current System Control Options](#3-current-system-control-options)
4. [Protocol Mechanics Overview](#4-protocol-mechanics-overview)
5. [Security Model](#5-security-model)
6. [Roadmap and Outlook](#6-roadmap-and-outlook)

---

## 1. Background and Motivation

### 1.1 The Design Assumptions of Existing Tools

Unix Shell (1971) and POSIX (1988) were designed **for humans**: command output is human-readable, interactions happen at human pace, and permission models are centered on user identity. This ecosystem has served well for decades, giving rise to mature tools like SSH, Ansible, and Kubernetes Operators — each battle-tested at scale in its respective domain.

When the operator shifts from a human engineer to an AI agent, several concrete problems emerge worth re-examining:

**The cost and fragility of text parsing**: An agent executing commands over SSH receives unstructured text output — which must be parsed with regex or another LLM. Minor format changes (such as column-width variations in `ps` output) can silently break parsing. This is solvable, but requires constant attention.

**Permission granularity and the risk of agent misbehavior**: SSH's permission model is session-scoped. Giving an agent an SSH session effectively grants a wide operating surface. Given that agents can hallucinate, this surface carries higher risk than it does for human operators.

**Availability under extreme conditions**: Under Out-Of-Memory (OOM) or disk-full conditions, SSH logins may time out and Ansible may fail to start due to memory allocation failures. If you want an agent to perform diagnostics or limited intervention under such conditions, existing tools have availability problems.

**Sampling frequency and connection overhead**: If an agent needs to sample system state at high frequency (multiple times per second), the per-connection handshake overhead of SSH becomes a bottleneck. Long-lived connections solve this, but existing tools are not optimized for this use case.

Some of these problems can be mitigated by layering on top of existing tools; others are structural constraints inherent to the tools' original design assumptions. ASys is an experiment in this context: if you designed a system interface specifically for AI agents, from first principles, what would it look like?

### 1.2 Design Starting Point: What Kind of Interface Does an Agent Need?

Starting from a few practical characteristics of AI agents, we can derive some interface design preferences:

**Agents are more reliable processing structured data than parsing text.** A binary format with fixed byte offsets has near-zero parsing cost and no risk of format drift. This is the rationale behind ASys's choice of APDU binary frames.

**Long-lived connections suit high-frequency interaction better than per-request handshakes.** Once a connection is established, round-trip latency for subsequent instructions approaches the physical limit. For scenarios requiring high-frequency sampling or rapid sequential operations, eliminating repeated handshake overhead has real practical value.

**Instruction-level permissions suit agents better than session-level permissions.** Agents make mistakes, and they make them fast. If permission boundaries are fine-grained enough — only explicitly authorized instructions exist, and unauthorized ones are rejected at the protocol layer — then the blast radius of an agent hallucination can be bounded in advance.

**Auditability matters especially for AI agents.** Human operators' decision-making is generally observable; AI agents' is often opaque. If the interface layer has built-in auditing, with a complete record of every system intervention, humans can review agent behavior after the fact — this is the foundation for building trust.

These four starting points correspond to ASys's core design: strongly-typed APDU binary frames, Noise IK encrypted long-lived connections, positive-authorization via Capability Map, Epoch_ID replay protection, and an append-only audit chain. Each choice involves tradeoffs; detailed reasoning is in `asys-design-notes.md`.

---

## 2. Design Philosophy

### 2.1 Principle One: Determinism First

Every ASys instruction maps to exactly one atomic operation. When an agent issues `SVC_RESTART`, the result is always "restart the service" — unaffected by environment, shell version, or system state. Determinism is the foundation of ASys's protocol integrity.

**Binary Immortality**

The `0x03` instruction defined by the ASys protocol always returns the same fixed byte layout. Whether the underlying system is RHEL 9.x or 10.x, the agent always finds the PID at byte offset 2, CPU percentage at byte offset 6. A fixed byte layout means the agent's parsing logic can be a single `struct.unpack` call rather than a regex that may break at any time. This is not merely a performance concern — it is a **difference in reliability by orders of magnitude**.

**Conclusion: All Compute Goes to Decision-Making**

When parsing overhead drops to zero, agents no longer spend any tokens guessing at text semantics, nor do they need to maintain extra hallucination-validation logic. 100% of compute goes toward what actually matters: perception, reasoning, and decision. For agent architects, this means lower inference costs and simpler error-handling paths.

### 2.2 Principle Two: Eliminate the Physical Attack Surface (Instruction Existence over Access Control)

An agent must hold the corresponding Capability to invoke a specific instruction. Permissions are not session-level "all-or-nothing" — they are **precise, instruction-level mappings**.

**Positive Authorization vs. Negative Interception**

Traditional security models (SSH/sudo) were designed for **human operators** — human actions are exploratory and intent is difficult to declare in advance, so "broad default permissions + **negative interception**" fits how humans work and is a reasonable design choice. But when the operator becomes an AI agent, this assumption no longer holds: agent behavior is programmatic, and permission boundaries can be precisely declared at deployment time.

ASys uses **positive authorization**: the system is completely dark to an agent — only instructions explicitly lit up in the Capability Map have physical existence. Permissions are not separate ACL rules; they are encoded directly in the Capability Map. Instructions not registered in the bitmap are discarded at the unpacking stage and never enter any execution path.

**Conclusion**

Least privilege is not a security policy option in ASys — it is a physical property of the protocol. No registration means no existence; no existence means no attack surface.

### 2.3 Principle Three: Separation of Mechanism and Policy

Core ISA (`0x00-0x0F`) defined instructions are permanently locked — once published, they cannot be changed. Standard ISA (`0x20-0x8F`) defined instruction semantics are similarly locked, but empty slots can be filled by the protocol group as needed. Protocol Control (`0x10-0x1F`) is reserved by the protocol group for internal use. `0x90-0xBF` is the Standard ISA reserved range, set aside for future standard instruction groups defined by the protocol group. Vendor Extensions (`0xC0-0xFF`) are freely defined by domain administrators — ASys provides only the "handle" (authentication and transport) without touching the "blade" (domain logic).

**Hard Core, Soft Boundary**

- **Core ISA (protocol constitution, immutable)**: the agent's "retina" for observing the world. `0x02` always returns system load, whether the underlying system is Linux, BSD, or some POSIX-compatible system 50 years from now. This cross-generational compatibility is what gives any agent confidence to call ASys instructions directly. Core ISA lowers the barrier to entry — any agent can connect and start sensing without knowing anything about the node.

- **Standard ISA + Vendor Extensions (domain law, evolvable)**: the "scalpel" for different vertical domains. Standard ISA (`0x20-0x8F`) is defined by the protocol group to cover common scenarios; Vendor Extensions (`0xC0-0xFF`) are freely extended by domain experts — a database agent might need `PROC_CHECKPOINT`, a network agent might need `NET_BGP_BOUNCE`. ASys provides only the handle (authentication and transport), not the blade (specific logic). This layer raises the application ceiling — domain experts can build instruction ecosystems of arbitrary depth within the protocol framework.

**Conclusion**

A lean core ensures long-term compatibility; rich extensions ensure practical utility. The separation of mechanism (Core) and policy (Standard ISA + Vendor Extensions) allows ASys to maintain protocol stability while supporting the extension needs of different vertical domains.

---

## 3. Current System Control Options

### 3.1 Existing Approaches and Their Use Cases

When an AI agent needs to control a system, several options are available today. Each has its strengths, suitable scenarios, and target audience.

**SSH + Shell Scripts / Ansible**

This is the most mature and general-purpose choice — 30 years of production validation, native support on virtually every system. Ansible's agentless architecture is a significant advantage: no client software needs to be installed on the target machine; SSH is sufficient. YAML Playbooks are highly readable for operations engineers; team collaboration, code review, and auditing are all natural. Idempotency design has been validated at scale, and error handling and retry logic are mature.

For scenarios dominated by human engineers doing configuration management and batch deployment, this is the reasonable first choice. When an AI agent uses these tools over SSH, it is effectively "simulating the way a human engineer works" — this is not a criticism, but a description: these tools were designed for humans, and an agent borrowing them is a natural transitional choice. But this also means that unstructured text output and the absence of protocol-level permission granularity are inherent limitations of this approach in agent scenarios.

**Kubernetes Operator / Declarative API**

K8s Operators represent a different philosophy: declare the desired state and let the controller converge to it. This approach excels at the cloud-native application layer — automatic handling of intermediate states, failure retries, and rolling updates, backed by the entire CNCF ecosystem with top-tier tooling and observability.

For applications running on K8s, an Operator is the natural choice for lifecycle management. Its applicable boundary is the resource layer managed by K8s; bare-metal servers, embedded devices, and low-level recovery when K8s itself has problems fall outside its design scope.

**Custom gRPC / Binary Protocol over SSH**

Some teams build their own control plane for agents: wrapping gRPC over SSH or TLS, using Protobuf to define strongly-typed interfaces. The advantage is full control over protocol details, tailored to specific needs, with good performance and type safety. For teams with existing gRPC infrastructure, this is a natural choice.

gRPC is a general-purpose RPC framework — it solves the problem of "how to transmit data." But in Agent-to-OS scenarios, each team still has to solve another layer of problems independently: how to define instruction semantics, how to express permission boundaries at the protocol layer, and how to build in replay protection and auditing. This is outside gRPC's scope, which means this work cannot be reused across teams.

**ASys**

ASys offers an additional path alongside the options above: designed specifically for AI agents as operators, with the frame format, authentication mechanism, and audit chain all built on the premise that "the agent is the primary client."

It is not intended to replace any of the above. A system can comfortably run Ansible (for human engineers) and ASys (for AI agents) simultaneously. The gap ASys aims to fill is: when an agent needs to control a system with high frequency, low latency, and full auditability — and needs the interface to remain available under extreme conditions — there is currently no standardized solution designed specifically for this scenario.

### 3.2 ASys Design Tradeoffs

Choosing ASys means accepting specific tradeoffs:

| Design Choice | Benefit | Cost |
|---------------|---------|------|
| Static memory pre-allocation | Process survives OOM; deterministic latency | Hard cap on concurrent connections (currently 8, adjustable at compile time) |
| Zero external dependencies (C standard library only) | Deployable on any POSIX environment; no runtime risk | Features must be self-implemented; no ecosystem libraries available |
| Capability Map positive authorization | Precise agent permission boundaries; no unauthorized access possible | Each agent requires manual public key registration by an administrator |
| Binary APDU frames | Zero parsing overhead; format does not drift with system version changes | Less intuitive to debug than text protocols; requires tooling support |
| Noise IK instead of mTLS | No certificate dependency; 1-RTT handshake | No PKI ecosystem; key management must be handled independently |
| Append-only audit chain | Every instruction is traceable and tamper-proof | Storage overhead; high-frequency scenarios need async write optimization |

These are not arguments that "ASys is better" — they are the basis for "if your scenario happens to need these properties, ASys is worth considering."

### 3.3 Scenarios Where ASys Is Worth Considering

Based on the above tradeoffs, ASys is well-suited for the following scenarios:

**High-frequency agent sampling of system state**: Long-lived connections + binary frames; `SYS_STATUS` RTT is < 1ms on cache hit, suitable for agents monitoring system metrics in real time.

**Last resort interface under extreme conditions**: SSH may become unavailable during OOM; `asyd` is designed to survive such conditions (Core ISA diagnostic instructions are always available; control instructions that depend on `fork()` may return `0x6F01` under severe OOM, signaling the agent to switch to a read-only diagnostic path).

**Precise control over agent permission boundaries**: Capability Map granularity is per-instruction; different agents can be granted different instruction subsets, and permission changes take effect via SIGHUP hot reload.

**Bare-metal / embedded / container-free environments**: Zero external dependencies, a single static binary — deployable on any POSIX environment capable of running C programs.

---

## 4. Protocol Mechanics Overview

### 4.1 Frame Format: Standing on the Shoulders of Giants

ASys's frame format is derived from the APDU (Application Protocol Data Unit) instruction system — one of the most widely deployed binary instruction protocols in history. APDU has been adopted as the application-layer instruction format by multiple international standards including ISO/IEC 7816 (contact smart cards) and ISO 14443 (contactless cards): every EMV bank chip card, every e-passport, every NFC transit card and access card, and every SIM card's application layer runs on the same APDU structure. SIM card deployment alone exceeds 10 billion units globally; combined with bank cards, identity documents, and access/transit cards, the APDU protocol family covers devices in the hundreds of billions — every edge case, every error path has been validated under the most demanding real-world conditions imaginable.

APDU's design philosophy is "instruction + parameters + expected response length" — it is fundamentally built for **machine-to-machine control**: a card reader (machine) sends structured instructions to a smart card (machine), with no human parsing involved. This is structurally identical to ASys's core premise — AI agents controlling systems directly. The APDU status word (SW) system has become industry convention: `0x9000` = Success, `0x6982` = Access Denied. ASys redefines the CLA byte bit fields on this foundation and extends the `0x6Fxx` subcode system (low byte carries kernel error subcodes), porting this decades-validated frame structure into the agent era.

The default port **7816** is an explicit homage to the ISO/IEC 7816 technical heritage.

**Standard Frame Layout (7 fields):**

```
[CLA][INS][P1][P2][Lc][Data][Le]
  1    1    1   1   1   var   1   (bytes)
```

| Field | Length | Semantics |
|-------|--------|-----------|
| `CLA` | 1B | Instruction class: protocol version (bit7-5), chaining flag (bit4), security level (bit3-2), extension frame (bit1) |
| `INS` | 1B | Instruction code; directly indexes the instruction group |
| `P1/P2` | 1B each | Instruction parameters |
| `Lc` | 1B | Byte count of the Data field |
| `Data` | variable | Payload (includes Seq sequence number) |
| `Le` | 1B | Expected response length; `0x00` means return status word only |

Secure frames append a 16-byte Auth Tag (ChaCha20-Poly1305) after `Le`, not counted in `Lc`, covering the complete frame header + Epoch_ID + Seq + Payload — any tampered field causes authentication to fail.

### 4.2 Instruction Set Layering: High Nibble Paging

ASys uses the **high nibble (upper 4 bits)** of the INS byte as a logical page index, dividing 256 instruction slots into five layers:

| Code Range | Group | Governance Rule |
|------------|-------|-----------------|
| `0x00-0x0F` | **Core ISA** | Protocol constitution — defined instructions permanently locked; cannot be changed in any version |
| `0x10-0x1F` | **Protocol Control** | Protocol-internal reserved (`0x11` TASK_QUERY, `0x12` TASK_CANCEL, etc.) |
| `0x20-0x8F` | **Standard ISA** | 7 functional groups (Process / Network / Diagnostics / Storage / Security / Runtime / Hardware); semantics locked |
| `0x90-0xBF` | **Standard ISA Reserved** | Reserved by protocol group for future standard instruction groups |
| `0xC0-0xFF` | **Vendor Extensions** | Unlimited vendor reuse via 4-byte `Vendor_ID` namespace |

This design lets any developer determine an instruction's group at a glance: `0x2x` is immediately recognizable as Process Control, `0x3x` as Network Control, without consulting a table.

Core ISA is the agent's "retina" for observing the world: `0x00 SYS_CAPS` returns the node's capability bitmap and static descriptor; `0x01 SYS_HELLO` establishes the session and aligns clocks; `0x02 SYS_STATUS` provides real-time system vitals at high frequency (10Hz+); `0x03 SYS_PROCS` returns a summary of high-CPU processes. These four instructions have no side effects and can be called immediately after the handshake — they are the foundational primitives for an agent to sense a node's state.

### 4.3 Connection Establishment: Three Steps

From TCP connection to the point where business instructions can be sent, three steps occur:

**Step 1: Client Magic (4 bytes)**

After the TCP connection is established, the agent sends a 4-byte Magic (`0x41535953`, ASCII: "ASYS"). A mismatched or timed-out Magic causes an immediate disconnect without sending any data — generic port scanners cannot trigger a server response.

**Step 2: Pre-Handshake Frame (38 bytes, plaintext)**

Once the Magic is verified, `asyd` sends:

```
[Magic(4B)][Version(2B)][ServerPubKey(32B)]
 0x41535953  0x0100      Curve25519 static public key
```

This step solves the key distribution problem — the agent does not need to obtain the server's public key out-of-band; `asyd` announces it before the handshake. The agent compares the received key's fingerprint against `~/.asys/known_hosts`: on first connection, it waits for administrator confirmation and saves the fingerprint; on subsequent connections, it verifies automatically. Transmitting the public key in plaintext carries no security risk — security depends on fingerprint confirmation, exactly as with SSH's first-connection mechanism.

> **SDK Security Requirement**: The Pre-Handshake Frame solves key distribution, not first-connection trust establishment. SDKs **must not automatically write unconfirmed fingerprints** to `known_hosts` (automatic TOFU). Automatic trust means an in-network ARP spoofing or DNS poisoning attack is sufficient to complete a man-in-the-middle attack. In cloud-native environments with dynamically provisioned nodes, it is recommended to pre-inject node public keys into `~/.asys/known_hosts` via an orchestration system (K8s Secret / Ansible / Vault) before the first connection, establishing trust before any connection is made.

**Step 3: Noise IK Handshake (1-RTT)**

```
Agent → asyd:  [e, es, s, ss]   ← agent ephemeral key + agent static key (encrypted)
asyd  → Agent:  [e, ee, se]     ← asyd ephemeral key
```

After the handshake, both parties hold symmetric session keys. `asyd` immediately derives `Epoch_ID` (4 bytes, never transmitted over the network) from the handshake key, for use in Auth Tag computation for all subsequent instructions. It simultaneously checks whether the agent's static public key is in the `authorized_agents` whitelist; if not, it returns `0x6982` and disconnects. The entire process completes in 1-RTT.

### 4.4 A Complete Interaction

Using `SVC_RESTART` (an async instruction to restart nginx) as an example, here is the complete flow from post-handshake to result confirmation:

```
① Agent → asyd:  [CLA=0x04][INS=0x22][Lc=0x0A][Seq=42][nginx][Le=0x06][Auth Tag]
                   Sec=01 (Signed)                service name without .service suffix

② asyd  → Agent:  [Task_Handle=0x0001AABB][SW=0x9000]
                   Queued successfully; fork initiated

③ Agent → asyd:  [INS=0x11][Lc=0x04][0x0001AABB][Le=0x03]
                   TASK_QUERY, polling after 3 seconds

④ asyd  → Agent:  [Status=0x01][SW=0x9000]
                   Success; handle released
```

A few details worth noting: the service name in `SVC_RESTART` does not include the `.service` suffix — `asyd` appends it internally, eliminating path injection attack surface at the protocol layer. `0x9000` in step ② means "queued successfully," not "execution complete" — the agent must poll for the final result via `TASK_QUERY`. The upper 16 bits of Task_Handle are bound to the Session_ID; querying a handle that does not belong to the current session always returns `0xFF`, leaking no information.

### 4.5 Protocol Evolution Guarantees

ASys has explicit protocol-level constraints for long-term compatibility:

- **Offset immutability**: byte offsets of any existing Core ISA fields never change; new fields may only occupy reserved space or extend at the end
- **Atomic substitution**: if a field becomes obsolete, it is filled with a sentinel value (`0xFF` / `0x0000`) rather than shortening the response — total response byte length never changes within the same version
- **Silent ignore**: agents must be able to safely ignore unknown Reserve fields; servers must be able to ignore unknown padding bits

These three rules together ensure that agent parsing code written today is expected to remain valid on some POSIX-compatible system 50 years from now.

---

## 5. Security Model

ASys's security architecture has four layers, forming defense in depth from transport to execution: transport encryption (Noise IK) → identity verification (public key whitelist) → permission isolation (Capability Map) → audit trail (append-only audit chain). Each layer is a physical property of the protocol, not a configurable policy option.

### 5.1 Transport Security: Why Not mTLS

ASys foregoes the industry-common mTLS in favor of **Noise Protocol Pattern IK** (Curve25519 + ChaCha20-Poly1305 + BLAKE2b). This is not a matter of preference — it follows from design constraints:

mTLS depends on PKI: CAs, certificates, revocation lists (CRL/OCSP), and certificate rotation. One of `asyd`'s core missions is to remain alive under extreme system pressure (OOM, disk full); an emergency interface that goes dark due to certificate expiry is more dangerous than having no interface at all. Additionally, OpenSSL/BoringSSL is a heavyweight dependency, fundamentally at odds with ASys's zero-external-dependency design philosophy.

Noise IK's three advantages correspond exactly to these three problems: **zero certificate dependency** (pure cryptographic primitives, no CA required), **single-file implementation** (based on Monocypher, approximately 2,000 lines of C code, fully auditable), and **1-RTT handshake** (IK mode requires the initiator to know the server's public key in advance, which pairs naturally with the Pre-Handshake Frame mechanism).

Noise IK also provides an additional protocol-level benefit: once the handshake completes, the agent's static public key serves as its identity and can directly index the Capability Map, requiring no additional identity layer.

**Forward Secrecy Note**: Noise IK session keys are derived with the participation of ephemeral keys (generated independently for each handshake); compromising the static private key **does not decrypt historical session content**. The real risk boundary is: if the server's static private key is compromised, the agent static public keys (identities) encrypted within historical handshake messages could theoretically be recovered — meaning an attacker could learn which agents connected to the node, but not what they did. Future versions plan to introduce the **Rekey mechanism** natively supported by the Noise specification, periodically rotating session keys during long-lived connections to further narrow the impact window of static key compromise.

### 5.2 Identity Model: Simpler Than SSH

ASys's identity model is intentionally simpler than SSH — no username, no password, no certificate. Only public keys.

```
Server (asyd)                        Client (Agent)
/etc/asyd/
├── id_curve25519      ← private key  ~/.asys/
├── id_curve25519.pub  ← public key   ├── id_curve25519
└── authorized_agents  ← whitelist    ├── id_curve25519.pub
                                      └── known_hosts
```

The two trust directions are fully symmetric:

**Agent trusts node**: On first connection, `asyd` sends the server public key via the Pre-Handshake Frame; the agent displays the fingerprint and waits for confirmation, then writes it to `~/.asys/known_hosts`. Subsequent connections verify automatically; a fingerprint mismatch causes rejection — identical to SSH's `known_hosts` mechanism.

**Node trusts agent**: The administrator writes the agent's public key to `/etc/asyd/authorized_agents`; after the handshake completes, `asyd` checks whether the public key is in the whitelist — if not, it returns `0x6982` and disconnects — identical to SSH's `authorized_keys` mechanism.

The whitelist supports SIGHUP hot reload: `sudo kill -HUP $(pidof asyd)` adds or revokes agent identities without affecting existing connections. **One machine, one identity** — when cloning a virtual machine, `id_curve25519` must be deleted; `asyd` will automatically generate a new key pair on first start, preventing multiple nodes from sharing a fingerprint and causing Capability Map conflicts.

### 5.3 Permission Isolation: Capability Map and Side-Channel Defense

After the Noise handshake completes and identity is confirmed, `asyd` looks up the **Capability Map** corresponding to the agent's static public key — a binary bitmap with per-instruction granularity.

The choice of bitmap over an ACL rule table has two non-obvious reasons:

**O(1) lookup**: `(bitmap >> ins) & 1` is a single machine instruction. Under large-scale malicious probing, `asyd` can reject unauthorized requests with minimal CPU consumption — no O(n) linear scan over ACL rules.

**Side-channel defense**: If permission is checked before existence, an attacker can infer "present but disabled" instructions from subtle response time differences, revealing the system's capability boundary. ASys's dispatch topology enforces **existence check before permission check** — all unauthorized operations have identical response times, eliminating the information leakage surface.

```c
// Existence check (O(1) bitmap)
if (!is_instruction_in_bitmap(ctx->cap_map, pkt->ins))
    return SW_NOT_FOUND;    // 0x6A81: physically nonexistent

// Fine-grained permission check
if (!check_permission(ctx, pkt))
    return SW_ACCESS_DENIED; // 0x6982: unauthorized, operation denied
```

The semantic distinction between `0x6A81` (physically nonexistent) and `0x6982` (unauthorized, operation denied) is critical: the former means "I violated a boundary," the latter means "the environment does not permit this" — agents trigger different self-healing logic accordingly.

### 5.4 Replay Protection: Epoch_ID Design

ASys uses a two-layer replay protection mechanism — **Epoch_ID + monotonically increasing Seq within session** — with no dependency on disk persistence.

`Epoch_ID` is the most noteworthy part of this design:

```
Epoch_ID = HMAC-BLAKE2b(recv_key, "asys-epoch-v1")[:4]
```

It is derived from the Noise IK handshake key and **never transmitted over the network** — both sides compute it independently and arrive at the same value. Each handshake produces a unique `Epoch_ID`, which is mixed into the Auth Tag computation for every instruction:

```
Auth_Tag = HMAC-BLAKE2b(recv_key, Header‖Epoch_ID‖Seq‖Payload)[:16]
```

This means that a captured instruction packet from an old session, when replayed in a new session, produces an HMAC verification failure (`0x6982`) due to the differing `Epoch_ID` — with no need to query any persistent state; old packets automatically become invalid after a server restart. Within-session replay is intercepted by the in-memory `last_seen_seq` (`0x6985`).

Auth Tag verification is required to use constant-time comparison (Monocypher `crypto_verify16()`); `memcmp()` is prohibited — the latter returns early upon finding the first mismatched byte, allowing attackers to infer the Auth Tag byte by byte through response time differences.

### 5.5 Audit Black Box

The fourth interface property derived in §1.2 — **built-in auditing** — is implemented here.

Before executing any Standard ISA or Vendor Extension instruction, an audit record must first be written:

```
[Timestamp(8B)][Agent_PubKey_Hash(4B)][INS(1B)][CLA(1B)][Seq(4B)][Param_Digest(4B)][SW(2B)]
Total: 24 bytes, fixed-length
```

The fixed-length binary format has two intentional properties: **injection-proof** (text logs can be polluted by carefully crafted parameter content; fixed-length binary is completely immune); **direct SIEM integration** (no parser needed; random access via `mmap`).

Audit logs are enforced as append-only via filesystem attributes (Linux: `chattr +a`); no agent instruction can modify already-written records, even with elevated privileges. Temporally, **write before execute**: the audit record is committed to disk before the instruction executes — even if execution fails, "what was attempted" is always recoverable.

When audit storage fails, `asyd` does not silently continue. Instead, it marks every response frame with `AUDIT_DEGRADED` — transparently exposing the degraded state to the agent, which then decides whether to proceed with high-risk instructions. Transparent failure, not silent failure.

> Note: The audit black box is a design goal; it is not yet implemented in v0.3.1 and is planned for a future release.

---

## 6. Roadmap and Outlook

### 6.1 Current Status

asyd v0.3.1 is the first public release of ASys, corresponding to protocol version v1.0. The two version numbers are managed independently: the protocol version increments only when the wire format or instruction semantics change; the software version evolves independently with each implementation iteration.

Protocol v1.0 covers the stable, implemented portion: the four Core ISA observation instructions (`SYS_CAPS` / `SYS_HELLO` / `SYS_STATUS` / `SYS_PROCS`), the first batch of Standard ISA control instructions (`PROC_THROTTLE` / `SVC_RESTART` / `TASK_QUERY`), a complete Noise IK encrypted channel, public key whitelist authentication, Epoch_ID replay protection, and the Pre-Handshake Frame key distribution mechanism.

The complete OODA loop has been validated on RHEL: the server runs a CPU hog to trigger abnormal load; a Python client sequentially calls `SYS_STATUS` to detect the anomaly, `SYS_PROCS` to identify the process, `PROC_THROTTLE` to suppress it, and `SYS_STATUS` again to confirm recovery — all instructions return `0x9000`.

Features defined in the specification but not yet implemented (per-agent fine-grained Capability Map, audit black box, chained transport, handshake first-packet deduplication) are marked as *planned* and are not within the commitments of protocol v1.0; they will be implemented in subsequent releases.

### 6.2 SDK Roadmap

The protocol itself solves the question of "how to communicate"; the SDK solves the question of "how developers can actually use it." Both are equally important.

**Python SDK** (near-term): targeted at AI agent developers, with the goal of embedding directly into mainstream agent frameworks like LangChain and AutoGen. Supports `asyncio` async I/O, automatic retry, idempotency protection, and automatic management of `~/.asys/` identity and `known_hosts` fingerprint verification.

A core SDK design principle: **agents never operate at the byte level directly**. Agents call structured interfaces (e.g., `sdk.proc_throttle(pid=1234, action="stop")`); the SDK handles parameter type validation, bounds checking, and compiles them into binary frames. LLMs are inherently insensitive to byte offsets; having agents directly assemble binary parameters is the wrong usage model. The SDK's strongly-typed validation layer is an extension of ASys's security model on the agent side.

### 6.3 Protocol Evolution

Standard ISA currently defines 9 instructions; most of the 112 slots in `0x20-0x8F` remain empty. This is intentional — long-term protocol validity matters more than early functional completeness. New instructions will be added demand-driven by real use cases, not pre-planned.

Vendor Extensions (`0xC0-0xFF`) are the core mechanism for protocol openness. Vertical domains such as databases, network devices, and cloud-native runtimes can define domain-specific instruction sets within ASys's authentication and transport framework without modifying the protocol core. Plans include establishing a Vendor_ID registration specification and a standardized process for third-party extensions.

A longer-term direction is introducing a lightweight Wasm plugin sandbox, allowing third-party vendors to extend the instruction set without modifying `asyd`'s core — contingent on defining ASys-WASI, aligning plugin capability boundaries with the Capability Map. This remains a research direction, not a commitment.

### 6.4 A Final Thought

ASys is an experiment: if you were designing a system interface for AI agents from scratch, what would it look like?

There is no single right answer. Binary frames, Noise IK, Capability Map — every choice involves tradeoffs. The design notes (`asys-design-notes.md`) record the full reasoning behind every "why not the alternative" decision. Challenges welcome.

If ASys sparks some discussion about what the interface between agents and systems should look like, the project has achieved its purpose.

---

*Maintained by the ASys project. Continuously evolving.*
