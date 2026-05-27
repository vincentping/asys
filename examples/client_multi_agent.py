#!/usr/bin/env python3
# Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
# SPDX-License-Identifier: Apache-2.0
"""
client_multi_agent.py — Multi-Agent Concurrent Session Simulator

Validates per-session lock correctness across four scenarios:
  Scenario 1: Concurrent Core ISA — multiple agents send SYS_STATUS simultaneously;
              responses must not interleave or arrive out of order
  Scenario 2: Cross-session TASK_QUERY isolation — Agent-B querying Agent-A's
              handle must receive Status=0xFF (no information leak)
  Scenario 3: Concurrent SVC_RESTART — multiple agents restart different services
              simultaneously; idempotency + independent handles per session
  Scenario 4: Disconnect resilience — Agent-C abruptly disconnects; other agents
              must remain unaffected

Usage:
  python3 client_multi_agent.py <host> [port]

  host  — node running asyd
  port  — default 7816

Prerequisites:
  - asyd running in multi-threaded mode (make asyd && sudo bin/asyd)
  - Agent public key added to /etc/asyd/authorized_agents on the server
  - asyd requires sudo (systemctl privileges)

Dependencies:
  pip install noiseprotocol cryptography
"""

import os
import socket
import struct
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac as crypto_hmac, hashes
from noise.connection import NoiseConnection, Keypair


# ── Constants ─────────────────────────────────────────────────────

ASYS_DIR    = os.path.expanduser('~/.asys')
KEY_PRIV    = os.path.join(ASYS_DIR, 'id_curve25519')
KNOWN_HOSTS = os.path.join(ASYS_DIR, 'known_hosts')

PRE_HANDSHAKE_MAGIC   = 0x41535953
PRE_HANDSHAKE_VERSION = 0x0100

DEFAULT_PORT = 7816

TASK_STATUS = {
    0x00: 'Pending',
    0x01: 'Success',
    0x02: 'Failed',
    0x03: 'Timeout',
    0xFF: 'NotFound',
}

g_pass = 0
g_fail = 0
g_lock = threading.Lock()


# ── Result helpers ─────────────────────────────────────────────────

def record(label, ok, detail=''):
    global g_pass, g_fail
    with g_lock:
        if ok:
            g_pass += 1
            print(f"  PASS  {label}")
        else:
            g_fail += 1
            tag = f"  ({detail})" if detail else ''
            print(f"  FAIL  {label}{tag}  (line CHECK)")


# ── Network helpers ────────────────────────────────────────────────

def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"Connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def load_client_key():
    if not os.path.exists(KEY_PRIV):
        print(f"Error: key not found: {KEY_PRIV}")
        print("Run: python3 tools/client/asys_keygen.py")
        sys.exit(1)
    with open(KEY_PRIV, 'rb') as f:
        key = f.read()
    if len(key) != 32:
        print(f"Error: {KEY_PRIV} corrupt (expected 32 bytes)")
        sys.exit(1)
    return key


def load_known_host(host, port):
    if not os.path.exists(KNOWN_HOSTS):
        return None
    key = f"{host}:{port}"
    with open(KNOWN_HOSTS) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] == key:
                return parts[1]
    return None


def recv_pre_handshake_frame(sock):
    data    = recv_exact(sock, 38)
    magic   = struct.unpack_from('>I', data, 0)[0]
    version = struct.unpack_from('>H', data, 4)[0]
    if magic != PRE_HANDSHAKE_MAGIC:
        raise ConnectionError(f"Bad magic 0x{magic:08X}")
    if version >> 8 != PRE_HANDSHAKE_VERSION >> 8:
        raise ConnectionError(f"Incompatible server version 0x{version:04X}")
    return data[6:38].hex()


def noise_handshake_client(sock, client_priv, server_pub):
    noise = NoiseConnection.from_name(b'Noise_IK_25519_ChaChaPoly_BLAKE2b')
    noise.set_as_initiator()
    noise.set_keypair_from_private_bytes(Keypair.STATIC, client_priv)
    noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, server_pub)
    noise.start_handshake()
    sock.sendall(noise.write_message())
    noise.read_message(recv_exact(sock, 48))
    return noise


def derive_epoch_id(noise):
    """Epoch_ID = HMAC-BLAKE2b(send_key, "asys-epoch-v1")[:4]"""
    send_key = noise.noise_protocol.cipher_state_encrypt.k
    h = crypto_hmac.HMAC(send_key, hashes.BLAKE2b(64), backend=default_backend())
    h.update(b"asys-epoch-v1")
    return h.finalize()[:4]


def connect(host, port, client_priv, server_pub_hex):
    """Connect and complete handshake. Returns (sock, noise, epoch_id, seq).
    seq is a per-connection mutable list [int] starting at 0."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)
    sock.connect((host, port))
    got_hex = recv_pre_handshake_frame(sock)
    if got_hex != server_pub_hex:
        sock.close()
        raise ConnectionError("Server key mismatch!")
    noise = noise_handshake_client(sock, client_priv, bytes.fromhex(server_pub_hex))
    epoch_id = derive_epoch_id(noise)
    return sock, noise, epoch_id, [0]   # seq counter as mutable list


# ── APDU transport ─────────────────────────────────────────────────

def compute_auth_tag(noise, epoch_id, cla, ins, p1, p2, lc, seq, payload):
    send_key  = noise.noise_protocol.cipher_state_encrypt.k
    header    = bytes([cla, ins, p1, p2, lc])
    seq_bytes = struct.pack('>I', seq)
    message   = header + epoch_id + seq_bytes + payload
    h = crypto_hmac.HMAC(send_key, hashes.BLAKE2b(64), backend=default_backend())
    h.update(message)
    return h.finalize()[:16]


def send_apdu(sock, noise, epoch_id, cla, ins, data=b''):
    lc    = len(data)
    sec   = (cla >> 2) & 0x03
    frame = bytes([cla, ins, 0x00, 0x00, lc]) + data + bytes([0x00])
    if sec != 0x00:
        seq_val  = struct.unpack('>I', data[:4])[0]
        payload  = data[4:]
        auth_tag = compute_auth_tag(noise, epoch_id, cla, ins, 0x00, 0x00, lc,
                                    seq_val, payload)
        frame   += auth_tag
    ct = noise.encrypt(frame)
    sock.sendall(struct.pack('>H', len(ct)) + ct)


def recv_apdu(sock, noise):
    clen = struct.unpack('>H', recv_exact(sock, 2))[0]
    return noise.decrypt(recv_exact(sock, clen))


# ── ISA command helpers ────────────────────────────────────────────

def cmd_sys_hello(sock, noise, epoch_id):
    """SYS_HELLO (0x01) → 18-byte response, SW=0x9000"""
    send_apdu(sock, noise, epoch_id, 0x00, 0x01)
    resp = recv_apdu(sock, noise)
    sw = struct.unpack_from('>H', resp, len(resp) - 2)[0]
    return resp, sw


def cmd_sys_status(sock, noise, epoch_id):
    """SYS_STATUS (0x02) → 23-byte response, SW=0x9000"""
    send_apdu(sock, noise, epoch_id, 0x00, 0x02)
    resp = recv_apdu(sock, noise)
    sw = struct.unpack_from('>H', resp, len(resp) - 2)[0]
    return resp, sw


def cmd_svc_restart(sock, noise, epoch_id, seq_ref, svc_name):
    """SVC_RESTART (0x22, Signed) → (handle, sw).
    seq_ref is a mutable [int] counter; incremented before each send."""
    seq_ref[0] += 1
    data = struct.pack('>I', seq_ref[0]) + svc_name.encode('ascii')
    send_apdu(sock, noise, epoch_id, 0x04, 0x22, data)
    resp = recv_apdu(sock, noise)
    sw = (resp[-2] << 8) | resp[-1]
    if sw == 0x9000 and len(resp) == 6:
        handle = struct.unpack_from('>I', resp, 0)[0]
        return handle, sw
    return None, sw


def cmd_task_query(sock, noise, epoch_id, handle):
    """TASK_QUERY (0x11, Plain) → (status, sw)"""
    data = struct.pack('>I', handle)
    send_apdu(sock, noise, epoch_id, 0x00, 0x11, data)
    resp = recv_apdu(sock, noise)
    sw = (resp[-2] << 8) | resp[-1]
    if len(resp) == 3:
        return resp[0], sw
    return 0xFF, sw


# ── Scenario 1: Concurrent Core ISA ───────────────────────────────

def _scenario1_worker(agent_id, host, port, client_priv, server_pub_hex, n_iters):
    """Each agent sends SYS_STATUS n_iters times and returns (ok, detail)."""
    try:
        sock, noise, epoch_id, _ = connect(host, port, client_priv, server_pub_hex)
    except Exception as e:
        return False, f"connect failed: {e}"

    errors = []
    try:
        for i in range(n_iters):
            resp, sw = cmd_sys_status(sock, noise, epoch_id)
            if sw != 0x9000:
                errors.append(f"iter {i}: SW=0x{sw:04X}")
            elif len(resp) != 23:
                errors.append(f"iter {i}: len={len(resp)}")
    except Exception as e:
        errors.append(f"exception: {e}")
    finally:
        sock.close()

    return (len(errors) == 0), '; '.join(errors)


def scenario1_concurrent_core_isa(host, port, client_priv, server_pub_hex):
    print("\n[Scenario 1: Concurrent Core ISA — 4 agents × 5 SYS_STATUS]")
    N_AGENTS = 4
    N_ITERS  = 5

    with ThreadPoolExecutor(max_workers=N_AGENTS) as pool:
        futures = {
            pool.submit(_scenario1_worker,
                        f"A{i+1}", host, port, client_priv, server_pub_hex, N_ITERS): i+1
            for i in range(N_AGENTS)
        }
        for fut in as_completed(futures):
            agent_num = futures[fut]
            ok, detail = fut.result()
            record(f"Agent-A{agent_num}: {N_ITERS}× SYS_STATUS all SW=0x9000", ok, detail)


# ── Scenario 2: Cross-session TASK_QUERY isolation ─────────────────

def scenario2_cross_session_isolation(host, port, client_priv, server_pub_hex):
    print("\n[Scenario 2: Cross-session TASK_QUERY isolation]")

    # Agent-B1 does SVC_RESTART "crond" and gets a handle
    try:
        sock_b1, noise_b1, epoch_b1, seq_b1 = connect(host, port, client_priv, server_pub_hex)
    except Exception as e:
        record("Agent-B1 connect", False, str(e))
        return

    handle_b1 = None
    try:
        handle_b1, sw = cmd_svc_restart(sock_b1, noise_b1, epoch_b1, seq_b1, 'crond')
        record("Agent-B1: SVC_RESTART crond → SW=0x9000", sw == 0x9000,
               f"SW=0x{sw:04X}")
    except Exception as e:
        record("Agent-B1: SVC_RESTART crond", False, str(e))
        sock_b1.close()
        return

    if handle_b1 is None:
        record("Agent-B1: obtained valid Task_Handle", False, "handle=None")
        sock_b1.close()
        return

    record("Agent-B1: obtained valid Task_Handle", handle_b1 != 0,
           f"handle=0x{handle_b1:08X}" if handle_b1 else "handle=0")

    # Agent-B2 (different TCP session) queries Agent-B1's handle → must be NotFound
    try:
        sock_b2, noise_b2, epoch_b2, _ = connect(host, port, client_priv, server_pub_hex)
    except Exception as e:
        record("Agent-B2 connect", False, str(e))
        sock_b1.close()
        return

    try:
        status, sw = cmd_task_query(sock_b2, noise_b2, epoch_b2, handle_b1)
        record("Agent-B2 querying B1's handle → Status=0xFF (no info leak)",
               status == 0xFF and sw == 0x9000,
               f"status=0x{status:02X} SW=0x{sw:04X}")
    except Exception as e:
        record("Agent-B2: TASK_QUERY cross-session", False, str(e))
    finally:
        sock_b2.close()

    # Agent-B1 queries own handle — must NOT be NotFound
    try:
        status, sw = cmd_task_query(sock_b1, noise_b1, epoch_b1, handle_b1)
        valid_own = (status in TASK_STATUS and status != 0xFF) and sw == 0x9000
        record("Agent-B1 querying own handle → Status != 0xFF",
               valid_own, f"status=0x{status:02X} SW=0x{sw:04X}")
    except Exception as e:
        record("Agent-B1: TASK_QUERY own handle", False, str(e))
    finally:
        sock_b1.close()


# ── Scenario 3: Concurrent SVC_RESTART (independent handles) ───────

def _scenario3_worker(agent_id, host, port, client_priv, server_pub_hex, svc_name):
    """Returns (handle, sw, final_status, detail_str)"""
    try:
        sock, noise, epoch_id, seq_ref = connect(host, port, client_priv, server_pub_hex)
    except Exception as e:
        return None, None, None, f"connect: {e}"
    try:
        handle, sw = cmd_svc_restart(sock, noise, epoch_id, seq_ref, svc_name)

        if sw != 0x9000 or handle is None:
            return handle, sw, None, f"SW=0x{sw:04X}"

        final_status = None
        for _ in range(30):
            time.sleep(1)
            status, qsw = cmd_task_query(sock, noise, epoch_id, handle)
            if status != 0x00:   # non-Pending → terminal
                final_status = status
                break

        return handle, sw, final_status, ''
    except Exception as e:
        return None, None, None, str(e)
    finally:
        sock.close()


def scenario3_concurrent_svc_restart(host, port, client_priv, server_pub_hex):
    print("\n[Scenario 3: Concurrent SVC_RESTART — 3 agents, 3 different services]")

    agents = [
        ('C1', 'crond'),
        ('C2', 'rsyslog'),
        ('C3', 'sshd'),
    ]

    results = {}
    with ThreadPoolExecutor(max_workers=len(agents)) as pool:
        futures = {
            pool.submit(_scenario3_worker,
                        aid, host, port, client_priv, server_pub_hex, svc): (aid, svc)
            for aid, svc in agents
        }
        for fut in as_completed(futures):
            aid, svc = futures[fut]
            handle, sw, final_status, detail = fut.result()
            results[aid] = (handle, sw, svc, final_status, detail)

    # Report SVC_RESTART results in agent order (not completion order)
    for aid, svc in agents:
        handle, sw, _, final_status, detail = results[aid]
        ok = (sw == 0x9000 and handle is not None and handle != 0)
        record(f"Agent-{aid}: SVC_RESTART {svc:<7} → SW=0x9000 + handle",
               ok, detail or f"SW=0x{sw:04X}" if not ok else '')

    # All handles must be distinct (independent per-session handles)
    handles = [results[aid][0] for aid in results
               if results[aid][0] is not None]
    all_distinct = (len(handles) == len(set(handles))) and len(handles) > 0
    record("All 3 Task_Handles are distinct", all_distinct,
           f"handles={[hex(h) for h in handles]}")

    # Report final status per agent
    for aid, svc in agents:
        _, _, _, final_status, detail = results[aid]
        if final_status is None:
            record(f"Agent-{aid}: {svc:<7} → Status=Success ✓", False,
                   detail or "no terminal status within 30s")
        else:
            status_name = TASK_STATUS.get(final_status, f"0x{final_status:02X}")
            record(f"Agent-{aid}: {svc:<7} → Status=Success ✓",
                   final_status == 0x01,
                   f"Status={status_name}" if final_status != 0x01 else '')


# ── Scenario 4: Disconnect resilience ──────────────────────────────

def scenario4_disconnect_resilience(host, port, client_priv, server_pub_hex):
    print("\n[Scenario 4: Disconnect resilience — Agent-D abruptly disconnects]")

    # Start a long-lived agent (D-stable) that sends a few commands
    try:
        sock_stable, noise_stable, epoch_stable, _ = connect(
            host, port, client_priv, server_pub_hex)
    except Exception as e:
        record("Agent-D-stable connect", False, str(e))
        return

    # Verify stable agent works before the disruptive event
    try:
        _, sw = cmd_sys_hello(sock_stable, noise_stable, epoch_stable)
        record("Agent-D-stable: SYS_HELLO before disrupt → 0x9000", sw == 0x9000)
    except Exception as e:
        record("Agent-D-stable: SYS_HELLO before disrupt", False, str(e))
        sock_stable.close()
        return

    # Disruptive agent: connect, send partial data, then hard close
    try:
        sock_bad = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_bad.settimeout(10)
        sock_bad.connect((host, port))
        recv_pre_handshake_frame(sock_bad)
        # Don't complete handshake — just drop the connection
        sock_bad.close()
        record("Agent-D-bad: abrupt disconnect (no handshake)", True)
    except Exception as e:
        record("Agent-D-bad: abrupt disconnect", False, str(e))

    # client_thread teardown is asynchronous: the server logs "disconnected"
    # and releases the slot only after handle_client returns.  Without this
    # pause, the next send on sock_stable may race with the server still
    # processing the abrupt RST from sock_bad.
    time.sleep(0.5)

    # Stable agent must still work after the disruption
    try:
        resp, sw = cmd_sys_status(sock_stable, noise_stable, epoch_stable)
        record("Agent-D-stable: SYS_STATUS after disrupt → 0x9000",
               sw == 0x9000 and len(resp) == 23,
               f"SW=0x{sw:04X} len={len(resp)}")
    except Exception as e:
        record("Agent-D-stable: SYS_STATUS after disrupt", False, str(e))
    finally:
        sock_stable.close()

    # New agent connects fine after the disruption
    try:
        sock_new, noise_new, epoch_new, _ = connect(
            host, port, client_priv, server_pub_hex)
        _, sw = cmd_sys_hello(sock_new, noise_new, epoch_new)
        record("Agent-D-new: fresh connect after disrupt → SYS_HELLO 0x9000",
               sw == 0x9000)
        sock_new.close()
    except Exception as e:
        record("Agent-D-new: fresh connect after disrupt", False, str(e))


# ── Entry point ────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args:
        print("Usage: python3 client_multi_agent.py <host> [port]")
        print()
        print("  host  — RHEL node running asyd (Phase 4 P1, multi-threaded)")
        print("  port  — default 7816")
        sys.exit(1)

    host = args[0]
    port = int(args[1]) if len(args) > 1 else DEFAULT_PORT

    print(f"=== ASys Agent Simulator — {host}:{port} ===")
    print("Validates per-session lock correctness (Phase 4 P1)")
    print()

    client_priv = load_client_key()

    server_pub_hex = load_known_host(host, port)
    if server_pub_hex is None:
        print(f"Error: {host}:{port} not in known_hosts.")
        print("Add agent pubkey to /etc/asyd/authorized_agents on the server.")
        sys.exit(1)

    try:
        scenario1_concurrent_core_isa(host, port, client_priv, server_pub_hex)
        scenario2_cross_session_isolation(host, port, client_priv, server_pub_hex)
        scenario3_concurrent_svc_restart(host, port, client_priv, server_pub_hex)
        scenario4_disconnect_resilience(host, port, client_priv, server_pub_hex)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(1)

    print()
    print("=" * 52)
    print(f"Summary: {g_pass} passed, {g_fail} failed")
    if g_fail == 0:
        print("ALL TESTS PASSED — per-session lock is correct")
    else:
        print("SOME TESTS FAILED — check output above")
    sys.exit(0 if g_fail == 0 else 1)


if __name__ == '__main__':
    main()
