#!/usr/bin/env python3
# Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
# SPDX-License-Identifier: Apache-2.0
"""
client_svc_restart.py — SVC_RESTART + TASK_QUERY E2E Test Client

验证 TC-E2E-001 (正常路径) 和 TC-E2E-002 (幂等轮询):
  1. 连接 asyd，Noise IK 握手
  2. 发送 SVC_RESTART("<service>")  →  Task_Handle + SW=0x9000
  3. 轮询 TASK_QUERY(handle)  →  直到 Status != Pending（最多 30 秒）
  4. 打印最终 Status

用法:
  python3 client_svc_restart.py <host> [port] [service]

  service 默认值: crond（RHEL 上无害的服务，restart 很快完成）

前提:
  - asyd 在目标节点运行 (make asyd && sudo bin/asyd)
  - 客户端密钥已注册:
      python3 tools/client/asys_keygen.py
      python3 tools/server/generate_token.py   # 在 RHEL 端
      python3 examples/client_core_isa.py <host>   # 完成 TOFU

Dependencies:
  pip install noiseprotocol cryptography
"""

import os
import socket
import struct
import sys
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac as crypto_hmac, hashes
from noise.connection import NoiseConnection, Keypair


# ── Constants ─────────────────────────────────────────────────────

ASYS_DIR    = os.path.expanduser('~/.asys')
KEY_PRIV    = os.path.join(ASYS_DIR, 'id_curve25519')
KNOWN_HOSTS = os.path.join(ASYS_DIR, 'known_hosts')

PRE_HANDSHAKE_MAGIC   = 0x41535953
PRE_HANDSHAKE_VERSION = 0x0100

DEFAULT_SERVICE = 'crond'   # harmless RHEL service; restart completes quickly
DEFAULT_PORT    = 7816

TASK_STATUS = {
    0x00: 'Pending',
    0x01: 'Success ✓',
    0x02: 'Failed  ✗',
    0x03: 'Timeout ⏱',
    0x04: 'Cancelled',
    0xFF: 'Not Found',
}


# ── Shared helpers ────────────────────────────────────────────────

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
        print(f"Error: {KEY_PRIV} corrupt (expected 32 bytes, got {len(key)})")
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
        print(f"Error: bad magic 0x{magic:08X}")
        sys.exit(1)
    if version >> 8 != PRE_HANDSHAKE_VERSION >> 8:
        print(f"Error: incompatible server version 0x{version:04X}")
        sys.exit(1)
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
    """Epoch_ID = HMAC-BLAKE2b(send_key, "asys-epoch-v1")[:4]
    send_key matches asyd's recv_key; both sides derive the same 4 bytes."""
    send_key = noise.noise_protocol.cipher_state_encrypt.k
    h = crypto_hmac.HMAC(send_key, hashes.BLAKE2b(64), backend=default_backend())
    h.update(b"asys-epoch-v1")
    return h.finalize()[:4]

def connect_and_handshake(host, port, client_priv):
    """Connect, verify known_hosts, Noise IK. Returns (sock, noise, epoch_id)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))
    server_pub_hex = recv_pre_handshake_frame(sock)
    stored = load_known_host(host, port)
    if stored is None:
        print(f"Error: {host}:{port} not in known_hosts.")
        print(f"Run client_core_isa.py first to complete TOFU registration.")
        sys.exit(1)
    if stored != server_pub_hex:
        print("ERROR: server key changed!")
        sys.exit(1)
    noise = noise_handshake_client(sock, client_priv, bytes.fromhex(server_pub_hex))
    epoch_id = derive_epoch_id(noise)
    return sock, noise, epoch_id


# ── Auth Tag ──────────────────────────────────────────────────────

def compute_auth_tag(noise, epoch_id, cla, ins, p1, p2, lc, seq, payload):
    """Auth_Tag = HMAC-BLAKE2b(send_key, Header||Epoch_ID||Seq||Payload)[:16]"""
    send_key  = noise.noise_protocol.cipher_state_encrypt.k
    header    = bytes([cla, ins, p1, p2, lc])
    seq_bytes = struct.pack('>I', seq)
    message   = header + epoch_id + seq_bytes + payload
    h = crypto_hmac.HMAC(send_key, hashes.BLAKE2b(64), backend=default_backend())
    h.update(message)
    return h.finalize()[:16]


# ── APDU transport ────────────────────────────────────────────────

def send_apdu(sock, noise, epoch_id, cla, ins, data=b''):
    """Send APDU frame. For Signed frames (CLA bits[3:2] != 00), data must be
    [Seq(4B)][Payload]; Auth Tag is computed and appended after Le."""
    lc  = len(data)
    sec = (cla >> 2) & 0x03
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


# ── Phase 3 instructions ──────────────────────────────────────────

def cmd_svc_restart(sock, noise, epoch_id, svc_name, seq):
    """
    SVC_RESTART (0x22): CLA=0x04 (Signed), INS=0x22
    Data = [Seq(4B BE)][SvcName]
    Success response  = [Task_Handle(4B BE)][SW=0x9000]  (6 bytes)
    Returns (handle, sw).
    """
    data = struct.pack('>I', seq) + svc_name.encode('ascii')
    send_apdu(sock, noise, epoch_id, 0x04, 0x22, data)
    resp = recv_apdu(sock, noise)

    sw = (resp[-2] << 8) | resp[-1]
    if sw != 0x9000:
        return None, sw

    if len(resp) != 6:
        print(f"  Warning: unexpected response length {len(resp)} (expected 6)")
        return None, sw

    handle = struct.unpack_from('>I', resp, 0)[0]
    return handle, sw


def cmd_task_query(sock, noise, epoch_id, handle: int):
    """
    TASK_QUERY (0x11): CLA=0x00 (Plain), INS=0x11
    Data = [Task_Handle(4B BE)]
    Response = [Status(1B)][SW=0x9000]  (3 bytes)
    epoch_id is accepted for interface consistency but unused here —
    send_apdu() skips Auth Tag computation for Plain frames (sec=0x00).
    """
    data = struct.pack('>I', handle)
    send_apdu(sock, noise, epoch_id, 0x00, 0x11, data)
    resp = recv_apdu(sock, noise)

    sw = (resp[-2] << 8) | resp[-1]
    if len(resp) != 3:
        print(f"  Warning: unexpected response length {len(resp)} (expected 3)")
        return 0xFF, sw

    return resp[0], sw


# ── Test runner ───────────────────────────────────────────────────

def run_e2e(host, port, svc_name):
    print(f"ASys Phase 3 E2E Test  —  {host}:{port}")
    print(f"Service: {svc_name}")
    print("=" * 52)

    client_priv = load_client_key()
    sock, noise, epoch_id = connect_and_handshake(host, port, client_priv)
    print("Handshake OK\n")

    seq = 0   # per-connection counter; starts at 1 on first use

    try:
        # ── Step 1: SVC_RESTART ───────────────────────────────
        print(f"► SVC_RESTART(\"{svc_name}\")")
        t0 = time.time()
        seq += 1
        try:
            handle, sw = cmd_svc_restart(sock, noise, epoch_id, svc_name, seq)
        except Exception as e:
            print(f"  ERROR: {type(e).__name__}: {e}")
            return False

        rtt = (time.time() - t0) * 1000

        if sw != 0x9000:
            sw_desc = {
                0x6982: "Access Denied (Auth Tag invalid or not registered)",
                0x6985: "Replay Detected",
                0x6700: "Wrong Length",
                0x6A80: "Invalid service name",
                0x6400: "Task pool full (retry later)",
                0x6F00: "fork() failed",
            }.get(sw, "unknown error")
            print(f"  FAILED  SW=0x{sw:04X}  {sw_desc}")
            return False

        print(f"  SW:           0x{sw:04X}  OK")
        print(f"  Task_Handle:  0x{handle:08X}")
        print(f"  RTT:          {rtt:.1f} ms")

        # ── Step 2: TASK_QUERY polling loop ───────────────────
        print(f"\n► TASK_QUERY polling (max 30s) ...")
        final_status = None
        for attempt in range(30):
            time.sleep(1)
            status, sw = cmd_task_query(sock, noise, epoch_id, handle)
            status_name = TASK_STATUS.get(status, f"0x{status:02X}")
            print(f"  [{attempt+1:2d}s]  Status = {status_name}")
            if status != 0x00:   # not Pending
                final_status = status
                break
        else:
            print("  Polling timed out after 30 iterations")
            return False

    finally:
        sock.close()

    print()
    success = (final_status == 0x01)
    print("=" * 52)
    if success:
        print(f"PASS  SVC_RESTART(\"{svc_name}\") completed with Status=Success")
    else:
        status_name = TASK_STATUS.get(final_status, f"0x{final_status:02X}")
        print(f"FAIL  Final status: {status_name}")
        if final_status == 0x02:
            print(f"      systemctl returned non-zero — is \"{svc_name}\" a valid service?")
        elif final_status == 0x03:
            print(f"      Task timed out (>30s) — systemctl did not exit in time")
    return success


# ── Entry point ───────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args:
        print("Usage: python3 client_svc_restart.py <host> [port] [service]")
        print()
        print("  host     — RHEL node running asyd")
        print("  port     — default 7816")
        print("  service  — service name without .service suffix (default: crond)")
        print()
        print("Examples:")
        print("  python3 client_svc_restart.py 192.168.56.10")
        print("  python3 client_svc_restart.py 192.168.56.10 7816 rsyslog")
        sys.exit(1)

    host    = args[0]
    port    = int(args[1]) if len(args) > 1 else DEFAULT_PORT
    service = args[2]      if len(args) > 2 else DEFAULT_SERVICE

    try:
        ok = run_e2e(host, port, service)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(1)
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
