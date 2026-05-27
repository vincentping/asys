#!/usr/bin/env python3
# Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
# SPDX-License-Identifier: Apache-2.0
"""
client_proc_throttle.py — Interactive remote PROC_THROTTLE client

Connects to asyd, shows current CPU status and top processes,
then lets you select a PID to throttle.

Usage:
    python3 client_proc_throttle.py <host> [port]

Prerequisites:
    - Generate client key: python3 tools/client/asys_keygen.py
    - Agent registered with asyd (run client_core_isa.py once against the host)

Dependencies:
    pip install noiseprotocol cryptography
"""

import os
import signal
import socket
import struct
import sys
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hmac as crypto_hmac, hashes
from noise.connection import NoiseConnection, Keypair


# ── Paths ──────────────────────────────────────────────────────────

ASYS_DIR    = os.path.expanduser('~/.asys')
KEY_PRIV    = os.path.join(ASYS_DIR, 'id_curve25519')
KNOWN_HOSTS = os.path.join(ASYS_DIR, 'known_hosts')

PRE_HANDSHAKE_MAGIC   = 0x41535953
PRE_HANDSHAKE_VERSION = 0x0100


# ── Client key ─────────────────────────────────────────────────────

def load_client_key() -> bytes:
    if not os.path.exists(KEY_PRIV):
        print(f"Error: key not found: {KEY_PRIV}")
        print("Run: python3 tools/client/asys_keygen.py")
        sys.exit(1)
    with open(KEY_PRIV, 'rb') as f:
        key = f.read()
    if len(key) != 32:
        print(f"Error: {KEY_PRIV} corrupt")
        sys.exit(1)
    return key


# ── known_hosts ────────────────────────────────────────────────────

def load_known_host(host, port):
    if not os.path.exists(KNOWN_HOSTS):
        return None
    target = f"{host}:{port}"
    with open(KNOWN_HOSTS) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0] == target:
                return parts[1]
    return None

def write_known_host(host, port, pub_hex):
    os.makedirs(ASYS_DIR, exist_ok=True)
    with open(KNOWN_HOSTS, 'a') as f:
        f.write(f"{host}:{port}  {pub_hex}\n")


# ── Low-level helpers ──────────────────────────────────────────────

def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"Connection closed ({len(buf)}/{n} bytes)")
        buf += chunk
    return buf

def recv_pre_handshake_frame(sock) -> str:
    data    = recv_exact(sock, 38)
    magic   = struct.unpack_from('>I', data, 0)[0]
    version = struct.unpack_from('>H', data, 4)[0]
    if magic != PRE_HANDSHAKE_MAGIC:
        print(f"Error: not an ASys server (magic 0x{magic:08X})")
        sys.exit(1)
    if version >> 8 != PRE_HANDSHAKE_VERSION >> 8:
        print(f"Error: incompatible server version 0x{version:04X}")
        sys.exit(1)
    return data[6:38].hex()

def noise_handshake(sock, client_priv, server_pub):
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

def connect(host, port, client_priv):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    server_pub_hex = recv_pre_handshake_frame(sock)
    stored = load_known_host(host, port)

    if stored is None:
        print(f"WARNING: {host}:{port} not in known_hosts.")
        print(f"  Fingerprint: {server_pub_hex}")
        ans = input("Continue? (yes/no): ").strip().lower()
        if ans not in ('yes', 'y'):
            sys.exit(1)
        write_known_host(host, port, server_pub_hex)
    elif stored != server_pub_hex:
        print("ERROR: Server key changed — aborting.")
        sys.exit(1)

    noise = noise_handshake(sock, client_priv, bytes.fromhex(server_pub_hex))
    epoch_id = derive_epoch_id(noise)
    return sock, noise, epoch_id


# ── APDU send / recv ───────────────────────────────────────────────

_seq = 0
_epoch_id = None

def _compute_auth_tag(noise, epoch_id, cla, ins, p1, p2, lc, seq, payload):
    send_key  = noise.noise_protocol.cipher_state_encrypt.k
    header    = bytes([cla, ins, p1, p2, lc])
    seq_bytes = struct.pack('>I', seq)
    message   = header + epoch_id + seq_bytes + payload
    h = crypto_hmac.HMAC(send_key, hashes.BLAKE2b(64), backend=default_backend())
    h.update(message)
    return h.finalize()[:16]

def send_apdu(sock, noise, ins, data=b'', p1=0x00, p2=0x00, cla=0x00):
    lc = len(data)
    plaintext = bytes([cla, ins, p1, p2, lc]) + data + b'\x00'
    ct = noise.encrypt(plaintext)
    sock.sendall(struct.pack('>H', len(ct)) + ct)

def send_apdu_signed(sock, noise, ins, payload=b'', p1=0x00, p2=0x00):
    global _seq, _epoch_id
    _seq += 1
    data = struct.pack('>I', _seq) + payload
    lc   = len(data)
    auth_tag = _compute_auth_tag(noise, _epoch_id, 0x04, ins, p1, p2, lc, _seq, payload)
    plaintext = bytes([0x04, ins, p1, p2, lc]) + data + b'\x00' + auth_tag
    ct = noise.encrypt(plaintext)
    sock.sendall(struct.pack('>H', len(ct)) + ct)

def recv_apdu(sock, noise) -> bytes:
    clen = struct.unpack('>H', recv_exact(sock, 2))[0]
    return noise.decrypt(recv_exact(sock, clen))

def sw(resp) -> int:
    return (resp[-2] << 8) | resp[-1]


# ── ISA helpers ────────────────────────────────────────────────────

def get_status(sock, noise):
    """Returns (cpu_pct, load1, rpi)."""
    send_apdu(sock, noise, 0x02)
    resp = recv_apdu(sock, noise)
    return resp[2], resp[0] / 10.0, resp[16]

def get_procs(sock, noise):
    """Returns list of (pid, cpu_x100, mem_pct) for non-empty slots."""
    send_apdu(sock, noise, 0x03)
    resp = recv_apdu(sock, noise)
    procs = []
    for i in range(5):
        off = 2 + i * 8
        pid      = struct.unpack_from('>I', resp, off)[0]
        cpu_x100 = struct.unpack_from('>H', resp, off + 4)[0]
        mem_pct  = resp[off + 6]
        if pid != 0:
            procs.append((pid, cpu_x100, mem_pct))
    return procs

def proc_stop(sock, noise, pid: int) -> int:
    payload = struct.pack('>I', pid)
    send_apdu_signed(sock, noise, 0x20, payload=payload, p1=0x00)
    return sw(recv_apdu(sock, noise))

def proc_cont(sock, noise, pid: int) -> int:
    payload = struct.pack('>I', pid)
    send_apdu_signed(sock, noise, 0x20, payload=payload, p1=0x01)
    return sw(recv_apdu(sock, noise))


# ── Signal handler state ───────────────────────────────────────────

_stopped_pid  = None   # PID currently under SIGSTOP, or None
_signal_sock  = None
_signal_noise = None

def _on_signal(sig, frame):
    if _stopped_pid is None:
        sys.exit(0)
    try:
        ans = input(f"\n  Restore PID {_stopped_pid}? (yes/no) [no]: ").strip().lower()
    except EOFError:
        ans = ''
    if ans in ('yes', 'y') and _signal_sock and _signal_noise:
        rc = proc_cont(_signal_sock, _signal_noise, _stopped_pid)
        print(f"  PROC_THROTTLE CONT  PID={_stopped_pid}  SW=0x{rc:04X}  "
              f"{'OK' if rc == 0x9000 else 'ERROR'}", flush=True)
    else:
        print(f"  PID {_stopped_pid} left paused.", flush=True)
    sys.exit(0)


# ── Main ───────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args:
        print("Usage: python3 client_proc_throttle.py <host> [port]")
        sys.exit(1)

    host = args[0]
    port = int(args[1]) if len(args) > 1 else 7816

    global _signal_sock, _signal_noise
    client_priv = load_client_key()

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT,  _on_signal)

    print(f"\nASys Throttle Client  —  {host}:{port}")
    print("=" * 52)

    global _epoch_id
    sock, noise, _epoch_id = connect(host, port, client_priv)
    _signal_sock  = sock
    _signal_noise = noise
    print("Handshake OK\n")

    try:
        # ── Observe ────────────────────────────────────────
        cpu, load1, rpi = get_status(sock, noise)
        procs = get_procs(sock, noise)

        print(f"  CPU={cpu}%  load1m={load1:.1f}  RPI={rpi}/100")
        print()
        print(f"  {'#':<3}  {'PID':<8}  {'CPU%':>6}  {'MEM%':>5}")
        print(f"  {'-'*3}  {'-'*8}  {'-'*6}  {'-'*5}")
        for idx, (pid, cx, mp) in enumerate(procs):
            print(f"  {idx+1:<3}  {pid:<8}  {cx/100:>5.2f}%  {mp:>4}%")

        if not procs:
            print("  (no processes returned)")
            return

        # ── Select PID ─────────────────────────────────────
        print(flush=True)
        raw = input("Select # or PID to throttle (blank to cancel): ").strip()
        if not raw:
            print("Cancelled.")
            return

        try:
            val = int(raw)
        except ValueError:
            print(f"Not a number: {raw!r}")
            return

        pid_list = [p[0] for p in procs]
        if 1 <= val <= len(procs):
            target_pid = pid_list[val - 1]
            print(f"  Selected #{val} → PID {target_pid}", flush=True)
        elif val in pid_list:
            target_pid = val
            print(f"  Selected PID {target_pid}", flush=True)
        else:
            print(f"  '{val}' is not a valid index (1-{len(procs)}) or listed PID.")
            return

        # ── Throttle ───────────────────────────────────────
        global _stopped_pid
        print(f"\n  PROC_THROTTLE STOP  PID={target_pid} ...", flush=True)
        rc = proc_stop(sock, noise, target_pid)
        print(f"  SW=0x{rc:04X}  {'OK' if rc == 0x9000 else 'ERROR'}", flush=True)
        if rc != 0x9000:
            return
        _stopped_pid = target_pid

        # ── Verify ─────────────────────────────────────────
        print("  Waiting 2 s for CPU to settle...", flush=True)
        time.sleep(2)
        cpu2, _, _ = get_status(sock, noise)
        delta = cpu - cpu2
        print(f"  CPU={cpu2}%  (was {cpu}%,  Δ={delta:+}%)", flush=True)

        # ── Restore ────────────────────────────────────────
        print(f"\n  PID {target_pid} paused.  Press Ctrl+C to restore or exit.", flush=True)
        while True:
            time.sleep(1)

    finally:
        sock.close()

    print("\n" + "=" * 52)


if __name__ == '__main__':
    main()
