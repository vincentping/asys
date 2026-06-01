#!/usr/bin/env python3
# Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
# SPDX-License-Identifier: Apache-2.0
"""
client_core_isa.py — ASys Integration Test Client (Noise IK)

Connects to asyd, handles server identity verification via known_hosts,
then runs the Core ISA test suite.

Usage:
    Standard:  python3 client_core_isa.py <host> [port]
    Legacy:    python3 client_core_isa.py <server_pub_hex> <host> [port]

    Standard mode: asyd sends a Pre-Handshake Frame containing its public key.
                   First connection prompts for fingerprint confirmation (like SSH).
    Legacy mode:   64-char hex pubkey provided on command line (skips confirmation
                   prompt; still reads Pre-Handshake Frame and compares).

Prerequisites:
    1. Run tools/client/asys_keygen.py to generate ~/.asys/id_curve25519
    2. Admin adds agent pubkey to /etc/asyd/authorized_agents on the server:
         cat ~/.asys/id_curve25519.pub | ssh user@host "cat >> /etc/asyd/authorized_agents"

Dependencies:
    pip install noiseprotocol cryptography

~/.asys/ layout:
    id_curve25519       private key, 32 bytes raw (0600)
    id_curve25519.pub   public key, 64-char hex (0644)
    known_hosts         trusted server fingerprints
"""

import os
import socket
import struct
import sys
import time

from noise.connection import NoiseConnection, Keypair


# ── Paths ─────────────────────────────────────────────────────────

ASYS_DIR    = os.path.expanduser('~/.asys')
KEY_PRIV    = os.path.join(ASYS_DIR, 'id_curve25519')
KNOWN_HOSTS = os.path.join(ASYS_DIR, 'known_hosts')

PRE_HANDSHAKE_MAGIC   = 0x41535953   # "ASYS"
PRE_HANDSHAKE_VERSION = 0x0100       # v1.0


# ── Client key ────────────────────────────────────────────────────

def load_client_key() -> bytes:
    """Load private key from ~/.asys/id_curve25519. Exit if not found."""
    if not os.path.exists(KEY_PRIV):
        print(f"Error: client key not found: {KEY_PRIV}")
        print(f"Generate a keypair first:  python3 tools/client/asys_keygen.py")
        sys.exit(1)
    with open(KEY_PRIV, 'rb') as f:
        key = f.read()
    if len(key) != 32:
        print(f"Error: {KEY_PRIV} corrupt (expected 32 bytes, got {len(key)})")
        sys.exit(1)
    return key


# ── known_hosts ───────────────────────────────────────────────────

def _host_key(host, port):
    return f"{host}:{port}"

def load_known_host(host, port):
    """Return stored server pubkey hex for host:port, or None."""
    if not os.path.exists(KNOWN_HOSTS):
        return None
    key = _host_key(host, port)
    with open(KNOWN_HOSTS) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] == key:
                return parts[1]
    return None

def write_known_host(host, port, pub_hex):
    os.makedirs(ASYS_DIR, exist_ok=True)
    with open(KNOWN_HOSTS, 'a') as f:
        f.write(f"{_host_key(host, port)}  {pub_hex}\n")

def warn_host_changed(host, port, stored, received):
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
    print("@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!              @")
    print("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@")
    print(f"The server key for '{host}:{port}' has changed!")
    print(f"  known_hosts: {stored[:32]}...")
    print(f"  received:    {received[:32]}...")
    print(f"Remove the offending key from {KNOWN_HOSTS} to proceed.")
    sys.exit(1)


# ── Low-level helpers ─────────────────────────────────────────────

def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"Connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


# ── Pre-Handshake Frame ───────────────────────────────────────────

def recv_pre_handshake_frame(sock) -> str:
    """Receive 38-byte Pre-Handshake Frame. Returns server pubkey hex."""
    data    = recv_exact(sock, 38)
    magic   = struct.unpack_from('>I', data, 0)[0]
    version = struct.unpack_from('>H', data, 4)[0]
    pub     = data[6:38]

    if magic != PRE_HANDSHAKE_MAGIC:
        print(f"Error: not an ASys server (bad magic: 0x{magic:08X})")
        sock.close()
        sys.exit(1)
    if version >> 8 != PRE_HANDSHAKE_VERSION >> 8:
        print(f"Error: incompatible server version 0x{version:04X} "
              f"(client supports 0x{PRE_HANDSHAKE_VERSION:04X})")
        sock.close()
        sys.exit(1)

    return pub.hex()


# ── Connect + handshake ───────────────────────────────────────────

def connect_and_handshake(host, port, client_priv, expected_pub_hex=None):
    """
    Open connection, receive Pre-Handshake Frame, check known_hosts,
    then do Noise IK handshake.

    expected_pub_hex: if provided (legacy mode), compare with PHF instead
                      of prompting; auto-write known_hosts if not present.

    Returns (sock, noise).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    print(f"Connected to {host}:{port}")
    sock.sendall(struct.pack('>I', PRE_HANDSHAKE_MAGIC))

    server_pub_hex = recv_pre_handshake_frame(sock)

    stored = load_known_host(host, port)

    if expected_pub_hex is not None:
        # Legacy mode: compare PHF with provided hex
        if server_pub_hex != expected_pub_hex:
            print(f"Error: server pubkey mismatch!")
            print(f"  provided:    {expected_pub_hex[:32]}...")
            print(f"  PHF received:{server_pub_hex[:32]}...")
            sock.close()
            sys.exit(1)
        if stored is None:
            write_known_host(host, port, server_pub_hex)
            print(f"Added to known hosts: {_host_key(host, port)}")
        elif stored != server_pub_hex:
            warn_host_changed(host, port, stored, server_pub_hex)
    else:
        # Standard mode: known_hosts check
        if stored is None:
            print(f"The authenticity of host '{host}:{port}' can't be established.")
            print(f"Server public key fingerprint:")
            print(f"  {server_pub_hex}")
            ans = input("Are you sure you want to continue connecting (yes/no)? ").strip().lower()
            if ans not in ('yes', 'y'):
                print("Connection aborted.")
                sock.close()
                sys.exit(1)
            write_known_host(host, port, server_pub_hex)
            print(f"Warning: Permanently added '{_host_key(host, port)}' to known hosts.")
        elif stored != server_pub_hex:
            warn_host_changed(host, port, stored, server_pub_hex)
        # else: match — silent continue

    server_pub = bytes.fromhex(server_pub_hex)
    noise = noise_handshake_client(sock, client_priv, server_pub)
    print("Handshake OK")
    return sock, noise


# ── Noise IK handshake ────────────────────────────────────────────

def noise_handshake_client(sock, client_priv: bytes, server_pub: bytes):
    noise = NoiseConnection.from_name(b'Noise_IK_25519_ChaChaPoly_BLAKE2b')
    noise.set_as_initiator()
    noise.set_keypair_from_private_bytes(Keypair.STATIC, client_priv)
    noise.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, server_pub)
    noise.start_handshake()

    msg1 = noise.write_message()
    sock.sendall(msg1)

    msg2 = recv_exact(sock, 48)
    try:
        noise.read_message(msg2)
    except Exception as e:
        raise ConnectionError(f"Handshake msg2 verification failed: {e}")

    return noise


# ── Encrypted APDU send / recv ────────────────────────────────────

def send_apdu(sock, noise, ins, data=b'', le=0x00):
    lc = len(data)
    if lc > 255:
        raise ValueError(f"send_apdu: data too long ({lc} bytes, max 255)")
    plaintext = bytes([0x00, ins, 0x00, 0x00, lc]) + data + bytes([le])
    ciphertext = noise.encrypt(plaintext)
    prefix = struct.pack('>H', len(ciphertext))
    sock.sendall(prefix + ciphertext)

def recv_apdu(sock, noise) -> bytes:
    prefix = recv_exact(sock, 2)
    clen = struct.unpack('>H', prefix)[0]
    ciphertext = recv_exact(sock, clen)
    return noise.decrypt(ciphertext)

def check_sw(resp):
    sw = (resp[-2] << 8) | resp[-1]
    tag = "OK" if sw == 0x9000 else "ERROR"
    print(f"  SW:          0x{sw:04X}  {tag}")
    return sw

SW_MESSAGES = {
    0x6982: "Access denied — agent pubkey not in /etc/asyd/authorized_agents",
    0x6985: "Replay detected — sequence number already seen",
    0x6D00: "Instruction not supported",
    0x6E00: "CLA version error",
    0x6700: "Wrong length",
    0x6A80: "Wrong data",
    0x6400: "Blocked — task pool full",
}

class AsysError(Exception):
    def __init__(self, sw):
        self.sw = sw
        desc = SW_MESSAGES.get(sw, "server error")
        super().__init__(f"SW=0x{sw:04X} — {desc}")

def recv_response(sock, noise) -> bytes:
    """recv_apdu + raise AsysError on any non-0x9000 SW response."""
    resp = recv_apdu(sock, noise)
    if len(resp) < 2:
        raise ConnectionError(f"Response too short: {len(resp)} bytes")
    sw = (resp[-2] << 8) | resp[-1]
    if sw != 0x9000:
        raise AsysError(sw)
    return resp


# ── Response parsers ──────────────────────────────────────────────

ARCH_CODES = {0x0001: 'x86_64', 0x0002: 'aarch64', 0x0003: 'riscv64',
              0xFFFF: 'unknown'}
FS_CODES   = {0x0001: 'ext4',   0x0002: 'xfs',     0x0003: 'btrfs',
              0x0004: 'tmpfs',  0x0005: 'nfs',      0xFFFF: 'unknown'}
RPI_TYPES  = {0x01: 'NATIVE_KERNEL (PSI)', 0x02: 'USER_SIMULATED',
              0xFF: 'NOT_AVAILABLE'}
PROC_FLAGS = [(0x01, 'Zombie'), (0x02, 'Unresponsive'), (0x04, 'Privileged')]

def parse_sys_caps(resp):
    print("\n── SYS_CAPS (0x00) ─────────────────────────────────")
    if len(resp) < 36:
        print(f"  Error: truncated response ({len(resp)} bytes, expected 36)")
        return
    core_bm   = struct.unpack_from('>I', resp,  0)[0]
    ext_bm    = struct.unpack_from('>I', resp,  4)[0]
    proto_ver = struct.unpack_from('>H', resp,  8)[0]
    kern_hash = resp[10:14].hex()
    ncpus     = struct.unpack_from('>H', resp, 14)[0]
    arch_code = struct.unpack_from('>H', resp, 16)[0]
    ram_mb    = struct.unpack_from('>I', resp, 18)[0]
    swap_mb   = struct.unpack_from('>I', resp, 22)[0]
    root_mb   = struct.unpack_from('>I', resp, 26)[0]
    fs_code   = struct.unpack_from('>H', resp, 30)[0]
    rpi_type  = resp[32]
    active = [f"0x{i:02X}" for i in range(32) if (core_bm >> i) & 1]
    print(f"  Core bitmap:      0x{core_bm:08X}  active={active}")
    print(f"  Ext  bitmap:      0x{ext_bm:08X}")
    print(f"  Protocol:         v{proto_ver >> 8}.{proto_ver & 0xFF}")
    print(f"  Kernel hash:      0x{kern_hash}")
    print(f"  CPUs:             {ncpus}  arch={ARCH_CODES.get(arch_code, f'0x{arch_code:04X}')}")
    print(f"  RAM:              {ram_mb} MB   swap={swap_mb} MB")
    print(f"  Root partition:   {root_mb} MB   fs={FS_CODES.get(fs_code, f'0x{fs_code:04X}')}")
    print(f"  RPI type:         {RPI_TYPES.get(rpi_type, f'0x{rpi_type:02X}')}")
    check_sw(resp)

def parse_sys_hello(resp, rtt_ms):
    print("\n── SYS_HELLO (0x01) ────────────────────────────────")
    if len(resp) < 18:
        print(f"  Error: truncated response ({len(resp)} bytes, expected 18)")
        return
    magic    = resp[0:4].decode('ascii', errors='replace')
    node_uid = struct.unpack_from('>I', resp, 4)[0]
    ts_ns    = struct.unpack_from('>Q', resp, 8)[0]
    ts_s     = ts_ns / 1e9
    print(f"  Magic:            {magic!r}")
    print(f"  Node UID:         0x{node_uid:08X}")
    print(f"  Server timestamp: {ts_s:.3f} s  ({ts_ns} ns)")
    print(f"  RTT:              {rtt_ms:.2f} ms")
    check_sw(resp)

def parse_sys_status(resp, rtt_ms):
    print("\n── SYS_STATUS (0x02) ───────────────────────────────")
    if len(resp) < 23:
        print(f"  Error: truncated response ({len(resp)} bytes, expected 23)")
        return
    load1_x10    = resp[0]
    load5_x10    = resp[1]
    cpu_pct      = resp[2]
    mem_avail_mb = struct.unpack_from('>I', resp,  3)[0]
    root_pct     = resp[7]
    iowait_ms    = struct.unpack_from('>I', resp,  8)[0]
    in_mbps      = struct.unpack_from('>H', resp, 12)[0]
    out_mbps     = struct.unpack_from('>H', resp, 14)[0]
    rpi          = resp[16]
    if rpi <= 0x64:
        rpi_str = f"{rpi}/100"
    elif rpi == 0xFF:
        rpi_str = "NOT_SUPPORTED"
    else:
        rpi_str = f"RESERVED(0x{rpi:02X})"
    print(f"  Load avg:         1m={load1_x10/10:.1f}  5m={load5_x10/10:.1f}")
    print(f"  CPU usage:        {cpu_pct}%")
    print(f"  Mem available:    {mem_avail_mb} MB")
    print(f"  Root disk:        {root_pct}% used   IO wait={iowait_ms} ms")
    print(f"  Network:          in={in_mbps} Mbps   out={out_mbps} Mbps")
    print(f"  RPI:              {rpi_str}")
    print(f"  RTT:              {rtt_ms:.2f} ms")
    check_sw(resp)

def parse_sys_procs(resp, rtt_ms):
    print("\n── SYS_PROCS (0x03) ────────────────────────────────")
    if len(resp) < 44:
        print(f"  Error: truncated response ({len(resp)} bytes, expected 44)")
        return
    total_procs = struct.unpack_from('>H', resp, 0)[0]
    print(f"  Total processes:  {total_procs}")
    print(f"  Top 5 by CPU (lifetime share):")
    for i in range(5):
        off      = 2 + i * 8
        pid      = struct.unpack_from('>I', resp, off)[0]
        cpu_x100 = struct.unpack_from('>H', resp, off + 4)[0]
        mem_pct  = resp[off + 6]
        flags    = resp[off + 7]
        if pid == 0:
            print(f"    [{i}] (empty slot)")
            continue
        cpu_str  = f"{cpu_x100 / 100:.2f}%"
        flag_str = '+'.join(name for bit, name in PROC_FLAGS if flags & bit) or '-'
        print(f"    [{i}] PID={pid:<6}  CPU={cpu_str:>8}  MEM={mem_pct:>3}%  flags={flag_str}")
    print(f"  RTT:              {rtt_ms:.2f} ms")
    check_sw(resp)


# ── Cache timing test ─────────────────────────────────────────────

def cache_timing_test(sock, noise, rounds=6, interval_s=0.2):
    print("\n── Cache Timing Test ───────────────────────────────")
    print(f"   {rounds} rounds, {interval_s*1000:.0f}ms interval")
    print(f"   {'#':<4}  {'SYS_STATUS':>12}  {'SYS_PROCS':>12}")
    print(f"   {'─'*4}  {'─'*12}  {'─'*12}")
    for i in range(rounds):
        t0 = time.time()
        send_apdu(sock, noise, 0x02)
        recv_response(sock, noise)
        rtt_status = (time.time() - t0) * 1000

        t0 = time.time()
        send_apdu(sock, noise, 0x03)
        recv_response(sock, noise)
        rtt_procs = (time.time() - t0) * 1000

        print(f"   {i:<4}  {rtt_status:>10.2f}ms  {rtt_procs:>10.2f}ms")
        if i < rounds - 1:
            time.sleep(interval_s)
    print()


# ── Core ISA test suite ───────────────────────────────────────────

def run_core_isa(sock, noise):
    """Send SYS_CAPS → SYS_HELLO → SYS_STATUS → SYS_PROCS → cache timing."""
    send_apdu(sock, noise, 0x00)
    parse_sys_caps(recv_response(sock, noise))

    t0 = time.time()
    send_apdu(sock, noise, 0x01)
    parse_sys_hello(recv_response(sock, noise), (time.time() - t0) * 1000)

    t0 = time.time()
    send_apdu(sock, noise, 0x02)
    parse_sys_status(recv_response(sock, noise), (time.time() - t0) * 1000)

    t0 = time.time()
    send_apdu(sock, noise, 0x03)
    parse_sys_procs(recv_response(sock, noise), (time.time() - t0) * 1000)

    cache_timing_test(sock, noise, rounds=6, interval_s=0.2)


# ── Main ──────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]
    if not args:
        print("Usage:")
        print("  Standard: python3 client_core_isa.py <host> [port]")
        print("  Legacy:   python3 client_core_isa.py <server_pub_hex> <host> [port]")
        sys.exit(1)

    # Detect legacy mode: first arg is a 64-char hex string
    if len(args[0]) == 64 and all(c in '0123456789abcdefABCDEF' for c in args[0]):
        expected_pub_hex = args[0].lower()
        host = args[1] if len(args) > 1 else 'localhost'
        port = int(args[2]) if len(args) > 2 else 7816
    else:
        expected_pub_hex = None
        host = args[0]
        port = int(args[1]) if len(args) > 1 else 7816

    client_priv = load_client_key()

    print(f"ASys Test Client  —  {host}:{port}")
    print("=" * 52)

    sock, noise = connect_and_handshake(host, port, client_priv, expected_pub_hex)

    try:
        run_core_isa(sock, noise)
    except Exception as e:
        print(f"Error: {e}")
        sock.close()
        sys.exit(1)

    sock.close()
    print("=" * 52)
    print("Done.")


if __name__ == '__main__':
    main()
