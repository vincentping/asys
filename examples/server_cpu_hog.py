#!/usr/bin/env python3
# Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
# SPDX-License-Identifier: Apache-2.0
"""
server_cpu_hog.py — Spawn a CPU-intensive process and print its PID.

Run this on the managed node (RHEL) before running client_proc_throttle.py
on the remote client.

Usage:
    python3 server_cpu_hog.py
"""

import os
import subprocess
import sys
import signal
import time

hog = subprocess.Popen(
    [sys.executable, '-c', 'while True: pass'],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)

print(f"CPU hog started  PID={hog.pid}")
print("Press Ctrl+C to stop.")

def _cleanup(sig, frame):
    try:
        os.kill(hog.pid, signal.SIGCONT)  # resume if stopped by throttle
    except OSError:
        pass
    hog.terminate()
    hog.wait()
    print(f"\nCPU hog terminated  PID={hog.pid}")
    sys.exit(0)

signal.signal(signal.SIGINT,  _cleanup)
signal.signal(signal.SIGTERM, _cleanup)

while True:
    time.sleep(1)
