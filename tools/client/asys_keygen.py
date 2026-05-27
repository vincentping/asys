#!/usr/bin/env python3
# Copyright (c) 2026 Vincent Ping (vincentping@gmail.com)
# SPDX-License-Identifier: Apache-2.0
"""
asys_keygen.py — ASys client key generator (analogous to ssh-keygen)

Generates a Curve25519 keypair and stores it in ~/.asys/.

Usage:
    python3 tools/client/asys_keygen.py [--name <suffix>]

    --name <suffix>  Generate a named keypair: id_curve25519_<suffix>
                     (default: id_curve25519)

Output files:
    ~/.asys/id_curve25519        private key, 32 bytes raw, mode 0600
    ~/.asys/id_curve25519.pub    public key, 64-char hex + newline, mode 0644

If the default key already exists, the tool exits without overwriting.
Use --name to generate additional named keypairs.

Dependencies:
    pip install cryptography
"""

import os
import sys

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization


ASYS_DIR = os.path.expanduser('~/.asys')


def main():
    name_suffix = None
    args = sys.argv[1:]
    if '--name' in args:
        idx = args.index('--name')
        if idx + 1 >= len(args):
            print("Error: --name requires a suffix argument", file=sys.stderr)
            sys.exit(1)
        name_suffix = args[idx + 1]

    priv_name = f'id_curve25519_{name_suffix}' if name_suffix else 'id_curve25519'
    pub_name  = priv_name + '.pub'
    priv_path = os.path.join(ASYS_DIR, priv_name)
    pub_path  = os.path.join(ASYS_DIR, pub_name)

    # Create ~/.asys/ (0700)
    os.makedirs(ASYS_DIR, exist_ok=True)
    try:
        os.chmod(ASYS_DIR, 0o700)
    except Exception:
        pass  # Windows: chmod is a no-op

    # Refuse to overwrite existing key
    if os.path.exists(priv_path):
        print(f"Key already exists: {priv_path}")
        print(f"Use --name <suffix> to generate an additional keypair.")
        sys.exit(1)

    # Generate Curve25519 keypair via cryptography library
    private_key = X25519PrivateKey.generate()
    priv_bytes  = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    pub_hex = pub_bytes.hex()

    # Write private key (0600)
    with open(priv_path, 'wb') as f:
        f.write(priv_bytes)
    try:
        os.chmod(priv_path, 0o600)
    except Exception:
        pass

    # Write public key as hex text (0644)
    with open(pub_path, 'w') as f:
        f.write(pub_hex + '\n')
    try:
        os.chmod(pub_path, 0o644)
    except Exception:
        pass

    print(f"Your ASys identity has been saved in {ASYS_DIR}")
    print(f"  Private key: {priv_path}")
    print(f"  Public key:  {pub_path}")
    print(f"  Fingerprint: {pub_hex}")


if __name__ == '__main__':
    main()
