#!/usr/bin/env python3
"""
sender/keygen.py - Key Generation CLI for Document Sender

Generates:
  1. <sender_id>_private.pem: RSA-PSS private key in PKCS8 PEM format (chmod 600).
  2. <sender_id>_public.pem:  RSA-PSS public key in SubjectPublicKeyInfo PEM format.
  3. shared_hmac.key:         32-byte shared HMAC secret key (if not already existing).

Usage:
  python keygen.py --sender-id alice
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

# Ensure crypto_core is importable regardless of working directory
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from cryptography.hazmat.primitives import serialization
from crypto_core import generate_keypair


def _restrict_permissions(path: Path) -> None:
    """Apply chmod 0600 on Unix, and restrict ACL to the current user on Windows."""
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

    if os.name == "nt":
        user = os.environ.get("USERNAME")
        if user:
            try:
                subprocess.run(
                    ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                    capture_output=True,
                    check=False,
                    timeout=5,
                )
            except Exception:
                pass


def save_restricted_file(path: Path, data: bytes) -> None:
    """Write data to path with restricted read/write permissions (0600)."""
    # Use os.open to create with restricted permissions atomically
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY

    fd = os.open(str(path), flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except Exception:
        os.close(fd)
        raise

    _restrict_permissions(path)


def generate_keys(sender_id: str, out_dir: str = ".") -> None:
    out_path = Path(out_dir).resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    priv_file = out_path / f"{sender_id}_private.pem"
    pub_file = out_path / f"{sender_id}_public.pem"
    shared_key_file = out_path / "shared_hmac.key"

    print(f"[*] Generating cryptographic material for sender '{sender_id}'...")

    # 1. Generate RSA keypair using crypto_core
    private_key, public_key = generate_keypair()

    # 2. Serialize and save RSA private key (PKCS8 PEM, chmod 600)
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    save_restricted_file(priv_file, pem_private)

    # 3. Serialize and save RSA public key (SubjectPublicKeyInfo PEM)
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(pub_file, "wb") as f:
        f.write(pem_public)

    # 4. Generate random 32-byte shared HMAC key if one does not already exist
    shared_key_created = False
    if not shared_key_file.exists():
        shared_key = os.urandom(32)
        save_restricted_file(shared_key_file, shared_key)
        shared_key_created = True
    else:
        # Check size of existing shared key
        existing_len = shared_key_file.stat().st_size
        if existing_len < 16:
            print(f"[!] Warning: Existing shared key at {shared_key_file} is only {existing_len} bytes.")

    # 5. Output key distribution instructions
    print("\n" + "=" * 76)
    print(f" KEYPAIR & HMAC MATERIAL GENERATED FOR SENDER: {sender_id}")
    print("=" * 76)
    print(f" - Private Key : {priv_file} (chmod 600)")
    print(f" - Public Key  : {pub_file}")
    if shared_key_created:
        print(f" - Shared Key  : {shared_key_file} (32 bytes generated, chmod 600)")
    else:
        print(f" - Shared Key  : {shared_key_file} (existing key preserved)")

    print("\n" + "-" * 76)
    print(" KEY DISTRIBUTION & SECURITY INSTRUCTIONS (WHERE FILES GO):")
    print("-" * 76)
    print(" 1. LOCAL STORAGE (Stay on this machine ONLY - KEEP CONFIDENTIAL):")
    print(f"    [LOCAL] {priv_file.name}")
    print("            -> Sender's RSA private key. Used by sender_app.py to sign payloads.")
    print("            -> NEVER send over the network. Keep permission restricted (chmod 600).")
    print(f"    [LOCAL] {shared_key_file.name}")
    print("            -> Symmetric 256-bit secret key used by sender_app.py to compute HMAC.")
    print("")
    print(" 2. OUT-OF-BAND HANDOFF (Hand off to receiver team before transmission):")
    print(f"    [HANDOFF] {pub_file.name}")
    print("              -> Hand over to receiver to verify RSA-PSS digital signatures.")
    print(f"    [HANDOFF] {shared_key_file.name}")
    print("              -> Pre-share out-of-band (e.g., secure drive, encrypted vault).")
    print("              -> Receiver uses this to verify HMAC tags.")
    print("")
    print(" [!] CRITICAL SECURITY REMINDER:")
    print("     - NEVER send private key or shared HMAC key over the network alongside")
    print("       a document!")
    print("     - Public key and shared key must be established out-of-band beforehand.")
    print("=" * 76 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="One-time key generation CLI for Secure Document Exchange Sender."
    )
    parser.add_argument(
        "--sender-id",
        required=True,
        help="Sender identifier (e.g. 'alice')",
    )
    parser.add_argument(
        "--out-dir",
        default=".",
        help="Directory to save generated keys (default: current directory)",
    )
    args = parser.parse_args()

    generate_keys(sender_id=args.sender_id, out_dir=args.out_dir)


if __name__ == "__main__":
    main()
