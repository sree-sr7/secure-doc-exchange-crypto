#!/usr/bin/env python3
"""
sender/sender_app.py - Secure Document Sender CLI Application

Reads a file, constructs an anti-replay metadata bundle, binds it into a canonical
signing payload, computes raw SHA-256 fingerprint, computes HMAC tag, creates
RSA-PSS digital signature, and POSTs the secured bundle to the receiver endpoint.

CLI Usage:
    python sender_app.py <file> --sender-id alice --private-key alice_private.pem \
        --shared-key shared_hmac.key --receiver-url <url>
"""

import argparse
import base64
import json
import os
import secrets
import sys
import time
from pathlib import Path

# Ensure crypto_core is importable regardless of working directory
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

import requests
from cryptography.hazmat.primitives import serialization
from crypto_core import compute_hmac, hash_document_hex, sign_document
from sender.bundle import Metadata, build_signing_payload, get_next_seq


def send_document(
    file_path_str: str,
    sender_id: str,
    private_key_path_str: str,
    shared_key_path_str: str,
    receiver_url: str,
    state_dir: str | None = None,
    timeout: float = 30.0,
) -> None:
    # 1. Validate and read the input document
    file_path = Path(file_path_str)
    if not file_path.is_file():
        print(f"[-] Error: File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    try:
        document_bytes = file_path.read_bytes()
    except Exception as e:
        print(f"[-] Error reading file '{file_path}': {e}", file=sys.stderr)
        sys.exit(1)

    # 2. Validate and load the private key
    priv_path = Path(private_key_path_str)
    if not priv_path.is_file():
        print(f"[-] Error: Private key file not found: {priv_path}", file=sys.stderr)
        sys.exit(1)

    try:
        private_key_bytes = priv_path.read_bytes()
        private_key = serialization.load_pem_private_key(private_key_bytes, password=None)
    except Exception as e:
        print(f"[-] Error loading private key from '{priv_path}': {e}", file=sys.stderr)
        sys.exit(1)

    # 3. Validate and load the shared HMAC key
    shared_path = Path(shared_key_path_str)
    if not shared_path.is_file():
        print(f"[-] Error: Shared key file not found: {shared_path}", file=sys.stderr)
        sys.exit(1)

    try:
        shared_key_bytes = shared_path.read_bytes()
        if len(shared_key_bytes) < 16:
            print(
                f"[-] Error: Shared key in '{shared_path}' is {len(shared_key_bytes)} bytes. "
                f"Must be at least 16 bytes (32 bytes recommended).",
                file=sys.stderr,
            )
            sys.exit(1)
    except Exception as e:
        print(f"[-] Error reading shared key '{shared_path}': {e}", file=sys.stderr)
        sys.exit(1)

    # 4. Build Metadata with next sequence number, timestamp, and random nonce
    next_seq = get_next_seq(sender_id, state_dir=state_dir)
    timestamp = int(time.time())
    nonce = secrets.token_hex(16)
    filename = file_path.name

    metadata = Metadata(
        sender_id=sender_id,
        filename=filename,
        seq=next_seq,
        timestamp=timestamp,
        nonce=nonce,
    )

    # 5. Build canonical signing payload binding metadata to raw document
    try:
        signing_payload = build_signing_payload(document_bytes, metadata)
    except Exception as e:
        print(f"[-] Error building canonical signing payload: {e}", file=sys.stderr)
        sys.exit(1)

    # 6. Cryptographic operations via crypto_core:
    #    - hash_document_hex on raw document (for human verification & fingerprinting)
    #    - compute_hmac and sign_document on the canonical signing payload
    try:
        doc_sha256 = hash_document_hex(document_bytes)
        hmac_tag = compute_hmac(signing_payload, shared_key_bytes)
        signature = sign_document(signing_payload, private_key)
    except Exception as e:
        print(f"[-] Cryptographic operation failed: {e}", file=sys.stderr)
        sys.exit(1)

    # 7. Print the SHA-256 fingerprint as requested
    print(f"Document SHA-256: {doc_sha256}")

    # 8. Base64-encode document, tag, and signature
    document_b64 = base64.b64encode(document_bytes).decode("ascii")
    tag_b64 = base64.b64encode(hmac_tag).decode("ascii")
    signature_b64 = base64.b64encode(signature).decode("ascii")

    # 9. Construct JSON body containing:
    #    all metadata fields + document_b64 + document_sha256 + tag_b64 + signature_b64
    json_body = {
        "sender_id": metadata.sender_id,
        "filename": metadata.filename,
        "seq": metadata.seq,
        "timestamp": metadata.timestamp,
        "nonce": metadata.nonce,
        "document_b64": document_b64,
        "document_sha256": doc_sha256,
        "tag_b64": tag_b64,
        "signature_b64": signature_b64,
    }

    # 10. POST to receiver-url using requests
    print(f"[*] Sending transmission to {receiver_url} (seq: {metadata.seq})...")
    try:
        response = requests.post(
            receiver_url,
            json=json_body,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
    except requests.RequestException as e:
        print(f"[-] Network error connecting to receiver ({receiver_url}): {e}", file=sys.stderr)
        sys.exit(1)

    # 11. Print the receiver's JSON response
    try:
        resp_json = response.json()
        print("Receiver JSON response:")
        print(json.dumps(resp_json, indent=2))
    except Exception:
        print(
            f"[-] Receiver returned non-JSON response (HTTP {response.status_code}):\n{response.text}",
            file=sys.stderr,
        )
        sys.exit(1)

    # 12. Exit with a non-zero status code if response's "status" isn't "ACCEPTED"
    status = resp_json.get("status")
    if status != "ACCEPTED":
        print(
            f"[-] Verification rejected by receiver! Expected status 'ACCEPTED', got '{status}'.",
            file=sys.stderr,
        )
        sys.exit(1)

    print("[+] Transmission successfully ACCEPTED by receiver.")
    sys.exit(0)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Secure Document Exchange Sender Application"
    )
    parser.add_argument("file", help="Path to document file to send")
    parser.add_argument(
        "--sender-id",
        required=True,
        help="Sender identifier (e.g. 'alice')",
    )
    parser.add_argument(
        "--private-key",
        required=True,
        help="Path to sender's RSA private key PEM file (e.g. 'alice_private.pem')",
    )
    parser.add_argument(
        "--shared-key",
        required=True,
        help="Path to shared HMAC secret key file (e.g. 'shared_hmac.key')",
    )
    parser.add_argument(
        "--receiver-url",
        required=True,
        help="URL of the receiver HTTP endpoint",
    )
    parser.add_argument(
        "--state-dir",
        default=None,
        help="Optional directory to store sequence persistence files (default: current directory)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="HTTP request timeout in seconds (default: 30.0)",
    )

    args = parser.parse_args()

    send_document(
        file_path_str=args.file,
        sender_id=args.sender_id,
        private_key_path_str=args.private_key,
        shared_key_path_str=args.shared_key,
        receiver_url=args.receiver_url,
        state_dir=args.state_dir,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    main()
