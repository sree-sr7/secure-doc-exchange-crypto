#!/usr/bin/env python3
"""
sender/web/app.py - Web UI for the Secure Document Exchange Sender

Wraps the exact same sender-side flow used by sender/sender_app.py:

    read document -> build anti-replay metadata -> build canonical signing
    payload -> SHA-256 fingerprint -> HMAC-SHA256 tag -> RSA-PSS signature
    -> POST JSON bundle to the receiver's HTTP endpoint

...behind a browser form, so a document can be picked, signed, and
transmitted without the command line.

IMPORTANT: this file only *imports* from crypto_core/ and sender/bundle.py.
It does not modify crypto_core/, sender_app.py, bundle.py, or keygen.py in
any way -- the CLI keeps working exactly as before.

Run:
    pip install -r sender/requirements.txt
    python sender/web/app.py

Then open http://127.0.0.1:5000 in a browser.

Note on scope: this module (like the rest of the sender/receiver pair)
provides integrity (SHA-256), authenticity (HMAC), and non-repudiation
(RSA-PSS signature). The document body itself is base64-transported, not
symmetrically encrypted -- there is no confidentiality guarantee against
an eavesdropper reading the transmitted document. If Phase 2 requires
confidentiality too, that's a deliberate addition to make on top of this,
not something implied by "encrypt & send" in this UI's button label alone.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import time
from pathlib import Path

import requests
from cryptography.hazmat.primitives import serialization
from flask import Flask, render_template, request

# Ensure the repo root (containing crypto_core/ and sender/) is importable
# regardless of where this script is launched from.
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from crypto_core import compute_hmac, generate_keypair, hash_document_hex, sign_document
from sender.bundle import Metadata, build_signing_payload, get_next_seq

# Per-sender sequence-number state (.seq_<id>.json) for transmissions made
# through this web UI. Kept in its own folder so it doesn't collide with
# .seq_*.json files created by CLI runs in other working directories.
# Point SENDER_WEB_STATE_DIR at the same folder as the CLI if you want the
# two to share one sequence counter per sender.
STATE_DIR = Path(os.environ.get("SENDER_WEB_STATE_DIR", Path(__file__).parent / "state"))
STATE_DIR.mkdir(parents=True, exist_ok=True)

# crypto_core.limits.MAX_DOCUMENT_SIZE (100 MB) plus headroom for multipart
# overhead and the other form fields.
MAX_UPLOAD_BYTES = 100 * 1024 * 1024 + 2 * 1024 * 1024

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
app.config["SECRET_KEY"] = secrets.token_hex(16)


def _error(message: str):
    return render_template("index.html", error=message, result=None)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", error=None, result=None)


@app.route("/send", methods=["POST"])
def send():
    sender_id = request.form.get("sender_id", "").strip()
    receiver_url = request.form.get("receiver_url", "").strip()

    try:
        timeout = float(request.form.get("timeout") or 30.0)
    except ValueError:
        return _error("Timeout must be a number.")

    doc_file = request.files.get("document")
    priv_file = request.files.get("private_key")
    shared_file = request.files.get("shared_key")

    if not sender_id:
        return _error("Sender ID is required.")
    if not receiver_url:
        return _error("Receiver URL is required.")
    if not doc_file or not doc_file.filename:
        return _error("Please choose a document to send.")
    if not priv_file or not priv_file.filename:
        return _error("Please upload the sender's RSA private key (.pem).")
    if not shared_file or not shared_file.filename:
        return _error("Please upload the shared HMAC key file.")

    document_bytes = doc_file.read()
    filename = os.path.basename(doc_file.filename)

    try:
        private_key = serialization.load_pem_private_key(priv_file.read(), password=None)
    except Exception as e:
        return _error(f"Could not load the private key: {e}")

    shared_key_bytes = shared_file.read()
    if len(shared_key_bytes) < 16:
        return _error(
            f"Shared key is {len(shared_key_bytes)} bytes; it must be at least "
            "16 bytes (32 bytes recommended, as produced by keygen.py)."
        )

    # Anti-replay metadata -- same construction as sender_app.py's CLI flow.
    next_seq = get_next_seq(sender_id, state_dir=str(STATE_DIR))
    timestamp = int(time.time())
    nonce = secrets.token_hex(16)
    metadata = Metadata(
        sender_id=sender_id,
        filename=filename,
        seq=next_seq,
        timestamp=timestamp,
        nonce=nonce,
    )

    try:
        signing_payload = build_signing_payload(document_bytes, metadata)
        doc_sha256 = hash_document_hex(document_bytes)
        hmac_tag = compute_hmac(signing_payload, shared_key_bytes)
        signature = sign_document(signing_payload, private_key)
    except Exception as e:
        return _error(f"Cryptographic operation failed: {e}")

    json_body = {
        "sender_id": metadata.sender_id,
        "filename": metadata.filename,
        "seq": metadata.seq,
        "timestamp": metadata.timestamp,
        "nonce": metadata.nonce,
        "document_b64": base64.b64encode(document_bytes).decode("ascii"),
        "document_sha256": doc_sha256,
        "tag_b64": base64.b64encode(hmac_tag).decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }

    result = {
        "sender_id": sender_id,
        "filename": filename,
        "seq": next_seq,
        "timestamp": timestamp,
        "nonce": nonce,
        "doc_sha256": doc_sha256,
        "size_bytes": len(document_bytes),
        "receiver_url": receiver_url,
        "request_json": json.dumps(json_body, indent=2),
    }

    try:
        response = requests.post(
            receiver_url,
            json=json_body,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
    except requests.RequestException as e:
        result["network_error"] = str(e)
        return render_template("index.html", error=None, result=result)

    result["http_status"] = response.status_code
    try:
        resp_json = response.json()
        result["response_json"] = json.dumps(resp_json, indent=2)
        result["accepted"] = resp_json.get("status") == "ACCEPTED"
    except ValueError:
        result["response_text"] = response.text
        result["accepted"] = False

    return render_template("index.html", error=None, result=result)


@app.route("/keys", methods=["GET"])
def keys_page():
    return render_template("keys.html", keys=None)


@app.route("/keys/generate", methods=["POST"])
def keys_generate():
    sender_id = request.form.get("sender_id", "").strip() or "sender"
    private_key, public_key = generate_keypair()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    shared_key = os.urandom(32)

    keys = {
        "sender_id": sender_id,
        "private_pem": pem_private.decode("ascii"),
        "public_pem": pem_public.decode("ascii"),
        "shared_key_b64": base64.b64encode(shared_key).decode("ascii"),
        "private_filename": f"{sender_id}_private.pem",
        "public_filename": f"{sender_id}_public.pem",
        "shared_filename": "shared_hmac.key",
    }
    return render_template("keys.html", keys=keys)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    print(f"[*] Secure Document Sender web UI: http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=debug)
