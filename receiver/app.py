import base64
import json
import os
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from flask import Flask, request, jsonify, render_template

# Ensure repo root is in sys.path so we can import crypto_core and sender
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from crypto_core import verify_document_label
from sender.bundle import Metadata, build_signing_payload

app = Flask(__name__)

# Configuration directories
BASE_DIR = Path(os.environ.get("RECEIVER_BASE_DIR", Path(__file__).parent))
STATE_DIR = BASE_DIR / "state"
KEYS_DIR = BASE_DIR / "keys"
DOCS_DIR = BASE_DIR / "docs"

STATE_DIR.mkdir(parents=True, exist_ok=True)
KEYS_DIR.mkdir(parents=True, exist_ok=True)
DOCS_DIR.mkdir(parents=True, exist_ok=True)

RECEIVER_LOG = STATE_DIR / "receiver_log.json"

def get_receiver_log():
    if not RECEIVER_LOG.is_file():
        return []
    try:
        with open(RECEIVER_LOG, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def append_receiver_log(entry):
    logs = get_receiver_log()
    logs.insert(0, entry) # prepend
    temp_file = RECEIVER_LOG.with_name(f"{RECEIVER_LOG.name}.tmp.{os.getpid()}")
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2)
    temp_file.replace(RECEIVER_LOG)

def get_receiver_seq_path(sender_id: str) -> Path:
    safe_id = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in sender_id)
    return STATE_DIR / f".seq_{safe_id}.json"

def get_last_accepted_seq(sender_id: str) -> int:
    seq_file = get_receiver_seq_path(sender_id)
    if not seq_file.is_file():
        return 0
    try:
        with open(seq_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return int(data.get("last_accepted_seq", 0))
    except Exception:
        return 0

def update_last_accepted_seq(sender_id: str, new_seq: int):
    seq_file = get_receiver_seq_path(sender_id)
    temp_file = seq_file.with_name(f"{seq_file.name}.tmp.{os.getpid()}")
    state_data = {
        "sender_id": sender_id,
        "last_accepted_seq": new_seq,
    }
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(state_data, f, indent=2)
    temp_file.replace(seq_file)


def load_shared_key() -> bytes:
    """Loads the shared HMAC key from the local keys directory.
    This file should be securely provisioned out-of-band."""
    key_path = KEYS_DIR / "shared_hmac.key"
    if not key_path.is_file():
        raise FileNotFoundError(f"Shared HMAC key not found at {key_path}")
    with open(key_path, "rb") as f:
        return f.read()


def load_sender_public_key(sender_id: str):
    """Loads the sender's public key from the local keys directory."""
    safe_id = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in sender_id)
    key_path = KEYS_DIR / f"{safe_id}_public.pem"
    if not key_path.is_file():
        raise FileNotFoundError(f"Public key for sender '{sender_id}' not found at {key_path}")
    
    with open(key_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

@app.route("/", methods=["GET"])
def index():
    logs = get_receiver_log()
    return render_template("index.html", logs=logs)

@app.route("/receive", methods=["POST"])
def receive_document():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "REJECTED", "error": "Invalid or missing JSON payload"}), 400

    required_fields = [
        "sender_id", "filename", "seq", "timestamp", "nonce",
        "document_b64", "tag_b64", "signature_b64"
    ]
    
    for field in required_fields:
        if field not in data:
            return jsonify({"status": "REJECTED", "error": f"Missing required field: {field}"}), 400

    sender_id = str(data["sender_id"])
    log_entry = {
        "timestamp_received": int(time.time()),
        "sender_id": sender_id,
        "filename": str(data["filename"]),
        "seq": int(data["seq"]),
        "status": "REJECTED",
        "reason": "Unknown error"
    }
    
    try:
        # Load keys securely from the local filesystem
        shared_key = load_shared_key()
        public_key = load_sender_public_key(sender_id)
        
        # Decode base64 payloads
        document_bytes = base64.b64decode(data["document_b64"])
        mac_tag = base64.b64decode(data["tag_b64"])
        signature = base64.b64decode(data["signature_b64"])
        
        # Reconstruct Anti-Replay Metadata
        metadata = Metadata(
            sender_id=sender_id,
            filename=str(data["filename"]),
            seq=int(data["seq"]),
            timestamp=int(data["timestamp"]),
            nonce=str(data["nonce"])
        )
        
        # Check sequence number to prevent replay attacks
        last_seq = get_last_accepted_seq(sender_id)
        if metadata.seq <= last_seq:
            # Replay attack detected
            log_entry["reason"] = "Replay attack detected (sequence number too low or reused)"
            append_receiver_log(log_entry)
            return jsonify({"status": "REJECTED"}), 200

        # Reconstruct Canonical Signing Payload precisely as sender did
        signing_payload = build_signing_payload(document_bytes, metadata)
        
        # Verify both HMAC and Digital Signature using crypto_core
        result_label = verify_document_label(
            data=signing_payload,
            mac_tag=mac_tag,
            signature=signature,
            shared_key=shared_key,
            public_key=public_key
        )
        
        if result_label == "ACCEPTED":
            # Only update sequence number after successful verification
            update_last_accepted_seq(sender_id, metadata.seq)
            log_entry["status"] = "ACCEPTED"
            log_entry["reason"] = "Valid MAC and Signature"
            # Save document
            safe_filename = "".join(c if c.isalnum() or c in (".", "-", "_") else "_" for c in metadata.filename)
            doc_path = DOCS_DIR / f"{metadata.seq}_{safe_filename}"
            with open(doc_path, "wb") as f:
                f.write(document_bytes)
            log_entry["saved_path"] = str(doc_path.name)
            
            append_receiver_log(log_entry)
            return jsonify({"status": "ACCEPTED"}), 200
        else:
            log_entry["reason"] = "Verification failed (invalid MAC or Signature)"
            append_receiver_log(log_entry)
            return jsonify({"status": "REJECTED"}), 200

    except FileNotFoundError as e:
        log_entry["reason"] = f"Missing keys: {str(e)}"
        append_receiver_log(log_entry)
        return jsonify({"status": "REJECTED"}), 200
    except Exception as e:
        # Catch any structural errors, missing files, or crypto parsing exceptions
        # Do NOT leak the exception details to the client
        log_entry["reason"] = "Malformed payload or internal processing error"
        append_receiver_log(log_entry)
        return jsonify({"status": "REJECTED"}), 200

if __name__ == "__main__":
    port = int(os.environ.get("RECEIVER_PORT", 5001))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    print(f"[*] Secure Document Receiver Backend running on port {port}")
    app.run(host="127.0.0.1", port=port, debug=debug)
