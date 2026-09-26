import base64
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from flask import Flask, request, jsonify

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

STATE_DIR.mkdir(parents=True, exist_ok=True)
KEYS_DIR.mkdir(parents=True, exist_ok=True)

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
            return jsonify({"status": "ACCEPTED"}), 200
        else:
            return jsonify({"status": "REJECTED"}), 200

    except Exception:
        # Catch any structural errors, missing files, or crypto parsing exceptions
        # Do NOT leak the exception details to the client
        return jsonify({"status": "REJECTED"}), 200

if __name__ == "__main__":
    port = int(os.environ.get("RECEIVER_PORT", 5001))
    print(f"[*] Secure Document Receiver Backend running on port {port}")
    app.run(host="127.0.0.1", port=port)
