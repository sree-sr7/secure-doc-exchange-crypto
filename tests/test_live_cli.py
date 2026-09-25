"""
Live CLI Demonstration & Verification for Secure Document Exchange Sender.

Tests:
1. Key generation CLI (sender/keygen.py)
2. Sequence persistence across runs (seq 1, seq 2)
3. Successful transmission & receiver acceptance (sender/sender_app.py)
4. Full cryptographic verification on receiver side
5. Non-zero exit code on REJECTED status
"""

import base64
import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# Add repo root to path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from cryptography.hazmat.primitives import serialization
from crypto_core import hash_document_hex, verify_document
from sender.bundle import Metadata, build_signing_payload


def run_live_test():
    print("=" * 70)
    print("STARTING LIVE VERIFICATION OF SENDER SUBSYSTEM")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        print(f"[*] Working directory: {temp_path}\n")

        # -------------------------------------------------------------
        # STEP 1: Run keygen CLI
        # -------------------------------------------------------------
        print("--- STEP 1: Running sender/keygen.py ---")
        sender_id = "alice"
        keygen_cmd = [
            sys.executable,
            str(REPO_ROOT / "sender" / "keygen.py"),
            "--sender-id",
            sender_id,
            "--out-dir",
            str(temp_path),
        ]
        result = subprocess.run(keygen_cmd, capture_output=True, text=True, cwd=str(temp_path))
        assert result.returncode == 0, f"keygen failed:\n{result.stderr}"
        print(result.stdout)

        priv_key_file = temp_path / f"{sender_id}_private.pem"
        pub_key_file = temp_path / f"{sender_id}_public.pem"
        shared_key_file = temp_path / "shared_hmac.key"

        assert priv_key_file.exists(), "Private key not generated"
        assert pub_key_file.exists(), "Public key not generated"
        assert shared_key_file.exists(), "Shared HMAC key not generated"
        print("[+] Verified: All 3 key files generated successfully.\n")

        # Load keys for receiver verification
        public_key = serialization.load_pem_public_key(pub_key_file.read_bytes())
        shared_key = shared_key_file.read_bytes()

        # -------------------------------------------------------------
        # STEP 2: Create a sample document
        # -------------------------------------------------------------
        doc_file = temp_path / "financial_contract.txt"
        doc_content = b"PAYMENT ORDER: Transfer $1,000,000 to Account #987654321"
        doc_file.write_bytes(doc_content)
        expected_sha256 = hash_document_hex(doc_content)
        print(f"--- STEP 2: Created sample document '{doc_file.name}' ---")
        print(f"Content: {doc_content.decode('utf-8')}")
        print(f"Expected SHA-256: {expected_sha256}\n")

        # -------------------------------------------------------------
        # STEP 3: Setup Mock Receiver HTTP Server
        # -------------------------------------------------------------
        received_payloads = []
        receiver_mode = {"reject_next": False}

        class LiveReceiver(BaseHTTPRequestHandler):
            def do_POST(self):
                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len)
                data = json.loads(body.decode("utf-8"))
                received_payloads.append(data)

                # Receiver extraction & verification
                doc_bytes = base64.b64decode(data["document_b64"])
                tag = base64.b64decode(data["tag_b64"])
                sig = base64.b64decode(data["signature_b64"])
                meta = Metadata.from_dict(data)

                # Reconstruct payload using bundle.py
                payload = build_signing_payload(doc_bytes, meta)

                # Verify via crypto_core
                is_valid = verify_document(payload, tag, sig, shared_key, public_key)

                if receiver_mode["reject_next"]:
                    status = "REJECTED"
                else:
                    status = "ACCEPTED" if is_valid else "REJECTED"

                resp_obj = {
                    "status": status,
                    "sender_id": data["sender_id"],
                    "seq": data["seq"],
                    "document_sha256": data["document_sha256"],
                }
                resp_bytes = json.dumps(resp_obj).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_bytes)))
                self.end_headers()
                self.wfile.write(resp_bytes)

            def log_message(self, format, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), LiveReceiver)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        receiver_url = f"http://127.0.0.1:{port}/api/receive"

        try:
            # -------------------------------------------------------------
            # STEP 4: Send Document #1 (First transmission, seq=1)
            # -------------------------------------------------------------
            print(f"--- STEP 4: Sending document #1 via sender_app.py (target seq: 1) ---")
            send_cmd_1 = [
                sys.executable,
                str(REPO_ROOT / "sender" / "sender_app.py"),
                str(doc_file),
                "--sender-id",
                sender_id,
                "--private-key",
                str(priv_key_file),
                "--shared-key",
                str(shared_key_file),
                "--receiver-url",
                receiver_url,
                "--state-dir",
                str(temp_path),
            ]
            res_1 = subprocess.run(send_cmd_1, capture_output=True, text=True, cwd=str(temp_path))
            print("STDOUT:")
            print(res_1.stdout)
            if res_1.stderr:
                print("STDERR:", res_1.stderr)
            assert res_1.returncode == 0, f"sender_app exited with code {res_1.returncode}"
            assert f"Document SHA-256: {expected_sha256}" in res_1.stdout
            assert '"status": "ACCEPTED"' in res_1.stdout
            assert received_payloads[-1]["seq"] == 1
            print("[+] Verified: First transmission succeeded with seq=1 and ACCEPTED status.\n")

            # -------------------------------------------------------------
            # STEP 5: Send Document #2 (Second transmission, seq=2)
            # -------------------------------------------------------------
            print("--- STEP 5: Sending document #2 to verify strictly-increasing seq (seq: 2) ---")
            res_2 = subprocess.run(send_cmd_1, capture_output=True, text=True, cwd=str(temp_path))
            print("STDOUT:")
            print(res_2.stdout)
            assert res_2.returncode == 0
            assert received_payloads[-1]["seq"] == 2
            print("[+] Verified: Sequence number automatically incremented to 2.\n")

            # -------------------------------------------------------------
            # STEP 6: Verify failure exit code when receiver responds REJECTED
            # -------------------------------------------------------------
            print("--- STEP 6: Testing rejection handling (exit code != 0) ---")
            receiver_mode["reject_next"] = True
            res_reject = subprocess.run(send_cmd_1, capture_output=True, text=True, cwd=str(temp_path))
            print("STDOUT:")
            print(res_reject.stdout)
            print("STDERR:")
            print(res_reject.stderr)
            assert res_reject.returncode != 0, "Expected non-zero exit code on REJECTED status"
            print(f"[+] Verified: Process exited with non-zero code ({res_reject.returncode}) on REJECTED status.\n")

        finally:
            server.shutdown()
            server.server_close()

    print("=" * 70)
    print("ALL LIVE VERIFICATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 70)


if __name__ == "__main__":
    run_live_test()
