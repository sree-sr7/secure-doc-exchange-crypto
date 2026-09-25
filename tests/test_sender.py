import base64
import json
import os
import struct
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# Add repo root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization
from crypto_core import (
    hash_document_hex,
    compute_hmac,
    verify_hmac,
    generate_keypair,
    sign_document,
    verify_signature,
    verify_document,
)
from sender.bundle import (
    Metadata,
    build_signing_payload,
    parse_signing_payload,
    get_next_seq,
    get_current_seq,
)
from sender.keygen import generate_keys
from sender.sender_app import send_document


def test_bundle_payload_format():
    meta = Metadata(
        sender_id="alice",
        filename="contract.pdf",
        seq=1,
        timestamp=1700000000,
        nonce="abcd1234efgh5678",
    )
    doc = b"Hello, World!"
    payload = build_signing_payload(doc, meta)

    # Verify length prefixing
    offset = 0
    # sender_id
    (s_len,) = struct.unpack_from(">I", payload, offset)
    offset += 4
    assert payload[offset : offset + s_len] == b"alice"
    offset += s_len

    # filename
    (f_len,) = struct.unpack_from(">I", payload, offset)
    offset += 4
    assert payload[offset : offset + f_len] == b"contract.pdf"
    offset += f_len

    # seq
    (seq_len,) = struct.unpack_from(">I", payload, offset)
    offset += 4
    assert payload[offset : offset + seq_len] == b"1"
    offset += seq_len

    # timestamp
    (t_len,) = struct.unpack_from(">I", payload, offset)
    offset += 4
    assert payload[offset : offset + t_len] == b"1700000000"
    offset += t_len

    # nonce
    (n_len,) = struct.unpack_from(">I", payload, offset)
    offset += 4
    assert payload[offset : offset + n_len] == b"abcd1234efgh5678"
    offset += n_len

    # document at the end
    assert payload[offset:] == doc


def test_bundle_payload_roundtrip_parsing():
    meta = Metadata(
        sender_id="bob",
        filename="financial_report.xlsx",
        seq=42,
        timestamp=1720001234,
        nonce="nonce_secret_val",
    )
    doc = b"Secret Financial Data\x00\x01\x02\xff"
    payload = build_signing_payload(doc, meta)

    parsed_meta, parsed_doc = parse_signing_payload(payload)
    assert parsed_meta == meta
    assert parsed_doc == doc


def test_bundle_prevents_field_boundary_confusion():
    meta1 = Metadata(sender_id="alice", filename="contract", seq=1, timestamp=100, nonce="n1")
    meta2 = Metadata(sender_id="ali", filename="cecontract", seq=1, timestamp=100, nonce="n1")
    doc = b"test"

    payload1 = build_signing_payload(doc, meta1)
    payload2 = build_signing_payload(doc, meta2)
    assert payload1 != payload2


def test_bundle_validation_checks():
    doc = b"content"
    meta = Metadata(sender_id="alice", filename="doc.txt", seq=1, timestamp=100, nonce="n")

    # Document type check
    try:
        build_signing_payload("not bytes", meta)  # type: ignore
        assert False, "Expected TypeError for non-bytes document"
    except TypeError:
        pass

    # Empty sender_id check
    bad_meta = Metadata(sender_id="", filename="doc.txt", seq=1, timestamp=100, nonce="n")
    try:
        build_signing_payload(doc, bad_meta)
        assert False, "Expected ValueError for empty sender_id"
    except ValueError:
        pass


def test_sequence_number_persistence():
    with tempfile.TemporaryDirectory() as tmpdir:
        sender_id = "charlie"
        assert get_current_seq(sender_id, tmpdir) == 0

        # Increments strictly
        assert get_next_seq(sender_id, tmpdir) == 1
        assert get_next_seq(sender_id, tmpdir) == 2
        assert get_next_seq(sender_id, tmpdir) == 3

        # Restart simulation
        assert get_current_seq(sender_id, tmpdir) == 3
        assert get_next_seq(sender_id, tmpdir) == 4

        # Different sender has isolated sequence
        other_sender = "dave"
        assert get_current_seq(other_sender, tmpdir) == 0
        assert get_next_seq(other_sender, tmpdir) == 1
        assert get_current_seq(sender_id, tmpdir) == 4


def test_keygen_creates_keys_and_preserves_shared_key():
    with tempfile.TemporaryDirectory() as tmpdir:
        generate_keys("test_sender", out_dir=tmpdir)

        priv_path = Path(tmpdir) / "test_sender_private.pem"
        pub_path = Path(tmpdir) / "test_sender_public.pem"
        shared_path = Path(tmpdir) / "shared_hmac.key"

        assert priv_path.is_file()
        assert pub_path.is_file()
        assert shared_path.is_file()

        shared_bytes_1 = shared_path.read_bytes()
        assert len(shared_bytes_1) == 32

        # Verify key usability with cryptography & crypto_core
        priv_key = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
        pub_key = serialization.load_pem_public_key(pub_path.read_bytes())

        test_data = b"Signature verification test"
        sig = sign_document(test_data, priv_key)
        assert verify_signature(test_data, sig, pub_key) is True

        # Re-run keygen: shared_hmac.key must be preserved if already exists
        generate_keys("test_sender", out_dir=tmpdir)
        shared_bytes_2 = shared_path.read_bytes()
        assert shared_bytes_1 == shared_bytes_2, "Existing shared key must not be overwritten"


def test_full_sender_receiver_exchange_flow():
    """Spin up an ephemeral receiver HTTP server and test sender_app delivery and verification."""
    with tempfile.TemporaryDirectory() as tmpdir:
        sender_id = "alice"
        generate_keys(sender_id, out_dir=tmpdir)

        priv_path = Path(tmpdir) / f"{sender_id}_private.pem"
        pub_path = Path(tmpdir) / f"{sender_id}_public.pem"
        shared_path = Path(tmpdir) / "shared_hmac.key"

        pub_key = serialization.load_pem_public_key(pub_path.read_bytes())
        shared_key = shared_path.read_bytes()

        # Document to send
        doc_path = Path(tmpdir) / "important_contract.txt"
        doc_content = b"CRITICAL CONTRACT TERMS FOR INTEGRATION/INFRA"
        doc_path.write_bytes(doc_content)

        received_requests = []

        class MockReceiverHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                content_len = int(self.headers.get("Content-Length", 0))
                post_body = self.rfile.read(content_len)
                data = json.loads(post_body.decode("utf-8"))
                received_requests.append(data)

                # Reconstruct receiver side
                doc = base64.b64decode(data["document_b64"])
                tag = base64.b64decode(data["tag_b64"])
                signature = base64.b64decode(data["signature_b64"])
                metadata = Metadata.from_dict(data)

                # 1. Verify SHA-256 fingerprint matches document
                assert hash_document_hex(doc) == data["document_sha256"]

                # 2. Reconstruct signing payload using identical bundle builder
                reconstructed_payload = build_signing_payload(doc, metadata)

                # 3. Verify HMAC and RSA signature with crypto_core.verify_document
                valid = verify_document(
                    reconstructed_payload,
                    tag,
                    signature,
                    shared_key,
                    pub_key,
                )

                status = "ACCEPTED" if valid else "REJECTED"
                resp_bytes = json.dumps({"status": status, "seq": data["seq"]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_bytes)))
                self.end_headers()
                self.wfile.write(resp_bytes)

            def log_message(self, format, *args):
                pass  # Suppress HTTP server output

        # Start mock server on ephemeral port
        server = HTTPServer(("127.0.0.1", 0), MockReceiverHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        receiver_url = f"http://127.0.0.1:{port}/api/receive"

        try:
            # Execute send_document
            send_document(
                file_path_str=str(doc_path),
                sender_id=sender_id,
                private_key_path_str=str(priv_path),
                shared_key_path_str=str(shared_path),
                receiver_url=receiver_url,
                state_dir=tmpdir,
            )

            assert len(received_requests) == 1
            req = received_requests[0]
            assert req["sender_id"] == "alice"
            assert req["filename"] == "important_contract.txt"
            assert req["seq"] == 1
            assert base64.b64decode(req["document_b64"]) == doc_content
            assert req["document_sha256"] == hash_document_hex(doc_content)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    passed, failed = 0, 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
            passed += 1
        except Exception as e:
            print(f"FAIL  {t.__name__}  {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    if failed:
        sys.exit(1)
