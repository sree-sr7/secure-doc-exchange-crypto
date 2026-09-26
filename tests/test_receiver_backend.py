import base64
import json
import os
import tempfile
import pytest
from cryptography.hazmat.primitives import serialization

import sys
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from crypto_core import generate_keypair, compute_hmac, sign_document
from sender.bundle import Metadata, build_signing_payload
from receiver.app import app, KEYS_DIR, STATE_DIR

@pytest.fixture
def test_client():
    # Setup keys
    private_key, public_key = generate_keypair()
    shared_key = os.urandom(32)
    
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    
    # Save keys where receiver expects them
    with open(KEYS_DIR / "shared_hmac.key", "wb") as f:
        f.write(shared_key)
        
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(KEYS_DIR / "alice_public.pem", "wb") as f:
        f.write(pub_bytes)
        
    # Clear state for ALICE
    seq_file = STATE_DIR / ".seq_alice.json"
    if seq_file.exists():
        os.remove(seq_file)

    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client, private_key, shared_key


def _build_valid_request(private_key, shared_key, seq=1, document=b"secret test doc", modify_sig=False, modify_mac=False):
    metadata = Metadata(
        sender_id="alice",
        filename="test.txt",
        seq=seq,
        timestamp=1234567890,
        nonce="random123"
    )
    signing_payload = build_signing_payload(document, metadata)
    
    mac_tag = compute_hmac(signing_payload, shared_key)
    if modify_mac:
        mac_tag = b"X" + mac_tag[1:]
        
    signature = sign_document(signing_payload, private_key)
    if modify_sig:
        signature = b"X" + signature[1:]

    return {
        "sender_id": "alice",
        "filename": "test.txt",
        "seq": seq,
        "timestamp": 1234567890,
        "nonce": "random123",
        "document_b64": base64.b64encode(document).decode("ascii"),
        "document_sha256": "fake_hash", # Receiver ignores this, it relies on HMAC & Sig of canonical payload
        "tag_b64": base64.b64encode(mac_tag).decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii")
    }

def test_1_genuine_document(test_client):
    client, private_key, shared_key = test_client
    req = _build_valid_request(private_key, shared_key, seq=1)
    
    resp = client.post("/receive", json=req)
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ACCEPTED"

def test_2_modified_document(test_client):
    client, private_key, shared_key = test_client
    req = _build_valid_request(private_key, shared_key, seq=2)
    # Tamper with document AFTER signature/MAC generation
    req["document_b64"] = base64.b64encode(b"tampered doc").decode("ascii")
    
    resp = client.post("/receive", json=req)
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "REJECTED"

def test_3_modified_hmac(test_client):
    client, private_key, shared_key = test_client
    req = _build_valid_request(private_key, shared_key, seq=3, modify_mac=True)
    
    resp = client.post("/receive", json=req)
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "REJECTED"

def test_4_modified_signature(test_client):
    client, private_key, shared_key = test_client
    req = _build_valid_request(private_key, shared_key, seq=4, modify_sig=True)
    
    resp = client.post("/receive", json=req)
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "REJECTED"

def test_5_replay(test_client):
    client, private_key, shared_key = test_client
    req = _build_valid_request(private_key, shared_key, seq=5)
    
    # First time - ACCEPTED
    resp = client.post("/receive", json=req)
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ACCEPTED"
    
    # Second time - REJECTED (Replay)
    resp = client.post("/receive", json=req)
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "REJECTED"

def test_6_invalid_input(test_client):
    client, _, _ = test_client
    # Missing fields
    resp = client.post("/receive", json={"sender_id": "alice"})
    assert resp.status_code == 400
    assert "REJECTED" in resp.get_json()["status"]
    
    # Malformed JSON
    resp = client.post("/receive", data="not json", content_type="application/json")
    assert resp.status_code == 400
    assert "REJECTED" in resp.get_json()["status"]
