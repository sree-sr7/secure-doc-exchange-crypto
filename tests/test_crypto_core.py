import sys
import os
import tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_core import (
    hash_document,
    compute_hmac,
    verify_hmac,
    generate_keypair,
    sign_document,
    verify_signature,
    verify_document,
    verify_document_label,
    save_private_key,
    load_private_key,
)
import crypto_core.limits as limits

DOC = b"This is the real, unmodified contract text."
TAMPERED = b"This is the real, unmodifiEd contract text."
KEY = os.urandom(32)


def test_hash_deterministic():
    assert hash_document(DOC) == hash_document(DOC)


def test_hash_changes_on_tamper():
    assert hash_document(DOC) != hash_document(TAMPERED)


def test_hmac_genuine_passes():
    tag = compute_hmac(DOC, KEY)
    assert verify_hmac(DOC, KEY, tag) is True


def test_hmac_tampered_document_fails():
    tag = compute_hmac(DOC, KEY)
    assert verify_hmac(TAMPERED, KEY, tag) is False


def test_hmac_wrong_key_fails():
    tag = compute_hmac(DOC, KEY)
    wrong_key = os.urandom(32)
    assert verify_hmac(DOC, wrong_key, tag) is False


def test_signature_genuine_passes():
    priv, pub = generate_keypair()
    sig = sign_document(DOC, priv)
    assert verify_signature(DOC, sig, pub) is True


def test_signature_tampered_document_fails():
    priv, pub = generate_keypair()
    sig = sign_document(DOC, priv)
    assert verify_signature(TAMPERED, sig, pub) is False


def test_signature_wrong_key_fails():
    priv1, pub1 = generate_keypair()
    priv2, pub2 = generate_keypair()
    sig = sign_document(DOC, priv1)
    assert verify_signature(DOC, sig, pub2) is False


def test_combined_verify_accepts_genuine():
    priv, pub = generate_keypair()
    tag = compute_hmac(DOC, KEY)
    sig = sign_document(DOC, priv)
    assert verify_document(DOC, tag, sig, KEY, pub) is True


def test_combined_verify_rejects_on_mac_failure_only():
    priv, pub = generate_keypair()
    bad_tag = compute_hmac(TAMPERED, KEY)
    sig = sign_document(DOC, priv)
    assert verify_document(DOC, bad_tag, sig, KEY, pub) is False


def test_combined_verify_rejects_on_signature_failure_only():
    priv1, pub1 = generate_keypair()
    priv2, _pub2 = generate_keypair()
    tag = compute_hmac(DOC, KEY)
    wrong_sig = sign_document(DOC, priv2)
    assert verify_document(DOC, tag, wrong_sig, KEY, pub1) is False


def test_verify_document_fails_closed_on_malformed_tag():
    priv, pub = generate_keypair()
    sig = sign_document(DOC, priv)
    for bad_tag in [None, "not_bytes", 12345, b"", b"short"]:
        assert verify_document(DOC, bad_tag, sig, KEY, pub) is False


def test_replay_style_scenario_same_doc_reaccepted():
    priv, pub = generate_keypair()
    tag = compute_hmac(DOC, KEY)
    sig = sign_document(DOC, priv)
    first = verify_document(DOC, tag, sig, KEY, pub)
    replay = verify_document(DOC, tag, sig, KEY, pub)
    assert first is True
    assert replay is True


def test_verify_document_return_type_is_bool_not_truthy_string():
    priv, pub = generate_keypair()
    tag = compute_hmac(DOC, KEY)
    sig = sign_document(DOC, priv)
    bad_tag = compute_hmac(TAMPERED, KEY)

    genuine = verify_document(DOC, tag, sig, KEY, pub)
    forged = verify_document(DOC, bad_tag, sig, KEY, pub)

    assert isinstance(genuine, bool)
    assert isinstance(forged, bool)
    assert genuine is True
    assert forged is False
    assert bool(forged) is False


def test_verify_document_label_matches_bool_result():
    priv, pub = generate_keypair()
    tag = compute_hmac(DOC, KEY)
    sig = sign_document(DOC, priv)
    bad_tag = compute_hmac(TAMPERED, KEY)

    assert verify_document_label(DOC, tag, sig, KEY, pub) == "ACCEPTED"
    assert verify_document_label(DOC, bad_tag, sig, KEY, pub) == "REJECTED"


def test_size_limit_enforced():
    original = limits.MAX_DOCUMENT_SIZE
    limits.MAX_DOCUMENT_SIZE = 10
    try:
        oversized = b"x" * 11
        try:
            hash_document(oversized)
            assert False, "expected ValueError for oversized document"
        except ValueError:
            pass
    finally:
        limits.MAX_DOCUMENT_SIZE = original


def test_private_key_encrypted_roundtrip():
    priv, pub = generate_keypair()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "priv.pem")
        save_private_key(priv, path, b"correct horse battery staple")
        loaded = load_private_key(path, b"correct horse battery staple")
        sig = sign_document(DOC, loaded)
        assert verify_signature(DOC, sig, pub) is True


def test_private_key_wrong_passphrase_fails():
    priv, _pub = generate_keypair()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "priv.pem")
        save_private_key(priv, path, b"correct horse battery staple")
        try:
            load_private_key(path, b"totally wrong passphrase")
            assert False, "expected decryption to fail with wrong passphrase"
        except Exception:
            pass


def test_private_key_rejects_weak_passphrase():
    priv, _pub = generate_keypair()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "priv.pem")
        try:
            save_private_key(priv, path, b"short")
            assert False, "expected ValueError for a too-short passphrase"
        except ValueError:
            pass


def test_private_key_refuses_to_silently_overwrite():
    priv, _pub = generate_keypair()
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "priv.pem")
        save_private_key(priv, path, b"correct horse battery staple")
        try:
            save_private_key(priv, path, b"correct horse battery staple")
            assert False, "expected FileExistsError on second save to same path"
        except FileExistsError:
            pass


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    passed, failed = 0, 0
    for t in tests:
        try:
            t()
            print(f"PASS  {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL  {t.__name__}  {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")