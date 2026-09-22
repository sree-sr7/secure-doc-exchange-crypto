from .mac import verify_hmac
from .signatures import verify_signature


def verify_document(
    data: bytes,
    mac_tag: bytes,
    signature: bytes,
    shared_key: bytes,
    public_key,
) -> bool:
    if not verify_hmac(data, shared_key, mac_tag):
        return False
    return verify_signature(data, signature, public_key)


def verify_document_label(
    data: bytes,
    mac_tag: bytes,
    signature: bytes,
    shared_key: bytes,
    public_key,
) -> str:
    return "ACCEPTED" if verify_document(data, mac_tag, signature, shared_key, public_key) else "REJECTED"


def verify_document_verbose(
    data: bytes,
    mac_tag: bytes,
    signature: bytes,
    shared_key: bytes,
    public_key,
) -> dict:
    mac_ok = verify_hmac(data, shared_key, mac_tag)
    sig_ok = verify_signature(data, signature, public_key)
    return {
        "mac_valid": mac_ok,
        "signature_valid": sig_ok,
        "result": "ACCEPTED" if (mac_ok and sig_ok) else "REJECTED",
    }