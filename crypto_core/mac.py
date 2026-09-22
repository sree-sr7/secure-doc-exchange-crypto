import hmac
import hashlib
from .limits import check_size


def compute_hmac(data: bytes, key: bytes) -> bytes:
    if not isinstance(data, bytes) or not isinstance(key, bytes):
        raise TypeError("compute_hmac expects bytes for both data and key")
    if len(key) < 16:
        raise ValueError("HMAC key should be at least 16 bytes (128 bits)")
    check_size(data)
    return hmac.new(key, data, hashlib.sha256).digest()


def verify_hmac(data: bytes, key: bytes, tag: bytes) -> bool:
    try:
        expected = compute_hmac(data, key)
        return hmac.compare_digest(expected, tag)
    except (TypeError, ValueError):
        return False