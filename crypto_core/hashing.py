import hashlib
from .limits import check_size


def hash_document(data: bytes) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError("hash_document expects bytes")
    check_size(data)
    return hashlib.sha256(data).digest()


def hash_document_hex(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise TypeError("hash_document_hex expects bytes")
    check_size(data)
    return hashlib.sha256(data).hexdigest()