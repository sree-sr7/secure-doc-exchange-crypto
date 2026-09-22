import os
import subprocess
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from .limits import check_size


def generate_keypair(key_size: int = 3072) -> tuple[RSAPrivateKey, RSAPublicKey]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key


def sign_document(data: bytes, private_key: RSAPrivateKey) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError("sign_document expects bytes")
    check_size(data)
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(data: bytes, signature: bytes, public_key: RSAPublicKey) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def _restrict_windows_acl(path: str) -> None:
    user = os.environ.get("USERNAME")
    if not user:
        return
    try:
        subprocess.run(
            ["icacls", path, "/inheritance:r", "/grant:r", f"{user}:F"],
            capture_output=True,
            check=True,
            timeout=5,
        )
    except Exception:
        pass


def _write_restricted(path: str, data: bytes) -> None:
    if os.path.exists(path):
        raise FileExistsError(f"{path} already exists")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except Exception:
        os.close(fd)
        raise
    if os.name == "nt":
        _restrict_windows_acl(path)


def save_private_key(private_key: RSAPrivateKey, path: str, passphrase: bytes) -> None:
    if not passphrase or len(passphrase) < 8:
        raise ValueError("passphrase must be at least 8 bytes")
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )
    _write_restricted(path, pem)


def save_public_key(public_key: RSAPublicKey, path: str) -> None:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as f:
        f.write(pem)


def load_private_key(path: str, passphrase: bytes) -> RSAPrivateKey:
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=passphrase)


def load_public_key(path: str) -> RSAPublicKey:
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())