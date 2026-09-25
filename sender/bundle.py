"""
sender/bundle.py - Canonical Signing Payload Builder and Anti-Replay Metadata

Specification & Format Docstring:
---------------------------------
Both sender and receiver MUST construct byte-identical signing payloads for
HMAC computation and RSA-PSS signature verification.

To prevent replay attacks and field-boundary confusion, anti-replay metadata
fields are length-prefixed and bound to the document BEFORE hashing, MACing,
or signing.

Payload Framing:
    [4-byte BE len(sender_id)][sender_id UTF-8 bytes]
    [4-byte BE len(filename) ][filename UTF-8 bytes]
    [4-byte BE len(seq)      ][seq as ASCII/UTF-8 digits]
    [4-byte BE len(timestamp)][timestamp as ASCII/UTF-8 digits]
    [4-byte BE len(nonce)    ][nonce UTF-8 bytes]
    [raw document bytes]

Field Definitions:
    1. sender_id: String identifying the sending party (e.g., 'alice').
    2. filename:  String basename of the file being transmitted (e.g., 'doc.pdf').
    3. seq:       Strictly-increasing integer sequence number persisted per sender.
    4. timestamp: Unix epoch timestamp in integer seconds.
    5. nonce:     Random string/hex token uniquely generated per transmission.
    6. document:  Raw bytes of the document being protected.

Porting Note:
    Any receiver implementation (in Python or any other language) must unpack or
    reconstruct the payload using:
      - 32-bit unsigned big-endian integer length prefix (">I" in struct) for
        each of the 5 metadata fields in order:
        sender_id, filename, seq, timestamp, nonce.
      - Followed directly by the raw document bytes.
"""

from __future__ import annotations

import json
import os
import struct
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Tuple

# Ensure crypto_core is importable regardless of working directory
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

try:
    from crypto_core.limits import check_size
except ImportError:
    check_size = None


@dataclass(frozen=True)
class Metadata:
    """Anti-replay metadata bound into the canonical signing payload."""
    sender_id: str
    filename: str
    seq: int
    timestamp: int
    nonce: str

    def to_dict(self) -> dict[str, Any]:
        """Convert metadata to a serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Metadata":
        """Reconstruct Metadata dataclass from a dictionary."""
        return cls(
            sender_id=str(data["sender_id"]),
            filename=str(data["filename"]),
            seq=int(data["seq"]),
            timestamp=int(data["timestamp"]),
            nonce=str(data["nonce"]),
        )


def _encode_length_prefixed_field(val: Any, field_name: str) -> bytes:
    """Encode a single field into bytes prefixed with a 4-byte big-endian length."""
    if isinstance(val, bytes):
        raw = val
    elif isinstance(val, str):
        raw = val.encode("utf-8")
    elif isinstance(val, int):
        raw = str(val).encode("utf-8")
    else:
        raise TypeError(f"Field '{field_name}' must be str, int, or bytes; got {type(val).__name__}")

    if len(raw) > 0xFFFFFFFF:
        raise ValueError(f"Field '{field_name}' length ({len(raw)}) exceeds 4-byte limit")

    return struct.pack(">I", len(raw)) + raw


def build_signing_payload(document: bytes, metadata: Metadata) -> bytes:
    """
    Construct the canonical byte-identical signing payload binding metadata to document.

    Args:
        document: Raw document bytes.
        metadata: Metadata dataclass containing sender_id, filename, seq, timestamp, nonce.

    Returns:
        Canonical payload bytes:
        [len(sender_id)][sender_id] + [len(filename)][filename] +
        [len(seq)][seq] + [len(timestamp)][timestamp] + [len(nonce)][nonce] +
        document_bytes
    """
    if not isinstance(document, bytes):
        raise TypeError(f"document must be bytes, got {type(document).__name__}")
    if not isinstance(metadata, Metadata):
        raise TypeError(f"metadata must be an instance of Metadata, got {type(metadata).__name__}")

    if check_size is not None:
        check_size(document)

    if not metadata.sender_id:
        raise ValueError("metadata.sender_id must not be empty")
    if not metadata.filename:
        raise ValueError("metadata.filename must not be empty")
    if not isinstance(metadata.seq, int) or metadata.seq < 0:
        raise ValueError("metadata.seq must be a non-negative integer")
    if not isinstance(metadata.timestamp, int) or metadata.timestamp <= 0:
        raise ValueError("metadata.timestamp must be a positive integer (unix epoch seconds)")
    if not metadata.nonce:
        raise ValueError("metadata.nonce must not be empty")

    prefix_sender = _encode_length_prefixed_field(metadata.sender_id, "sender_id")
    prefix_filename = _encode_length_prefixed_field(metadata.filename, "filename")
    prefix_seq = _encode_length_prefixed_field(metadata.seq, "seq")
    prefix_timestamp = _encode_length_prefixed_field(metadata.timestamp, "timestamp")
    prefix_nonce = _encode_length_prefixed_field(metadata.nonce, "nonce")

    return prefix_sender + prefix_filename + prefix_seq + prefix_timestamp + prefix_nonce + document


def parse_signing_payload(payload: bytes) -> Tuple[Metadata, bytes]:
    """
    Parse a canonical signing payload back into (Metadata, document_bytes).
    Useful for receiver validation and unit tests.
    """
    if not isinstance(payload, bytes):
        raise TypeError(f"payload must be bytes, got {type(payload).__name__}")

    offset = 0
    raw_fields = []
    field_names = ["sender_id", "filename", "seq", "timestamp", "nonce"]

    for name in field_names:
        if offset + 4 > len(payload):
            raise ValueError(f"Payload truncated: cannot read 4-byte length prefix for '{name}'")
        (length,) = struct.unpack_from(">I", payload, offset)
        offset += 4
        if offset + length > len(payload):
            raise ValueError(f"Payload truncated: cannot read {length} bytes for field '{name}'")
        raw_fields.append(payload[offset : offset + length])
        offset += length

    try:
        sender_id = raw_fields[0].decode("utf-8")
        filename = raw_fields[1].decode("utf-8")
        seq = int(raw_fields[2].decode("utf-8"))
        timestamp = int(raw_fields[3].decode("utf-8"))
        nonce = raw_fields[4].decode("utf-8")
    except Exception as e:
        raise ValueError(f"Corrupted metadata in signing payload: {e}") from e

    document = payload[offset:]
    return (
        Metadata(
            sender_id=sender_id,
            filename=filename,
            seq=seq,
            timestamp=timestamp,
            nonce=nonce,
        ),
        document,
    )


# Sequence number local persistence per sender_id


def get_seq_file_path(sender_id: str, state_dir: str | Path | None = None) -> Path:
    """Return the filesystem path for the sequence persistence file for sender_id."""
    if state_dir is None:
        target_dir = Path(".")
    else:
        target_dir = Path(state_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    safe_id = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in sender_id)
    return target_dir / f".seq_{safe_id}.json"


def get_current_seq(sender_id: str, state_dir: str | Path | None = None) -> int:
    """Read the last sequence number recorded for sender_id, or 0 if uninitialized."""
    seq_file = get_seq_file_path(sender_id, state_dir)
    if not seq_file.is_file():
        return 0
    try:
        with open(seq_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return int(data.get("last_seq", 0))
    except Exception:
        return 0


def get_next_seq(sender_id: str, state_dir: str | Path | None = None) -> int:
    """
    Atomically get and increment the strictly-increasing sequence number for sender_id.
    Persisted locally so that it survives application restarts.
    """
    seq_file = get_seq_file_path(sender_id, state_dir)
    current_seq = get_current_seq(sender_id, state_dir)
    next_seq = current_seq + 1

    temp_file = seq_file.with_name(f"{seq_file.name}.tmp.{os.getpid()}")
    state_data = {
        "sender_id": sender_id,
        "last_seq": next_seq,
    }
    with open(temp_file, "w", encoding="utf-8") as f:
        json.dump(state_data, f, indent=2)

    # Atomic rename/replace to prevent corruption on crash
    temp_file.replace(seq_file)
    return next_seq
