# sender — Secure Document Exchange Sender

Sender-side implementation for the Secure Document Exchange System. This module builds anti-replay metadata bundles, binds them into canonical signing payloads, computes HMAC tags and RSA-PSS digital signatures using `crypto_core`, and securely transmits documents to the receiver.

> **CRITICAL NOTE:** `sender/bundle.py` must be shared verbatim with whoever builds the receiver or verification will never match.

---

## 1. Setup & Installation

From the repository root or the `sender/` directory:

```bash
pip install -r sender/requirements.txt
```

Only `cryptography` and `requests` are required.

---

## 2. One-Time Key Generation

Run `keygen.py` to generate the RSA keypair and symmetric HMAC key:

```bash
# From sender directory:
python keygen.py --sender-id alice

# Or from repository root:
python sender/keygen.py --sender-id alice
```

### Key Distribution Policy (Where Files Go):

| File | Destination | Security Rule |
|------|-------------|---------------|
| `alice_private.pem` | **LOCAL ONLY** | Stays on the sender machine. Saved with `chmod 600`. Never transmit! |
| `shared_hmac.key` | **LOCAL + OUT-OF-BAND** | Generated 32-byte secret. Stays local on sender AND handed to receiver **out-of-band** (never sent over the network with a document). |
| `alice_public.pem` | **OUT-OF-BAND** | Handed off to receiver out-of-band to verify RSA signatures. |

> **Security Rule:** Never send the private key (`alice_private.pem`) or the shared HMAC key (`shared_hmac.key`) over the network alongside a document.

---

## 3. Sending a Document

To send a file to the receiver endpoint:

```bash
python sender/sender_app.py <path-to-file> \
    --sender-id alice \
    --private-key alice_private.pem \
    --shared-key shared_hmac.key \
    --receiver-url https://receiver.example.com/api/receive
```

### Transmission Flow:
1. **Reads Document**: Loads the raw file bytes.
2. **Anti-Replay Metadata**: Reads/increments the strictly-increasing sequence number (`seq`, stored in `.seq_<sender_id>.json`), gets the current Unix timestamp, and generates a cryptographic nonce.
3. **Canonical Signing Payload**: Invokes `build_signing_payload()` to length-prefix all metadata fields before concatenating with raw document bytes, preventing field-boundary confusion.
4. **Crypto Core Integration**:
   - `hash_document_hex(document)`: Computes raw SHA-256 fingerprint for display and verification.
   - `compute_hmac(payload, shared_key)`: Computes HMAC-SHA256 tag over the canonical signing payload.
   - `sign_document(payload, private_key)`: Computes RSA-PSS signature over the canonical signing payload.
5. **JSON POST**: Sends `{ sender_id, filename, seq, timestamp, nonce, document_b64, document_sha256, tag_b64, signature_b64 }` to `--receiver-url`.
6. **Result Validation**: Prints the document SHA-256 and receiver JSON response. Exits with non-zero exit code if `status != "ACCEPTED"`.

---

## 4. Canonical Bundle Specification (`bundle.py`)

The receiver teammate must use the exact same payload framing defined in `sender/bundle.py`:

```
[4-byte big-endian len(sender_id)][sender_id UTF-8]
[4-byte big-endian len(filename) ][filename UTF-8]
[4-byte big-endian len(seq)      ][seq as ASCII/UTF-8 digits]
[4-byte big-endian len(timestamp)][timestamp as ASCII/UTF-8 digits]
[4-byte big-endian len(nonce)    ][nonce UTF-8]
[raw document bytes]
```

This guarantees byte-identical inputs to `crypto_core.verify_document()` on the receiver.
