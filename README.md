# crypto_core — Team 1 (Core Crypto Build)

Four functions the whole Secure Document Exchange System depends on:
hashing, HMAC, signing, verification. No networking or app logic lives
here — that's Integration/Infra's job once this is QA-signed-off.

## Setup

```bash
pip install cryptography
```

## Quick usage

```python
import os
from crypto_core import (
    hash_document_hex, compute_hmac, generate_keypair,
    sign_document, verify_document,
)

document = b"contents of the file being sent"
shared_key = os.urandom(32)          # exchanged out-of-band beforehand
private_key, public_key = generate_keypair()

# Sender side
tag = compute_hmac(document, shared_key)
signature = sign_document(document, private_key)
# -> send (document, tag, signature) as a bundle

# Receiver side
result = verify_document(document, tag, signature, shared_key, public_key)
print(result)  # "ACCEPTED" or "REJECTED"
```

## Run the self-tests

```bash
python tests/test_crypto_core.py
```

## Hardening decisions (read this before your Design Report / Phase 2)

| Risk on the attack checklist | How this module closes it |
|---|---|
| HMAC implemented as `hash(secret + message)` | Uses `hmac.new()` — the real RFC 2104 construction, immune to length-extension |
| Timing attack on tag/signature comparison | `hmac.compare_digest()` (constant-time), never `==` |
| DSA/ECDSA nonce reuse leaking the private key | Uses RSA-PSS instead — no secret per-signature nonce to reuse |
| Weak RSA padding (PKCS1v15 quirks) | Uses PSS padding (modern, provably secure) |
| Private key exposure | `save_private_key()` chmods the file `600`; only the **public** key goes in the Phase 2 handoff package |
| Verifier silently passing on partial failure | `verify_document()` always evaluates both checks and ANDs them — never short-circuits |

## Known gap — flag this, don't hide it

This module does **not** stop replay of an old, genuine, unmodified
bundle (a captured valid message resent as-is will still verify
`ACCEPTED`, since nothing here is unique per-send). That's covered in
`tests/test_crypto_core.py::test_replay_style_scenario_same_doc_reaccepted`
with an explanation. Replay defense (sequence number or timestamp,
tracked and rejected on reuse by the receiver) belongs in
Integration/Infra, layered on top of this module — make sure it's in
their build and in the Design Report, or it's a free point for the
opposing team.
