# sender/web — Browser UI for the Sender

A small Flask app that puts a web page in front of the exact same
sender-side flow as `sender/sender_app.py` (the CLI is untouched and still
works). Nothing here modifies `crypto_core/`, `sender_app.py`, `bundle.py`,
or `keygen.py` — it only imports the existing functions.

## Run it

```bash
pip install -r sender/requirements.txt
python sender/web/app.py
```

Open **http://127.0.0.1:5000**.

- Set a different port: `PORT=8080 python sender/web/app.py`
- Enable Flask's auto-reload/debug mode while developing: `FLASK_DEBUG=1 python sender/web/app.py`

## Pages

- **Send Document** (`/`) — upload the file to send, the sender's private
  key `.pem`, the shared HMAC key file, and the receiver URL. Submitting
  builds the same length-prefixed anti-replay payload as the CLI, computes
  the SHA-256 fingerprint / HMAC tag / RSA-PSS signature, POSTs the JSON
  bundle to the receiver, and shows the result (accepted/rejected, the
  receiver's response, and the exact request body that was sent).
- **Generate Keys** (`/keys`) — generates an RSA-PSS keypair + 32-byte
  shared HMAC key in memory (same material `keygen.py` produces) and lets
  you download each file from the browser. Nothing is written to disk on
  the server.

## Notes

- Uploaded document bytes and key material live only in the request's
  memory; they are not persisted anywhere on the server.
- Per-sender sequence numbers (used for anti-replay, same mechanism as the
  CLI) are persisted under `sender/web/state/.seq_<sender_id>.json`. Set
  `SENDER_WEB_STATE_DIR` to point this somewhere else, e.g. the same folder
  the CLI uses, if you want the two to share one counter per sender.
- This UI (like the underlying protocol) provides integrity, authenticity,
  and non-repudiation — not confidentiality. The document body is
  base64-transported, not symmetrically encrypted, so it is still readable
  by anyone who intercepts the request. If Phase 2 requires confidentiality
  too, that needs to be added on top of this deliberately.
