# Secure Document Receiver (API & Web Dashboard)

This is the receiver half of the Secure Document Exchange System. It provides an HTTP endpoint (`/receive`) for senders to securely submit documents, and a web dashboard (`/`) to monitor and review the verification status (ACCEPTED / REJECTED) of all incoming transfers.

## Features

- **Integrity & Authenticity Check**: Verifies the HMAC-SHA256 tag using a pre-shared key.
- **Non-Repudiation Check**: Verifies the RSA-PSS digital signature using the sender's public key.
- **Replay Protection**: Enforces strictly increasing sequence numbers per sender to reject replayed bundles.
- **Web Dashboard**: View transaction logs natively in the browser.
- **Safe Storage**: Safely stores valid documents inside the `docs/` folder.

## Setup

1. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Establish keys out-of-band:
   The receiver needs the shared HMAC key and the sender's public key. These must be placed in the `keys/` directory. If the directory does not exist, run the app once or create it manually:
   - `keys/shared_hmac.key`: Must match the symmetric key used by the sender.
   - `keys/<sender_id>_public.pem`: The RSA public key belonging to `<sender_id>`.

## Running the Receiver

Start the Flask application:
```bash
python app.py
```

- **Dashboard:** Open [http://127.0.0.1:5001/](http://127.0.0.1:5001/) to view incoming transfers.
- **API:** Senders should post their JSON bundles to `http://127.0.0.1:5001/receive`.
