# Secure Chat App with Face Login (PQC Hybrid)

This project is a college mini-project demo that implements a secure chat application protected by:

- Face recognition login (OpenCV + face_recognition)
- Hybrid key-exchange combining Post-Quantum KEM (Kyber) + Ephemeral X25519 for forward secrecy
- Server authentication via PQC signatures (Dilithium if available)
- AES-256-GCM for message encryption (derived via HKDF-SHA512)

This package contains demo-ready Python scripts. liboqs (liboqs-python) is required for real PQC algorithms; if it is not present the scripts will fall back to a simulated KEM (for demo only).

## Files
- register_face.py        -- capture face images to faces/
- face_login.py           -- authenticate user using faces/
- pqc_crypto.py           -- helper functions for KEM, ECDH, signatures, HKDF, AES-GCM (uses liboqs if available)
- server_pqc.py           -- server that performs PQC handshake and relays encrypted messages
- client_pqc.py           -- client that does face login, PQC handshake, then encrypted chat
- auto_demo.py            -- demo: register + login + chat start
- presentation.pptx       -- a simple presentation slide (cover)
- requirements.txt        -- pip installable deps
- faces/                  -- folder for face images (empty)

## Quick start (example)
1. Create virtualenv and activate it:
   python3 -m venv venv
   source venv/bin/activate

2. Install dependencies (liboqs-python may require build tools):
   pip install -r requirements.txt

3. Register face:
   python register_face.py

4. Start server (in one terminal):
   python server_pqc.py

5. Run client (in another terminal):
   python client_pqc.py

Notes:
- If `liboqs` is not installed, the scripts use a **simulated** KEM and will still demonstrate the handshake flow, but they will NOT be post-quantum secure. For an actual PQC demo, install liboqs-python as described in the README.
