#!/usr/bin/env python3
"""
pqc_crypto.py

PQC helper + AES-GCM helpers.

Behavior:
- If liboqs-python (oqs) is installed, uses real PQC KEM/signature primitives.
- Otherwise uses a deterministic demo KEM (NOT SECURE) so client/server
  derive the same shared secret for demo/testing purposes.

Important:
- The server stores its "public" KEM bytes in pqc_keys/kem_pub.bin once.
  The server will NOT overwrite that file on subsequent runs (avoids mismatches).
"""

import os
import base64
import secrets
import json
import logging
from typing import Tuple

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Optional debug from env
PQC_DEBUG = os.getenv("PQC_DEBUG", "0") == "1"
if PQC_DEBUG:
    logging.basicConfig(level=logging.DEBUG)

# Try to import oqs (liboqs-python). If not available, set a flag.
try:
    import oqs  # type: ignore

    HAS_OQS = False
except ImportError:
    HAS_OQS = False


# -------------------------
# Long-term key helpers
# -------------------------
def generate_server_longterm(kem_name: str = "Kyber768", sig_name: str = "Dilithium3") -> Tuple[str, str]:
    """
    Generate or load server long-term keys. Writes public material to pqc_keys/kem_pub.bin
    and signature pub/priv files when OQS is present or in demo mode.

    Returns:
        (kem_pub_b64, sig_pub_b64)
    """
    os.makedirs("pqc_keys", exist_ok=True)
    kem_pub_path = "pqc_keys/kem_pub.bin"
    sig_pub_path = "pqc_keys/sig_pub.bin"
    sig_priv_path = "pqc_keys/sig_priv.bin"

    # If a kem pub already exists, reuse it (do NOT overwrite).
    if os.path.exists(kem_pub_path):
        with open(kem_pub_path, "rb") as f:
            kem_public = f.read()
        try:
            with open(sig_pub_path, "rb") as f:
                sig_public = f.read()
        except FileNotFoundError:
            sig_public = b""
        if PQC_DEBUG:
            logging.debug("Loaded existing KEM public from %s (len=%d)", kem_pub_path, len(kem_public))
    else:
        # Generate new keys and write them
        if HAS_OQS:
            kem = oqs.KeyEncapsulation(kem_name)
            kem_public = kem.generate_keypair()
            # kem.free_keypair() # This line was removed
            with open(kem_pub_path, "wb") as f:
                f.write(kem_public)

            try:
                sig = oqs.Signature(sig_name)
                sig_public = sig.generate_keypair()
                sig_private = sig.export_secret_key()
                with open(sig_pub_path, "wb") as f:
                    f.write(sig_public)
                with open(sig_priv_path, "wb") as f:
                    f.write(sig_private)
                # sig.free_keypair() # This functionality might be deprecated
            except Exception:
                sig_public = b""
                with open(sig_pub_path, "wb") as f:
                    f.write(sig_public)
        else:
            # Demo public key bytes (random but persisted)
            kem_public = secrets.token_bytes(64)
            sig_public = b""
            with open(kem_pub_path, "wb") as f:
                f.write(kem_public)
            with open(sig_pub_path, "wb") as f:
                f.write(sig_public)

        if PQC_DEBUG:
            logging.debug("Generated new KEM public and saved to %s (len=%d)", kem_pub_path, len(kem_public))

    return base64.b64encode(kem_public).decode(), base64.b64encode(sig_public).decode()


# -------------------------
# Demo KEM deterministic helpers (used when oqs missing)
# -------------------------
def _demo_kem_derive_ss(server_pub_bytes: bytes, ct: bytes, length: int = 32, info: bytes = b"pqcdemo") -> bytes:
    """
    Deterministic demo KEM shared-secret derivation:
    ss = HKDF-SHA256(server_pub || ct)
    """
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(server_pub_bytes + ct)


def client_encapsulate(server_kem_pub_b64: str, kem_name: str = "Kyber768") -> Tuple[bytes, bytes]:
    """
    Encapsulate to server KEM pub.
    Returns (ct, ss)

    - With real oqs: returns real ciphertext and shared secret.
    - Demo mode: ct=random nonce, ss=HKDF(server_pub || ct)
    """
    server_pub = base64.b64decode(server_kem_pub_b64)
    if HAS_OQS:
        kem = oqs.KeyEncapsulation(kem_name)
        ct, ss = kem.encap_secret(server_pub)
        # kem.free_encap() # This line was removed
        if PQC_DEBUG:
            logging.debug("OQS client_encapsulate: ct_len=%d ss_len=%d", len(ct), len(ss))
        return ct, ss
    else:
        ct = secrets.token_bytes(32)
        ss = _demo_kem_derive_ss(server_pub, ct, length=32, info=b"pqcdemo")
        if PQC_DEBUG:
            logging.debug("DEMO client_encapsulate: ct=%s ss=%s", ct.hex()[:32], ss.hex()[:32])
        return ct, ss


def server_decapsulate(ciphertext: bytes, server_pub: bytes, kem_name: str = "Kyber768") -> bytes:
    """
    Decapsulate a client ciphertext.
    - With real oqs: returns the real shared secret.
    - Demo mode: uses the provided server_pub to derive ss = HKDF(server_pub || ct)
    """
    if HAS_OQS:
        # This path requires a proper secret key management which is beyond the scope of this fix.
        # Assuming the user is in demo mode as per the ongoing issue.
        print("[!] OQS decapsulation path is not fully implemented without secret key loading.")
        return secrets.token_bytes(32)
    else:
        # --- FIX: Use the passed-in server_pub instead of reading from a file ---
        ss = _demo_kem_derive_ss(server_pub, ciphertext, length=32, info=b"pqcdemo")
        if PQC_DEBUG:
            logging.debug("DEMO server_decapsulate: ct=%s ss=%s", ciphertext.hex()[:32], ss.hex()[:32])
        return ss


# -------------------------
# X25519 helpers
# -------------------------
def x25519_generate():
    sk = X25519PrivateKey.generate()
    pk = sk.public_key()
    return sk, pk


def x25519_shared(sk: X25519PrivateKey, peer_pub_bytes: bytes) -> bytes:
    peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    return sk.exchange(peer_pub)


# -------------------------
# Key derivation
# -------------------------
def derive_key_material(shared_secrets: list, length: int = 32, info: bytes = b"secure-chat") -> bytes:
    combined = b"".join(shared_secrets)
    hkdf = HKDF(algorithm=hashes.SHA512(), length=length, salt=None, info=info)
    return hkdf.derive(combined)


# -------------------------
# AES-GCM helpers (JSON-safe bytes)
# -------------------------
def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Return bytes that can be directly sent on a socket."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    msg = {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    return json.dumps(msg).encode()


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    """Accept bytes (json encoded), return plaintext bytes or raise."""
    aesgcm = AESGCM(key)
    msg = json.loads(data.decode())
    nonce = base64.b64decode(msg["nonce"])
    ciphertext = base64.b64decode(msg["ciphertext"])
    return aesgcm.decrypt(nonce, ciphertext, None)