#!/usr/bin/env python3
"""
Two-way PQC secure chat client (one-to-one).
Performs face authentication, PQC+X25519 handshake, then runs receiver thread + send loop.
"""

import socket
import struct
import threading
from face_login import authenticate
from pqc_crypto import (
    client_encapsulate,
    x25519_generate,
    x25519_shared,
    derive_key_material,
    aes_encrypt,
    aes_decrypt
)
from cryptography.hazmat.primitives import serialization

# --- CONFIG ---
# Paste your ngrok address here. Example: "tcp://0.tcp.in.ngrok.io:16841"
NGROK_ADDR = "tcp://0.tcp.in.ngrok.io:13075"


def parse_ngrok(addr: str):
    """
    Parse ngrok tcp address of form tcp://host:port into (host, int(port)).
    """
    if addr.startswith("tcp://"):
        addr = addr.replace("tcp://", "")
    parts = addr.split(":")
    if len(parts) != 2:
        raise ValueError(f"Invalid ngrok address: {addr}")
    host, port = parts[0], int(parts[1])
    return host, port


SERVER, PORT = parse_ngrok(NGROK_ADDR)

# --- length-prefixed helpers ---
def send_msg(s: socket.socket, data: bytes):
    s.sendall(struct.pack(">I", len(data)) + data)


def recv_msg(s: socket.socket) -> bytes:
    header = b''
    while len(header) < 4:
        chunk = s.recv(4 - len(header))
        if not chunk:
            return b''
        header += chunk
    msglen = struct.unpack(">I", header)[0]
    data = b''
    while len(data) < msglen:
        chunk = s.recv(min(4096, msglen - len(data)))
        if not chunk:
            return b''
        data += chunk
    return data


def receive_loop(sock: socket.socket, key: bytes):
    try:
        while True:
            data = recv_msg(sock)
            if not data:
                print("\n[*] Connection closed by server.")
                break
            try:
                plain = aes_decrypt(key, data).decode()
                print(f"\nServer: {plain}\nYou: ", end="", flush=True)
            except Exception as e:
                print(f"\n[!] Failed to decrypt server message: {repr(e)}")
                break
    except Exception as e:
        print(f"[!] Receive loop error: {e}")


def send_loop(sock: socket.socket, key: bytes):
    try:
        while True:
            msg = input("You: ")
            if msg.strip().lower() in ("q", "exit", "/exit"):
                print("[*] Quitting send loop.")
                break
            packet = aes_encrypt(key, msg.encode())
            send_msg(sock, packet)
    except Exception as e:
        print(f"[!] Send loop error: {e}")


def run_client():
    username = authenticate()
    if not username:
        print("Face authentication failed. Exiting.")
        return

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[*] Connecting to {SERVER}:{PORT} ...")
    s.connect((SERVER, PORT))

    # Step 1: send username
    send_msg(s, username.encode())

    # Step 2: receive server KEM pub
    server_kem_pub_b64 = recv_msg(s).decode()
    ct, ss = client_encapsulate(server_kem_pub_b64)

    # Step 3: send ciphertext (ct)
    send_msg(s, ct)

    # Step 4: send client's X25519 pub
    sk, pk = x25519_generate()
    send_msg(s, pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))

    # Step 5: receive server X25519 pub
    server_pk_bytes = recv_msg(s)
    shared = x25519_shared(sk, server_pk_bytes)
    key = derive_key_material([ss, shared])

    # --- DEBUGGING CODE ---
    # print(f"PQC Shared Secret (ss): {ss.hex()}")
    #print(f"X25519 Shared Secret:   {shared.hex()}")
    #print(f"Final Derived Key:      {key.hex()}")
    #print("--------------------------\n")
    # --- END OF DEBUGGING CODE ---

    print("[+] Secure channel established. Start chatting! Type 'q' to quit.")

    recv_t = threading.Thread(target=receive_loop, args=(s, key), daemon=True)
    recv_t.start()

    send_loop(s, key)

    print("[*] Closing connection.")
    s.close()


if __name__ == "__main__":
    run_client()