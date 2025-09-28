#!/usr/bin/env python3
"""
Two-way PQC secure chat server (one-to-one).
Now with ngrok auto-tunnel for remote connections.
"""

import socket
import struct
import threading
import subprocess
import time
import requests
import base64
from pqc_crypto import (
    generate_server_longterm,
    server_decapsulate,
    x25519_generate,
    x25519_shared,
    derive_key_material,
    aes_encrypt,
    aes_decrypt
)
from cryptography.hazmat.primitives import serialization

HOST = "0.0.0.0"
PORT = 5050

# --- length-prefixed helpers ---
def send_msg(conn: socket.socket, data: bytes):
    conn.sendall(struct.pack(">I", len(data)) + data)

def recv_msg(conn: socket.socket) -> bytes:
    header = b''
    while len(header) < 4:
        chunk = conn.recv(4 - len(header))
        if not chunk:
            return b''
        header += chunk
    msglen = struct.unpack(">I", header)[0]
    data = b''
    while len(data) < msglen:
        chunk = conn.recv(min(4096, msglen - len(data)))
        if not chunk:
            return b''
        data += chunk
    return data

def receive_loop(conn: socket.socket, key: bytes, peer_name: str):
    try:
        while True:
            data = recv_msg(conn)
            if not data:
                print("\n[*] Connection closed by peer.")
                break
            try:
                plain = aes_decrypt(key, data).decode()
                print(f"\n[{peer_name}]: {plain}\nServer: ", end="", flush=True)
            except Exception as e:
                print(f"\n[!] Decryption error: {repr(e)}")
                break
    except Exception as e:
        print(f"[!] Receive loop error: {e}")

def send_loop(conn: socket.socket, key: bytes):
    try:
        while True:
            msg = input("Server: ")
            if msg.strip().lower() in ("q", "exit", "/exit"):
                print("[*] Shutting down send loop.")
                break
            packet = aes_encrypt(key, msg.encode())
            send_msg(conn, packet)
    except Exception as e:
        print(f"[!] Send loop error: {e}")

def start_ngrok():
    """Start ngrok TCP tunnel on PORT and return public address"""
    try:
        # Launch ngrok in background
        print("[*] Starting ngrok tunnel...")
        ngrok_process = subprocess.Popen(["ngrok", "tcp", str(PORT)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)  # wait for tunnel to initialize

        # Query ngrok local API to get the public URL
        resp = requests.get("http://127.0.0.1:4040/api/tunnels")
        resp.raise_for_status()
        tunnels_json = resp.json()
        
        for tunnel in tunnels_json["tunnels"]:
            if tunnel.get("proto") == "tcp":
                public_url = tunnel["public_url"]
                return public_url
        
        print("[!] No TCP tunnel found in ngrok API response.")
        return None
    except requests.exceptions.ConnectionError:
        print("[!] Failed to connect to ngrok API. Is ngrok running?")
        return None
    except Exception as e:
        print(f"[!] An error occurred while starting ngrok: {e}")
        return None

def run_server():
    print("[+] Starting PQC Secure Chat Server...")

    public_addr = start_ngrok()
    if public_addr:
        print(f"[+] Share this address with your friend: {public_addr}")
    else:
        print("[!] Ngrok tunnel not available. Server will be local LAN only.")

    # Load the long-term KEM public key once at startup.
    kem_pub_b64, _ = generate_server_longterm()
    # Decode it once to get the raw bytes
    kem_pub_bytes = base64.b64decode(kem_pub_b64)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(1)
    print(f"[+] Listening on {HOST}:{PORT} ... (waiting for a client)")

    conn, addr = sock.accept()
    print(f"[+] Connection from {addr}")

    # Generate X25519 keys *after* connection for a fresh session key.
    sk, pk = x25519_generate()
    
    # Handshake
    username_bytes = recv_msg(conn)
    if not username_bytes:
        print("[!] No username received; closing.")
        conn.close(); sock.close(); return
    username = username_bytes.decode()
    print(f"[+] Authenticated user: {username}")

    send_msg(conn, kem_pub_b64.encode())
    ct = recv_msg(conn)
    
    # --- FIX: Pass the kem_pub_bytes directly to the function ---
    ss = server_decapsulate(ct, kem_pub_bytes)
    
    client_pk_bytes = recv_msg(conn)
    
    send_msg(conn, pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))

    shared = x25519_shared(sk, client_pk_bytes)
    key = derive_key_material([ss, shared])

    # (debugging code)
    #print("\n--- SERVER-SIDE KEYS ---")
    #print(f"PQC Shared Secret (ss): {ss.hex()}")
    #print(f"X25519 Shared Secret:   {shared.hex()}")
    #print(f"Final Derived Key:      {key.hex()}")
    #print("--------------------------\n")
    
    print("[+] Secure channel established. You can chat now. Type 'q' to quit.")

    recv_t = threading.Thread(target=receive_loop, args=(conn, key, username), daemon=True)
    recv_t.start()

    send_loop(conn, key)

    print("[*] Closing connection.")
    conn.close()
    sock.close()
    print("[+] Server stopped.")

if __name__ == "__main__":
    run_server()