#!/usr/bin/env python3
import hashlib
import socket
import struct
import json
import base64
from pathlib import Path

CHUNK_SIZE = 1024
PORT = 6969
HEADER_SIZE = 4
RESPONSE_OK = b'ACK'
RESPONSE_ERR = b'ERR'

def encode_file_chunks(filepath: str, chunk_size: int = CHUNK_SIZE) -> list:
    with open(filepath, 'rb') as f:
        file_data = f.read()

    chunks = [file_data[i:i + chunk_size] for i in range(0, len(file_data), chunk_size)]

    return [
        {
            "index": i,
            "data": base64.b64encode(chunk).decode(),
            "checksum": hashlib.md5(chunk).hexdigest()
        }
        for i, chunk in enumerate(chunks)
    ]

def send_packet(conn: socket.socket, packet: dict) -> None:
    payload = json.dumps(packet).encode()
    header = struct.pack('!I', len(payload))
    message = header + payload

    while True:
        conn.sendall(message)
        response = conn.recv(3)
        if response == RESPONSE_OK:
            print(f"Packet {packet['index']} transmitted successfully.")
            break
        print(f"Packet {packet['index']} failed checksum, retrying...")

def start_server(filename: str, port: int = PORT) -> None:
    packets = encode_file_chunks(filename)

    with socket.socket() as server_socket:
        host = socket.gethostname()
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"[+] Listening on {host}:{port}...")

        conn, addr = server_socket.accept()
        with conn:
            print(f"[+] Connection from {addr}")
            packet_count = len(packets)
            conn.sendall(f'{packet_count:<5}'.encode())  # 5-byte padded count

            for packet in packets:
                send_packet(conn, packet)

            print("[+] All packets sent.")

def main():
    filename = input("Enter file name to send: ").strip()
    if not Path(filename).is_file():
        print(f"[!] File '{filename}' not found.")
        return
    start_server(filename)

if __name__ == '__main__':
    main()
