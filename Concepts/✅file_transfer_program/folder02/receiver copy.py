#!/usr/bin/env python3
import struct
import socket
import json
import base64
import hashlib

CHUNK_HEADER_SIZE = 4
PORT = 6969
RESPONSE_OK = b'ACK'
RESPONSE_ERR = b'ERR'

def recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """Receive an exact number of bytes from the socket."""
    data = b''
    while len(data) < num_bytes:
        packet = sock.recv(num_bytes - len(data))
        if not packet:
            raise ConnectionError("Connection closed prematurely")
        data += packet
    return data

def receive_valid_chunk(sock: socket.socket, index: int) -> bytes:
    """Receive and validate a packet until the checksum matches."""
    while True:
        header = recv_exact(sock, CHUNK_HEADER_SIZE)
        payload_length = struct.unpack('!I', header)[0]
        payload = recv_exact(sock, payload_length)

        packet = json.loads(payload.decode())
        decoded_chunk = base64.b64decode(packet['data'])
        checksum = packet['checksum']

        actual_checksum = hashlib.md5(decoded_chunk).hexdigest()
        if actual_checksum == checksum:
            sock.send(RESPONSE_OK)
            print(f"[+] Packet {index} received and verified.")
            return decoded_chunk
        else:
            sock.send(RESPONSE_ERR)
            print(f"[!] Checksum mismatch on packet {index}. Retrying...")

def receive_file(filename: str, sock: socket.socket) -> None:
    """Receives all packets and writes to file."""
    packet_count = int(recv_exact(sock, 10).decode())
    print(f"[+] Expecting {packet_count} packets...")

    file_data = b''
    for index in range(packet_count):
        chunk = receive_valid_chunk(sock, index)
        file_data += chunk

    with open(filename, 'wb') as f:
        f.write(file_data)

    print(f"[+] File '{filename}' received successfully.")

def connect_to_server(host: str, port: int) -> socket.socket:
    """Connect to the server and return the socket."""
    sock = socket.socket()
    sock.connect((host, port))
    print(f"[+] Connected to server at {host}:{port}")
    return sock

def main():
    host = socket.gethostname()
    filename = input("Enter filename to save as: ").strip()

    with connect_to_server(host, PORT) as sock:
        receive_file(filename, sock)

if __name__ == '__main__':
    main()
