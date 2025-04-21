#!/usr/bin/env python3
import struct
import socket
import json
import base64
import hashlib
import os

CHUNK_HEADER_SIZE = 4
PORT = 6000
RESPONSE_OK = b'ACK'
RESPONSE_ERR = b'ERR'

def recv_exact(connection: socket.socket, num_bytes: int) -> bytes:
    """Receive an exact number of bytes from the socket."""
    data = b''
    while len(data) < num_bytes:
        packet = connection.recv(num_bytes - len(data))
        if not packet:
            raise ConnectionError("Connection closed prematurely")
        data += packet
    return data

def receive_valid_packet(connection: socket.socket, index: int) -> bytes:
    """Receive and validate a packet until the checksum matches."""
    while True:
        header = recv_exact(connection, CHUNK_HEADER_SIZE)
        payload_length = struct.unpack('!I', header)[0]
        payload = recv_exact(connection, payload_length)

        packet = json.loads(payload.decode())
        decoded_data = base64.b64decode(packet['data'])
        checksum = packet['checksum']

        actual_checksum = hashlib.md5(decoded_data).hexdigest()
        if actual_checksum == checksum:
            connection.send(RESPONSE_OK)
            print(f"[+] Packet {index} received and verified.")
            return decoded_data
        else:
            connection.send(RESPONSE_ERR)
            print(f"[!] Checksum mismatch on packet {index}. Retrying...")
    
'''
/home/osaka/Documents/Shared/Ebuise/drift.txt
or
C:\Users\osaka\Documents\Shared\Ebuise\drift.txt
to
/home/raspberrypi/02/123456/Documents/Shared/Ebuise/drift.txt
'''
def format(path) -> str:
    path = path.replace('\\', '/')
    path = path.split('/')
    path = path[1:]
    path = '/'.join(path)

    # TODO look up ip_map to find mac_addr then userid then add into directory!!
    # DONE os.path.expanduser(path)
    path = os.path.expanduser(path)

    os.makedirs(os.path.dirname(path), exist_ok=True)
    return path

def receive_file(connection) -> None:
    metadata = recv_exact(connection, 1024).decode()
    packet_count = metadata['packet_count']
    path = metadata['path']
    formatted_path = format(path)
    print(f"[+] Expecting {packet_count} packets...")

    file_data = b''

    for index in range(packet_count): # 🧠
        data = receive_valid_packet(connection, index) # 🧠
        file_data += data # 🧠

    with open(formatted_path, 'wb') as f:
        f.write(file_data)

    print(f"[+] File '{formatted_path}' received successfully.")

def connect_to_server(host: str, port: int) -> socket.socket:
    """Connect to the server and return the socket."""
    # sock = socket.socket()
    # sock.connect((host, port))
    # print(f"[+] Connected to server at {host}:{port}")
    # return sock

    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(10)
    print(f"[+] Listening on {host}:{port}...")

    connection, addr = server_socket.accept() # accepted some device
    print(f"[+] Connection from {addr}")
    # with conn:
    #     print(f"[+] Connection from {addr}")
    return connection


def main():
    host = socket.gethostname()

    connection = connect_to_server(host, PORT)
    # with sock:
        # receive_file(filename, sock)
    receive_file(connection)

if __name__ == '__main__':
    main()
