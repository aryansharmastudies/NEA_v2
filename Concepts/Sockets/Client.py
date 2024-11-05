import socket, time

host = '192.168.56.1'
port = 2323

socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
socket.connect((host, port)) # sends a connection request to the server.

socket.send("Hello, Server!".encode('utf-8'))
print(socket.recv(1024).decode('utf-8'))
