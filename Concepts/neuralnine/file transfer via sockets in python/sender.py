import socket
import os

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((socket.gethostbyname(socket.gethostname()), 80))

print(f'{socket.gethostbyname(socket.gethostname())}')


file = open("virus.png", "rb")
filesize = os.path.getsize("virus.png")

client.send("virus_2.png".encode())
client.send(str(filesize).encode())

data = file.read()
client.sendall(data)
client.send(b'<END>')

file.close()
client.close()
