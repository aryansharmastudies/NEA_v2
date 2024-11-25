import socket
import os

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('192.168.1.108', 1234))

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
