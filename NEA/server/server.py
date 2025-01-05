# hosts file-server on raspberry pi.
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = socket.gethostname()
print(host)
s.bind((host, 1234))
s.listen(2)

while True:
    clientsocket, addr = s.accept()
    print(f"connected with {addr}")
    message = clientsocket.recv(1024)
    name = input("enter the file name u wanna store it as: ")
    file = open(name, "wb")
    file.write(message)
    file.close()
    clientsocket.close()