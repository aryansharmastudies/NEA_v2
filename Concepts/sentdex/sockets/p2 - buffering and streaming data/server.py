# anything you want to send things bigger than 1024 bytes, you need to buffer it.
# use a header to tell client how long the message is.
# whole point is once you know you are recieveing x number of characters, you know when to stop.

import socket
import time

host = '0.0.0.0'
host_2 = socket.gethostbyname(socket.gethostname())
print(host_2)
port = 80
HEADERSIZE = 10

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host_2, port))
s.listen(5)

while True:
    clientsocket, address = s.accept()
    print(f"Connection from {address} has been established!")

    msg = "Welcome to the server!"
    msg = f'{len(msg):<{HEADERSIZE}}' + msg
    print(msg)

    clientsocket.send(bytes(msg, "utf-8"))

    while True:
        time.sleep(0.5)
        msg = f"The time is {time.time()}"
        msg = f'{len(msg):<{HEADERSIZE}}'+ msg
        clientsocket.send(bytes(msg, "utf-8"))
