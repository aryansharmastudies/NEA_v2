# anything you want to send things bigger than 1024 bytes, you need to buffer it.
# use a header to tell client how long the message is.
# whole point is once you know you are recieveing x number of characters, you know when to stop.

import socket
import time

host = '0.0.0.0'
port = 1234
HEADERSIZE = 10

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host, port))
s.listen(5)

while True:
    clientsocket, address = s.accept()
    print(f"Connection from {address} has been established!")

    msg = "Welcome to the server!"
    msg = f'{len(msg):<{HEADERSIZE}}' + msg
    print(msg)

    clientsocket.send(bytes(msg, "utf-8"))

    while True:
        time.sleep(3)
        msg = f"The time is {time.time()}"
        msg = f'{len(msg):<{HEADERSIZE}}'+ msg
        clientsocket.send(bytes(msg, "utf-8"))
