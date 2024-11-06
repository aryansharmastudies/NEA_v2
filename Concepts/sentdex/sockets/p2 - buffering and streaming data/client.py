import socket

HEADERSIZE = 10

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((socket.gethostbyname(socket.gethostname()), 2))

# print(f'{socket.gethostbyname(socket.gethostname())}') # NOTE: This is the same as '0.0.0.0' on the server side.

while True:

    full_msg = ''
    new_msg = True
    while True:
        msg = s.recv(16)
        if new_msg:
            print(f"new message length: {msg[:HEADERSIZE].decode('utf-8')}") # NOTE: String slicing to get the header of the new_msg informing us about the length of the message.
            msglen = int(msg[:HEADERSIZE])
            new_msg = False

        full_msg += msg.decode('utf-8')

        if len(full_msg) - HEADERSIZE == msglen:
            print("full message recvd")
            print(full_msg[HEADERSIZE:])
            new_msg = True
            full_msg = '' # empty the full_msg variable for the next message.

    print(full_msg)