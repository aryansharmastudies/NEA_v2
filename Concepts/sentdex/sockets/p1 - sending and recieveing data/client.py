import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((socket.gethostname(), 1234))

full_message = ''
while True: # buffer size is 8 bytes.
    msg = s.recv(8)
    if len(msg) <= 0: # or else it will keep waiting for more data.
        break
    full_message += msg.decode('utf-8')
print(full_message)