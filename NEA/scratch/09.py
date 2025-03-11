import socket 

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ip = '192.168.1.221'
port = 6000
s.bind((ip, port))
s.listen(5)
print(f"Listening on {ip}:{port}")
