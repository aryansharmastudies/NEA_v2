import socket
import os

gw = os.popen("ip -4 route show default").read().split()
wireless_ipv4 = gw[-3]
hostname = socket.gethostname()
addrinfo = socket.gethostbyname(hostname)
port = int(input("enter port number. "))

print(f"gw: {wireless_ipv4}")
print(f"hostname: {hostname}")
print(f"addrinfo: {addrinfo}")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((wireless_ipv4, port))
s.listen()

while True:
    print()
    print("listening...")
    client_socket, client_addr = s.accept()
    print(f"connection made with {client_addr}")

