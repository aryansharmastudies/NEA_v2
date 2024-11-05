import socket
import requests
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
# s.bind((socket.getaddrinfo(), 1234))

# https://icanhazip.com returns the public IPv6 address of the server.
response = requests.get('https://icanhazip.com')
print(response.text)
ipv6_address = response.text.strip()
print(f"My public IPv6 address is: {ipv6_address}")