import socket
import os

gw = os.popen("ip -4 route show default").read().split()
print(f"gw: {gw}")

# ********* Variables *********
auto_host0 = socket.gethostname() # automatically get host name of the server.
print(f"auto_host0: {auto_host0}")
auto_host1 = socket.gethostbyname(socket.gethostname()) # automatically get IP address of the server. 
print(f"auto_host1: {auto_host1}")
auto_host2 = '0.0.0.0'# automatically get IP address of the server.
# NOTE autohost_1 and autohost_2 return the same.
x = "192.168.1.108"
specific_host = '192.168.1.75' # specify private IP address.
print(f"automatic host: {auto_host1}")

port = 1999 # specify port number.

# ********** Server **********

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # NOTE connect to the internet, use TCP. This socket is just for accepting communication, not for individual connections to clients.
server.bind((gw[-3], port)) # by binding to IP, it makes clear its server, 9999 is port Note: IP is private IP, not public.

server.listen(5) # listen for connections, 5 is the maximum number of connections.

while True: # accept connection, unconditionally so we accept all connections.
    
    communication_socket, address = server.accept() # NOTE return value for server.accept() is another socket object and address of client its connecting to.
    print(f"Connection from {address} has been established!") # print address of client that connected to server.
    
    message = communication_socket.recv(1024).decode('utf-8') # receive message from client, 1024 is buffer size. Note, decode is different to decrypt, there is no encryption here. Decode is to convert byte stream to string.
    print(f"Message from client: {message}")
    
    communication_socket.send("Message received, Thank you!".encode('utf-8')) # send message to client, encode is to convert string to byte stream.
    
    communication_socket.close()
    print(f"Connection from {address} has been closed!") # close connection with client.
    