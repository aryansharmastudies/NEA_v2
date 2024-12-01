import socket
ip = input("enter ip you want to connect to. ")
port = input("enter port you want to connect to. ")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((ip,int(port)))
print("Connection Succesful")
