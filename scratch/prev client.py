import socket
import os
#THE SHIT THAT WAS ON PREV CLIENT.PY
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = input("host name?")
s.connect((host, 1234))

def convert_to_binary(file_name = "text"):
    r = open(f"{file_name}.txt", "rb") # read byte mode
    data = r.read()
    return data

data = convert_to_binary()
s.send(data)