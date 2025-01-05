import socket

def wlan_ip():
    import subprocess
    result=subprocess.run('ipconfig',stdout=subprocess.PIPE,text=True).stdout.lower()
    scan=0
    for i in result.split('\n'):
        if 'wireless' in i: scan=1
        if scan:
            if 'ipv4' in i: return i.split(':')[1].strip()

IPADDRESS = wlan_ip() #usually 192.168.0.(DHCP assigned ip)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((IPADDRESS, 8000))
s.listen(5)

while True:
    clientsocket, address = s.accept()
    print(f"Connection from {address} has been established!")
    clientsocket.send(bytes("Welcome to the server!", "utf-8"))
    clientsocket.close()