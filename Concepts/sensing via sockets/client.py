import socket

def discover_pi():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp_socket.bind(("", 37020))

    print("Listening for broadcasts...")
    while True:
        data, addr = udp_socket.recvfrom(1024)
        print(f"Discovered server: {data.decode()} at {addr[0]}")

if __name__ == "__main__":
    discover_pi()