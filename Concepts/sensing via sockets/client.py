import socket


def discover_pi():

    servers = []

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp_socket.bind(("", 37020))

    print("Listening for broadcasts...")
    while True:
        data, addr = udp_socket.recvfrom(1024)
        if data.decode() not in servers:
            servers.append(data.decode())
        # print(f"Discovered server: {data.decode()} at {addr[0]}")
        print(servers)

if __name__ == "__main__":
    discover_pi()