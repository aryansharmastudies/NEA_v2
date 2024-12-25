import socket

def broadcast_pi():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp_socket.settimeout(0.2)
    message = "RaspberryPiServer"
    
    try:
        while True:
            udp_socket.sendto(message.encode(), ("<broadcast>", 37020))
            print("Broadcasting presence...")
    except KeyboardInterrupt:
        print("Broadcast stopped.")
    finally:
        udp_socket.close()

if __name__ == "__main__":
    broadcast_pi()
