import socket
import time

def broadcast_pi():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    message = "RaspberryPiServer_02"

    try:
        while True:
            udp_socket.sendto(message.encode(), ("<broadcast>", 37020))
            print("Broadcasting presence...")
            time.sleep(1)  # Send broadcasts every 1 second
    except KeyboardInterrupt:
        print("Broadcast stopped.")
    finally:
        udp_socket.close()

if __name__ == "__main__":
    broadcast_pi()
