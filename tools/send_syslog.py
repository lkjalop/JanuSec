import socket
import sys

def send_udp(host: str, port: int, message: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message.encode(), (host, port))
    sock.close()

def send_tcp(host: str, port: int, message: str):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.sendall((message + "\n").encode())
    sock.close()

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: send_syslog.py udp|tcp host port \"message\"")
        sys.exit(2)
    proto = sys.argv[1]
    host = sys.argv[2]
    port = int(sys.argv[3])
    msg = sys.argv[4]
    if proto == "udp":
        send_udp(host, port, msg)
    else:
        send_tcp(host, port, msg)
