import sys
import socket
import quic

def main(argc, argv):
    if argc == 1:
        print("Usuge:")
        print("client.py <TTP_DNS_ADDRESS> <PORT>")
    else:
        dns_addr = sys.argv[1]
        port = int(sys.argv[2])
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


if __name__ == "__main__":
    main(len(sys.argv), sys.argv)