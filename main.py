import os
import sys
import dns_provider
import threading

from dns_service import DatabaseController

_packet_capture_thread = None
_database_controller = None

def _execute_thread(addr):
    if addr is None:
        raise ValueError("'addr' is non-nullable")
    if not isinstance(addr, (tuple, list, set)):
        raise TypeError("'addr' must iterable-type")

    print("Connecting TTP list database ...")

    _database_controller = DatabaseController().initialize()
    if _database_controller is not None:
        print("Connected TTP list database!")
    else:
        from pymysql import OperationalError
        raise OperationalError("Connecting the database was failed")
    
    sniffer = dns_provider.Sniffer()
    sniffer.await_dns_packet(addr[0], addr[1])

def start_program():
    print("  _____  _   _  _____ _______ _______ _____ ")
    print(" |  __ \| \ | |/ ____|__   __|__   __|  __ \\")
    print(" | |  | |  \| | (___    | |     | |  | |__) |")
    print(" | |  | | . ` |\___ \   | |     | |  |  ___/ ")
    print(" | |__| | |\  |____) |  | |     | |  | |     ")
    print(" |_____/|_| \_|_____/   |_|     |_|  |_| ")
    print("DNS TTP(Third-Trusted Party) provider")
    print("==========================")

def main(argc : int, argv : list):
    if argc == 1:
        print("You need to input an argument(s).")
        print("Usuge: main.py <target_ip> [port=53]")
    else:
        if argc >= 2:
            port = int(argv[2])
        else:
            port = 53
        ipaddr = argv[1]
        addr = (ipaddr, port)
        _packet_capture_thread = threading.Thread(target=_execute_thread, args=[addr,])
        _packet_capture_thread.start()

if __name__ == "__main__":
    start_program()
    main(len(sys.argv), sys.argv)