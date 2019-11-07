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
        if len(_database_controller.get_ttp_list()) == 0:
            print("[Warning] No provided TTP server, Generating default TTP server ...")
            _database_controller.insert_ttp_list("1.1.1.1", "Cloudflare DNS", "-")
            _database_controller.insert_ttp_list("8.8.8.8", "Google Public DNS", "-")
            _database_controller.insert_ttp_list("9.9.9.9", "IBM Quad9 DNS", "-")

        print("Loading TTP(Trusted-Third Party) server list ...")
        data_list = _database_controller.get_ttp_list()
        if len(data_list) == 0:
            raise OperationalError("Internal error, TTP list is empty!")
        _database_controller.configure_ttp(True)
    else:
        from pymysql import OperationalError
        raise OperationalError("Connecting the database was failed")
    
    sniffer = dns_provider.Sniffer()
    sniffer.await_dns_packet(addr[0], addr[1], _database_controller)

def start_program():
    print("  _____  _   _  _____ _______ _______ _____ ")
    print(" |  __ \| \ | |/ ____|__   __|__   __|  __ \\")
    print(" | |  | |  \| | (___    | |     | |  | |__) |")
    print(" | |  | | . ` |\___ \   | |     | |  |  ___/ ")
    print(" | |__| | |\  |____) |  | |     | |  | |     ")
    print(" |_____/|_| \_|_____/   |_|     |_|  |_| ")
    print("DNS TTP(Third-Trusted Party) provider by Ruskonert@gmail.com")
    print("For capstone project.")
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