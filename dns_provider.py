import socket
import struct
import os
import sys
import threading
import dns_service

from datetime import date, time, datetime

class DnsRecordType:
    @staticmethod
    def get_type(dec):
        types = {
            1: "A",
            28: "AAAA (Ipv6)",
            5: "CHAME",
            6: "SOA",
            15: "MX",
            16: "TXT",
            12: "PTR",
            }
        record_name = types.get(dec, "Unknown")
        return record_name, dec

    @staticmethod
    def get_class(dec):
        classes = {
            0: "Reserved",
            1: "Internet",
            2: "Unassigned",
            3: "Chaos (CH)",
            4: "Hesiod (HS)"
        }
        class_name = classes.get(dec, "Unknown")
        return class_name, dec

class Sniffer:
    dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    def __init__(self):
        self._threads = []
        self._running = True
        self._work = threading.Thread(target=Sniffer._internal_service, args=[self,])
    
    def _internal_service(self):
        for thread in self._threads:
            if not thread.is_alive():
                self._threads.remove(thread)

    @staticmethod
    def translate_to_url(pack):
        try:
            pack = pack[:-5]
            total_url = ''
            focus = 0
            while focus < len(pack):
                sub_length = pack[focus] + 1
                url = pack[focus+1:focus+sub_length]
                total_url += url.decode('utf-8') + "."
                focus += sub_length
            return total_url[:-1]
        except:
            return "Malformed packet!"
    
    def kill(self):
        self._running = False

    def output_dns_info(self, data):
        try:
            for i in range(0, len(data)):
                print("{:02x}".format(data[i]), end=' ')
                if (i + 1) % 16 == 0:
                    print()

            print("\nRESULT: ")
            data_unpack = struct.unpack("!HHHHHH{}s".format(len(data) - 12), data)
            dns_queries_info = data_unpack[-1]

            sep = len(dns_queries_info)
            dns_queries_type = dns_queries_info[sep-4:sep]
            dns_type, dns_class = struct.unpack("!HH", dns_queries_type)
            dns_record_type = DnsRecordType.get_type(dns_type)
            dns_class_type = DnsRecordType.get_class(dns_class)

            print("Transaction id: 0x{:04X}".format(data_unpack[0]))
            print("Flags: 0x{:04X}".format(data_unpack[1]))
            print("Questions: {:x}".format(data_unpack[2]))

            print("Answer RRs: {:x}".format(data_unpack[3]))
            print("Authority RRs: {:x}".format(data_unpack[4]))
            print("Additional RRs: {:x}".format(data_unpack[5]))

            print("Query Type: {} (0x{:04X})".format(dns_record_type[0], dns_record_type[1]))
            print("Query Class: {} (0x{:04X})".format(dns_class_type[0], dns_class_type[1]))
            print("Request Domain: {}".format(Sniffer.translate_to_url(dns_queries_info)))
        except struct.error:
            print("warning: Malformed packet or unregistered format -> ignored")

    def await_dns_packet(self, ip_addr, port, service):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv_address = (ip_addr, int(port))
        sock.bind(recv_address)
        while True:
            # Capturing packet data, which types 'DNS'
            data, addr = sock.recvfrom(65535)
            print("\n[{}] -> {}:{}".format(str(datetime.now()), addr[0], addr[1]))

            # Output the information about packet
            self.output_dns_info(data)
            def _internal():
                provider = dns_service.DnsQueryProviderTask()
                resp_information = provider.request_dns_response(data)
                for k in resp_information.keys():
                    sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock2.sendto(resp_information[k][0], addr)
                    sock2.close()
            threading.Thread(target=_internal).start()


