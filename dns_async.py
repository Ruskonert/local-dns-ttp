import asyncio
import random
import socket
import hashlib
import struct


class DnsAsyncTaskResponser:
    def __init__(self, db_service):
        self.result = []
        self._sockets = []
        self._service = db_service



    async def _internal_connect(self, req_data, addr):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sockets.append(sock)
        result = await sock.sendto(req_data, addr)
        return result



    def ttp_address_list(self):
        element_list = []
        for sql_element in self._service.get_ttp_list():
            element_list.append((sql_element[0], sql_element[1]))
        return element_list



    async def _start_dns_request(self, req_data, target_addr):
        functions = [asyncio.ensure_future(_internal_connect(req_data, addr)) for addr in self.ttp_address_list()]
        for fn in asyncio.as_completed(functions):
            async_sock_result = await fn
            self.result.append(fn)            

        # the result of ttp
        dns_response_data = None
        for result in self.result:
            if dns_response_data is None:
                dns_response_data = result[0]
            unpack_data =struct.unpack("!HHHHHH{}s".format(len(dns_response_data)-12), dns_response_data)
            # query answer & others
            queries = unpack_data[6]
            url = ""
            focus = 0
            total_url = ""
            while focus < len(queries):
                sub_length = queries[focus] + 1
                url = queries[focus+1:focus+sub_length]
                total_url += url.decode('utf-8') + "."
                focus += sub_length
            print(total_url[:-1] + " -> ")
            # Queires Type, Classes and Answers
            qna = struct.unpack("!HH{}s".format(len(queries) - 4), queries[focus:])

            # Seperate answers
            answer_part = qna[2]
            m = hashlib.sha256()
            m.update(answer_part)
            m.hexdigest()



    def start_dns_request(self, req_data, target_addr):
        task = asyncio.get_event_loop()
        task.run_until_complete(self._start_dns_request(self, req_data, target_addr))    
        task.close()
