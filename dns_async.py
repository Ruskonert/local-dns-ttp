import asyncio
import random
import socket
import hashlib
import time
import struct
from concurrent.futures import ThreadPoolExecutor


class DnsAsyncTaskResponser:
    def __init__(self, db_service):
        self.result = []
        self._sockets = []
        self._service = db_service
        self.hash_list = []



    @staticmethod
    async def _internal_connect(target, req_data, addr, timeout=1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        def _execute():
            sock.sendto(req_data, (addr[0], 53))
            sock.settimeout(timeout)
            try:
                return sock.recvfrom(65535)
            except socket.timeout:
                return b'Timeout', (addr[0], 53)
        async_loop = asyncio.get_event_loop()
        start_time = time.time()
        result = await async_loop.run_in_executor(None, _execute)
        end_time = time.time()
        target._sockets.append(sock)

        result_list = list(result) 
        result_list.append(round((end_time - start_time) * 1000, 1))
        return result_list



    @staticmethod
    async def _start_dns_request(target, req_data):
        functions = [asyncio.ensure_future(DnsAsyncTaskResponser._internal_connect(target, req_data, addr)) for addr in target.ttp_address_list()[1:]]
        for fn in asyncio.as_completed(functions):
            async_sock_result = await fn
            target.result.append(async_sock_result)
        for e in target._sockets:
            e.close()



    def ttp_address_list(self):
        element_list = []
        for sql_element in self._service.get_ttp_list():
            element_list.append((sql_element[0], sql_element[1]))
        return element_list
 

    @staticmethod
    async def calculate_dns_hash(result_element):
        def _execute(data):
            m = hashlib.sha256()
            m.update(data)
            result_hash = m.hexdigest()
            return result_hash

        unpack_data = struct.unpack("!HHHHHH{}s".format(len(result_element[0])-12), result_element[0])

        # query answer & others.
        # but the important part is pack 6.
        queries = unpack_data[6]
        focus = 0
        url = ""
        total_url = ""
        while queries[focus] != 0x00:
            end_length = queries[focus] + 1
            url = queries[focus+1:focus+end_length]
            total_url += url.decode('utf-8') + '.'
            focus += end_length            
        # Queries Type, Classes and Answers
        # qna[0] = Queries type
        # qna[1] = Queries classes
        # qna[2] = Answers (detailed)
        qna = struct.unpack("!HH{}s".format(len(queries[focus+1:]) - 4), queries[focus+1:])
        result_hash = _execute(qna[2][15:])
        print("{}ms : [{}:{}] -> {}".format(result_element[2], result_element[1][0], result_element[1][1], result_hash))
        return result_hash



    async def validate_result(self):
        def check_expired_data():
            # the result of ttp
            # result configuration:
            # result[0] -> TTP Responsed data
            # result[1] -> (ip_address, port(53))
            # result[2] -> period time to response TTP
            results = []
            for result_element in self.result:
                if result_element[0] == b'Timeout':
                    print("-----> warning! {}ms : [{}:{}] -> NO RESPONSING!".format(result_element[2], result_element[1][0], result_element[1][1]))
                else:
                    results.append(result_element)
            return results

        functions = [asyncio.ensure_future(DnsAsyncTaskResponser.calculate_dns_hash(data)) for data in check_expired_data()]
        for function in asyncio.as_completed(functions):
            result_hash = await function
            self.hash_list.append(result_hash)



    def start_dns_request(self, req_data, target_addr):
        start_time = time.time()
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(DnsAsyncTaskResponser._start_dns_request(self, req_data))
        loop.close()
        # task is ended, so socket will close & clear.
        for sock in self._sockets:
            sock.close()
            self._sockets.clear()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(DnsAsyncTaskResponser.validate_result(self))
        loop.close()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(self.result[0][0], target_addr)
        end_time = time.time()
        print("Elapsed time about all tasks -> [{}:{}]: {}ms".format(target_addr[0], target_addr[1], round((end_time - start_time) * 1000, 1)))