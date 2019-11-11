import pymysql
import socket
import threading

from multiprocessing.pool import ThreadPool

class DnsQueryProviderTask:
    def __init__(self, db_controller=None):
        # The multiprocessing pool
        self._pool = None

        self._manager = None

        # The thread task for multiprocessing
        self._main = None
        # Delegate for elements, which equals Database Controller
        self._db_controller = DatabaseController().initialize()
        # main thread is running?
        self._running = True
        # TTP UDP sockets
        self._sockets = []
        # The results of TTP response about sending the query data
        self.results = {}
        # DNS query, it equals the request data of DNS query
        self._req = None



    def force_terminate(self):
        self._running = False



    def terminate(self):
        if len(self._sockets) == 0:
            return
        else:
            for socket in self._sockets:
                socket.close()
        if self._pool is not None:
            self._pool.terminate()
            self._pool = None   
        if self._main.is_alive():
            self._main.join()
            self._main = None


    @staticmethod
    def _async_dns_response(target, ip_addr, dns_name, hash):
        new_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        target._sockets.append(new_socket)
        new_socket.sendto(target._req, (ip_addr, 53))
        recv_data = new_socket.recvfrom(65535)
        target.results[dns_name] = recv_data
        new_socket.close()



    # This method only use for multi-processing, Please don't call this method directly!
    # Use request_dns_response function.
    def _request_dns_response(self, dns_query_data, elements):
        if len(elements) == 0:
            return
        if dns_query_data is None:
            raise ValueError("DNS query data is null, What does TTP Server checks trusting address?")
        self._req = dns_query_data
        self._pool = ThreadPool(processes=len(elements))
        self._pool.daemon = True
        for e in elements:
            self._pool.apply_async(DnsQueryProviderTask._async_dns_response, args=(self, e[0], e[1], e[2]))
        self._pool.close()
        self._pool.join()



    def request_dns_response(self, dns_query_data):
        elements = self._db_controller.get_ttp_list()
        self._main = threading.Thread(target=self._request_dns_response, args=(dns_query_data, elements,))
        self._main.start()
        while self._running and self._main.is_alive():
            if len(self.results) >= len(elements):
                break
        self.terminate()
        return self.results
        



class DatabaseController:
    def __init__(self):
        self._conn = None
        self._sockets = {}
        self.cursor = None



    def initialize(self):
        self._conn = pymysql.connect(host='127.0.0.1', user='root', password='1234', db='dns', charset='utf8')
        self.cursor = self._conn.cursor()
        return self
        


    def _execute(self, sql, args):
        self.cursor.execute(sql, args)
        self._conn.commit()



    def get_ttp_list(self, table_name="ttp_list"):
        self._execute("SELECT * FROM {}".format(table_name), None)
        return self._get_result()



    def insert_ttp_list(self, ip_addr, dns_name, hash, table_name="ttp_list"):
        sql = "insert into {}(ip_addr, dns_name, hash) values".format(table_name)
        self._execute(sql + "(%s,%s,%s)", (ip_addr, dns_name, hash))



    def _debug(self, noisy, message):
        if noisy:
            print(message)



    def configure_ttp(self, noisy=False):
        for ttp_element in self.get_ttp_list():
            ip_addr = ttp_element[0]
            dns_name = ttp_element[1]
            hash = ttp_element[2]
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._sockets[(ip_addr, dns_name)] = sock
                self._debug(noisy, "Generated task to request to the DNS Server [{}:{}]".format(dns_name, ip_addr))
            except Exception as e:
                print(e)
                self._debug(noisy, "[Warning] Can't connect server [{}:{}]".format(dns_name, ip_addr))
            


    def _get_result(self, all=True):
        if all:
            return self.cursor.fetchall()
        else:
            return self.cursor.fetchone()