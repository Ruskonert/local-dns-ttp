import pymysql
import socket

class DatabaseController:
    def __init__(self):
        self._conn = None
        self._sockets = {}
        self.cursor = None

    def initialize(self):
        self._conn = pymysql.connect(host='127.0.0.1', user='root', password='12345678', db='dns', charset='utf8')
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