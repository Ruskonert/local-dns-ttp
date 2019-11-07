import pymysql

class DatabaseController:
    def __init__(self):
        self._conn = None
        self.cursor = None

    def initialize(self):
        self._conn = pymysql.connect(host='127.0.0.1', user='root', password='12345678', db='dns', charset='utf8')
        self.cursor = self._conn.cursor()
        return self
        
    def execute(self, sql, args):
        self.cursor.execute(sql, args)

    def get_result(self, all=True):
        if all:
            return self.cursor.fetchall()
        else:
            return self.cursor.fetchone()