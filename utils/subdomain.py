# coding: utf-8
import threading
import socket

__author__ = 'contato318'


class ThSubdomain (threading.Thread):

    def __init__(self, bDomain):
        threading.Thread.__init__(self)
        self.bDomain = bDomain
        self.dict_return = {}

    def run(self):
        for domain in self.bDomain:
            temp = self.finder(domain)
            if temp is not None:
                self.dict_return[domain] = temp

    def join(self):
        threading.Thread.join(self)
        return self.dict_return

    def finder(self, target):
            try:
                ip = socket.gethostbyname(target)
                if ip:
                        print("{0:65s} - {1}".format(target, ip))
                        return ip
            except:
                        pass

