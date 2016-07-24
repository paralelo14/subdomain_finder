# coding: utf-8
import threading
import nmap
import sys

__author__ = 'contato318'


class ThScan(threading.Thread):

    def __init__(self, target='localhost', ports="20-1024", options="-Pn -T5 -A", dict_domains={}):
        threading.Thread.__init__(self)
        self.target = target
        self.options = options
        self.port = ports
        self.dict_domains = dict_domains

    def run(self):
        self.scan()

    def scan(self):
        try:
           nm = nmap.PortScanner()         # instantiate nmap.PortScanner object
        except nmap.PortScannerError:
            print('SCAN: Nmap not found', sys.exc_info()[0])
            sys.exit(0)
        except:
            print("SCAN: Unexpected error:", sys.exc_info()[0])
            sys.exit(0)

        scan_dict = nm.scan(self.target, ports=self.port, arguments=self.options)
        print("##############################")
        print("REPORT SCAN: ")
        print("    IP: "+self.target)

        # List other sub domains of target
        print("    OTHER SUB DOMAINS:")
        for domain, ip in self.dict_domains.items():
            if ip == self.target:
                print("           "+domain)

        # OS details
        try:
                for osmatch in nm[self.target]['osmatch']:
                    print('     OS:{0} - {1}%'.format(osmatch['name'], osmatch['accuracy']))
                    print('           OsClass: {0}|{1}|{2}|{3}|{4}|{5}%'.format(
                                                           osmatch['osclass'][0]['type'],
                                                           osmatch['osclass'][0]['vendor'],
                                                           osmatch['osclass'][0]['osfamily'],
                                                           osmatch['osclass'][0]['osgen'],
                                                           osmatch['osclass'][0]['osgen'])
                         )


        except:
            pass

        # TODO: port details, services, etc...
        try:
            for proto in nm[self.target].all_protocols():
                print('        -----PORTS-----')
                print('        Protocol : %s' % proto)

                lport = list(nm[self.target][proto].keys())
                lport.sort()
                for port in lport:
                    print('        PORT : %s\tSTATE : %s' % (port, nm[self.target][proto][port]['state']))

        except:
            pass

