"""
Usage:
    subdomain_finder.py --target=<arg> --wordlist=<arg> [--threads=<arg> --scan --uniq-ip]
    subdomain_finder.py --help
    subdomain_finder.py --version

Options:
    -h --help                          open help menu
    -v --version                       show version

Required options:
    --target='domain'                  your target =)
    --wordlist='list for brute force'  your favorite list of subdomains

Optional options:
    --threads=number of subdomais      how many subdomais test for threads [default: 100]
    --scan                             scan subdomains (nmap)
    --uniq-ip                          show list ips

"""

import threading
import socket

import nmap

import os
import sys
from docopt import docopt, DocoptExit



class myScan(threading.Thread):

    def __init__(self, target='localhost', param='', dict_domains={}):
        threading.Thread.__init__(self)
        self.target = target
        self.param = param
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
        
        scan_dict=nm.scan(self.target, self.param, arguments='-Pn -A')
        print("##############################")
        print("REPORT SCAN:")
        print("    IP: "+self.target)
        print("    OTHER SUB DOMAINS:")
        for domain, ip in self.dict_domains.items():
            if ip == self.target:
                print("           "+domain)

        try:
                for osmatch in nm[self.target]['osmatch']:
                    print('     OS:{0} - {1}%'.format(osmatch['name'], osmatch['accuracy']))
                    print('           OsClass.type : {0}'.format(osmatch['osclass'][0]['type']))
                    print('           OsClass.vendor : {0}'.format(osmatch['osclass'][0]['vendor']))
                    print('           OsClass.osfamily : {0}'.format(osmatch['osclass'][0]['osfamily']))
                    print('           OsClass.osgen : {0}'.format(osmatch['osclass'][0]['osgen']))
                    #print('           OsClass.accuracy : {0}%'.format(osmatch['osclass'][0]['accuracy']))
                     
        except:
            pass




class myTestDomain (threading.Thread):
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



def subdomain_finder(threads, wordlist, target):

    # Converting wordlist file to list
    wlist = [line.rstrip('\n')+'.'+target for line in open(wordlist)]

    len_chuck = int(threads)
    # chunks of wordlist
    chunks = [wlist[x:x+len_chuck] for x in range(0, len(wlist), len_chuck)]

    # start threads
    threads_domain = []
    for chunk in chunks:
        t=myTestDomain(chunk)
        t.start()
        threads_domain.append(t)

    dict_domain = {}
    for tw in threads_domain:
        if len(tw.join()) > 0:
            for domain, ip in tw.join().items():
                dict_domain[domain] = ip

    return dict_domain


def ip_scan(domains_ips):

    print('\n  SCAN... wait!')
    threads_scan = []
    for ip in ip_uniq(domains_ips):
        scan = myScan(ip, "0-65535", domains_ips)
        scan.start()
        threads_scan.append(scan)

    for ts in threads_scan:
        ts.join()


def ip_uniq(domains_ips):

    ips = {}
    for a, e in domains_ips.items():
        ips[e] = 1

    return ips

def banner():
        os.system('clear')
        print("\n")
        print("\033[32m\tMMP\"\"MM\"\"YMM `7MMF'     A     `7MF' db\"")
        print("\033[32m\tP'   MM   `7   `MA     ,MA     ,V  ;MM:     ")
        print("\033[33m\t     MM         VM:   ,VVM:   ,V  ,V^MM.    ")
        print("\033[33m\t     MM          MM.  M' MM.  M' ,M  `MM    ")
        print("\033[33m\t     MM          `MM A'  `MM A'  AbmmmqMA   ")
        print("\033[31m\t     MM           :MM;    :MM;  A'     VML  ")
        print("\033[31m\t   .JMML.          VF      VF .AMA.   .AMMA.\033[39m")
        print("\t\tTWA Corp. sub domain finder")
        print("\t           Use with NO moderation :D")
        print("\t             Third World Attacker\n")

def main():
    try:
        banner()
        arguments = docopt(__doc__, version="TWA Corp. SubDomain Finder - 2016")
        target = arguments['--target']
        wordlist = arguments['--wordlist']
        threads = arguments['--threads']
        opt_scan = arguments['--scan']
        opt_uniq_ips = arguments['--uniq-ip']

    except DocoptExit as e:
        banner()
        os.system('python3 subdomain_finder.py --help')
        sys.exit(1)

    domains_ips={}
    domains_ips = subdomain_finder(threads, wordlist, target)

    if opt_uniq_ips:
        print("\n  IPs:")
        ips = ip_uniq(domains_ips)
        print("    Uniq: "+str(len(ips)))
        for ip in ip_uniq(domains_ips):
            print("        "+ip)

    if opt_scan:
        ip_scan(domains_ips)

if __name__ == '__main__':
    main()

