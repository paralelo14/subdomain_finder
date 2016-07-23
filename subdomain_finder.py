"""
Usage:
    subdomain_finder.py --target=<arg> --wordlist=<arg> [--threads=<arg>]
    subdomain_finder.py --help
    subdomain_finder.py --version

Options:
    -h --help                          open help menu
    -v --version                       show version

Required options:
    --target='domain'                  your target =)
    --wordlist='list for brute force'  your favorite list of subdomains

Optional options:
    --threads=number of subdomais      how many subdomais test for threads

"""
import threading
import socket

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException

import os
import sys
from docopt import docopt, DocoptExit


class myScan(threading.Thread):
    
     #TODO: Format output!
    def __init__(self,target='localhost',param='',dict_domains={}):
        threading.Thread.__init__(self)
        self.target = target
        self.param = param
        self.dict_domains = dict_domains
    
    def run(self):
         report = self.scan_do(self.target, self.param)
         if report:
             self.scan_print(report)
         else:
             print("\n SCAN: No results returned for "+self.target)
          

    def scan_do(self,targets, options):
         parsed = None
         nmproc = NmapProcess(targets, options)
         rc = nmproc.run()
         if rc != 0:
             print("\n SCAN: failed, {0}".format(nmproc.stderr))
         #print(type(nmproc.stdout))
         try:
             parsed = NmapParser.parse(nmproc.stdout)
         except NmapParserException as e:
             print("\n SCAN: Exception raised while parsing scan: {0}".format(e.msg))
     
         return parsed
     
     
    def scan_print(self,nmap_report):
         
         for host in nmap_report.hosts:
             if len(host.hostnames):
                 tmp_host = host.hostnames.pop()
             else:
                 tmp_host = host.address

             print("##########################################")
             print("SCAN REPORT FOR {0} ({1})".format(tmp_host,host.address))
             print("    OTHER SUB DOMAINS:")
             for domain, ip in self.dict_domains.items():
                  if ip == host.address :
                      print("           "+domain)
             
             #print("    STATUS HOST: {0}.".format(host.status))
             print("    PORTS:")
             print("          PORT     STATE         SERVICE")
     
             for serv in host.services:
                 pserv = "        {0:>5s}/{1:3s}  {2:12s}  {3}".format(
                         str(serv.port),
                         serv.protocol,
                         serv.state,
                         serv.service)
                 if len(serv.banner):
                     pserv += " ({0})".format(serv.banner)
                 print(pserv)
     
             if host.os_fingerprinted:
                 print("\n    OS FINGERPRINT:")
                 msg = ''
                 for osm in host.os.osmatches:
                     print("        Found Match:{0} ({1}%)".format(osm.name, osm.accuracy))
                     #for osc in osm.osclasses:
                     #    print("\tOS Class: {0}".format(osc.description))
                     #    for cpe in osc.cpelist:
                     #        print("\tCPE: {0}".format(cpe.cpestring))
             else:
                 print("\n    OS FINGERPRINT: No fingerprint available")
             print("##########################################")





class myTestDomain (threading.Thread):
    def __init__(self,bDomain):
        threading.Thread.__init__(self)
        self.bDomain = bDomain
        self.dict_return={}
    
    def run(self):
        for domain in self.bDomain:
            temp=self.finder(domain)
            if temp is not None:
                self.dict_return[domain]=temp
    
    def join( self ):
        threading.Thread.join( self )
        return self.dict_return

    def finder(self, target):
            try:
                ip = socket.gethostbyname(target)
                if ip: 
                        print("{0:65s} - {1}".format(target,ip))
                        return ip
            except:
                        pass
    







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
        arguments = docopt(__doc__, version="TWA Corp. SubDomain Finder - 2016")
        target = arguments['--target']
        wordlist = arguments['--wordlist']
        threads = arguments['--threads']

    except DocoptExit as e:
        banner()
        os.system('python3 subdomain_finder.py --help')
        sys.exit(1)


    # Converting wordlist file to list
    wlist = [line.rstrip('\n')+'.'+target for line in open(wordlist)]
    
    # number of targets per thread
    len_chuck=10
    # chunks of wordlist
    chunks = [wlist[x:x+len_chuck] for x in range(0, len(wlist), len_chuck)]


    # start threads
    threads_domain = []
    for chunk in chunks:
        t=myTestDomain(chunk)
        t.start()
        threads_domain.append(t)
    
    dict_domain={}
    #waiting 
    for tw in threads_domain:
        if len(tw.join()) >0 :
            for domain,ip in tw.join().items():
                dict_domain[domain]=ip
                
    for curr in db.all('id'):
        print(curr)

    print ("\n  IPs:")
    ips = {}
    for a,e in dict_domain.items():
        ips[e] = 1

    print ("    Uniq: "+str(len(ips)))
    for ip in ips.keys():
        print("        "+ip)
    

    print('\n  SCAN... wait!')
    threads_scan = []
    for ip in ips.keys():
        scan=myScan(ip,"-sV -A -Pn ",dict_domain)
        scan.start()
        threads_scan.append(scan)

    for ts in threads_scan:
        ts.join()

if __name__ == '__main__':
    main()
#END...
