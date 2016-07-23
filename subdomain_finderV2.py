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
    
     #TODO: Format output!
    def __init__(self,target='localhost',param='',dict_domains={}):
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
        
        scan_dict=nm.scan(self.target, self.param,arguments='-Pn -A')
        print ("##############################")
        print ("REPORT SCAN:")
        print ("    IP: "+self.target)        
        print("    OTHER SUB DOMAINS:")
        for domain, ip in self.dict_domains.items():
             if ip == self.target :
                  print("           "+domain)

        try:
                for osmatch in nm[self.target]['osmatch']:
                    print('     OS:{0} - {1}%'.format(osmatch['name'],osmatch['accuracy']))
                    print('           OsClass.type : {0}'.format(osmatch['osclass'][0]['type']))
                    print('           OsClass.vendor : {0}'.format(osmatch['osclass'][0]['vendor']))
                    print('           OsClass.osfamily : {0}'.format(osmatch['osclass'][0]['osfamily']))
                    print('           OsClass.osgen : {0}'.format(osmatch['osclass'][0]['osgen']))
                    #print('           OsClass.accuracy : {0}%'.format(osmatch['osclass'][0]['accuracy']))
                     
        except:
            pass
         

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
        opt_scan = arguments['--scan']
        opt_uniq-ips = arguments['--uniq-ip']

    except DocoptExit as e:
        banner()
        os.system('python3 subdomain_finder.py --help')
        sys.exit(1)


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
    
    dict_domain={}
    #waiting 
    for tw in threads_domain:
        if len(tw.join()) >0 :
            for domain,ip in tw.join().items():
                dict_domain[domain]=ip
                

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
        scan=myScan(ip,"0-65535",dict_domain)
        scan.start()
        threads_scan.append(scan)

    for ts in threads_scan:
        ts.join()

if __name__ == '__main__':
    main()
#END...
