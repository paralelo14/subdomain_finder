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
    --threads=number of threads       how many evil threads

"""
import os
from queue import Queue
import sys
import socket
import threading
import time

from docopt import docopt, DocoptExit

class SubDomainFinder:

    @staticmethod
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

    def finder(self, q):
        while True:
            target = q.get()
            try:
            	ip = socket.gethostbyname(target)
            	if ip:
            		print(target+' ----> '+ip)
            except:
            		q.task_done()
            		pass
            q.task_done()

    def finder_function(self, target, wordlist, threads):
        # If no value passed on threads, default will be 15
        if not threads:
            threads=50
        threads = int(threads)

        # Converting wordlist file to list
        wlist = [line.rstrip('\n')+'.'+target for line in open(wordlist)]

        # My Queue
        q = Queue(maxsize=0)

        self.banner()
        print('\033[31m[###] ATENTION [###]\033[39m')
        print('- Results can change on each execution..')
        print('- So run with 10, 25, ..., 50, 100, 150, ... threads.\n')
        print('[*] Starting evil threads..\n')

        # Preparing evil threads =)
        for i in range(threads):
            t = threading.Thread(target=self.finder, args=(q,))
            t.daemon = True
            t.start()

        # Preparing target queue
        for word in wlist:
            q.put(word)

        q.join()

def main():
    try:
        arguments = docopt(__doc__, version="TWA Corp. SubDomain Finder - 2016")
        target = arguments['--target']
        wordlist = arguments['--wordlist']
        threads = arguments['--threads']

    except DocoptExit as e:
        SubDomainFinder.banner()
        os.system('python3 subdomain_finder.py --help')
        sys.exit(1)

    f = SubDomainFinder()
    f.finder_function(target,wordlist,threads)

if __name__ == '__main__':
    main()