# -*- coding: utf-8 -*-
"""
Find subdomains using brute force.
There is the option of running automatic scan using nmap - to discover operating systems, we recommend running as administrator or root.


Usage:
    subdomain_finder.py --target=<arg> --wordlist=<arg> [--threads=<arg>  --whois --scan  --scan-ports=<arg>  --scan-options=<arg>  --uniq-ip]
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
    --whois                            get "whois" information
    --scan-ports='20-443'              ports
    --scan-options='-Pn -T5 -A'        scan option style nmap [default: '-Pn -T5 -A']
    --uniq-ip                          show list ips

"""


import whois
import os
import sys
from docopt import docopt, DocoptExit

from utils import scan_host, subdomain


def subdomain_finder(threads, wordlist, target):

    # Converting wordlist file to list
    wlist = [line.rstrip('\n')+'.'+target for line in open(wordlist)]

    len_chuck = int(threads)
    # chunks of wordlist
    chunks = [wlist[x:x+len_chuck] for x in range(0, len(wlist), len_chuck)]

    # start threads
    threads_domain = []

    for chunk in chunks:
        t = subdomain.ThSubdomain(chunk)
        t.start()
        threads_domain.append(t)

    dict_domain = {}
    for tw in threads_domain:
        if len(tw.join()) > 0:
            for domain, ip in tw.join().items():
                dict_domain[domain] = ip

    return dict_domain


def ip_scan(domains_ips, ports, options):

    print('\n  SCAN... wait!')
    threads_scan = []
    for ip in ip_uniq(domains_ips):
        scan = scan_host.ThScan(ip, ports, options, domains_ips)
        scan.start()
        threads_scan.append(scan)

    for ts in threads_scan:
        ts.join()


def ip_uniq(domains_ips):

    ips = {}
    for a, e in domains_ips.items():
        ips[e] = 1

    return ips

def domain_whois(target):
    try:
        details = whois.whois(target)
        print(details)
    except:
        print("WHOIS: Error!", sys.exc_info()[0])


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
        opt_whois = arguments['--whois']
        opt_scan_ports = arguments['--scan-ports']
        opt_scan_options = arguments['--scan-options']
        opt_uniq_ips = arguments['--uniq-ip']

    except DocoptExit as e:
        banner()
        os.system('python3 subdomain_finder.py --help')
        sys.exit(1)

    if opt_whois:
        domain_whois(target)
        banner()

    domains_ips={}
    domains_ips = subdomain_finder(threads, wordlist, target)

    if opt_uniq_ips:
        print("\n  IPs:")
        ips = ip_uniq(domains_ips)
        print("    Uniq: "+str(len(ips)))
        for ip in ip_uniq(domains_ips):
            print("        "+ip)

    if opt_scan:
        ip_scan(domains_ips, opt_scan_ports, opt_scan_options)

if __name__ == '__main__':
    main()

