# -*- coding: utf-8 -*-
"""
Find subdomains using brute force.
There is the option of running automatic scan using nmap - to discover operating systems, we recommend running as administrator or root.


Usage:
    subdomain_finder.py --target=<arg> [--wordlist=<arg> --threads=<arg>  --whois --scan  --scan-ports=<arg>  --scan-options=<arg>  --uniq-ip]
    subdomain_finder.py --help
    subdomain_finder.py --version

Options:
    -h --help                          open help menu
    -v --version                       show version

Required options:
    --target='domain'                  your target =)

Optional options:
    --wordlist='list for brute force'  your favorite list of subdomains
    --threads=number of subdomais      how many subdomais test for threads [default: 275]
    --scan                             scan subdomains (nmap)
    --whois                            get "whois" information
    --scan-ports='20-443'              ports
    --scan-options='-Pn -T5 -A'        scan option style nmap [default: '-Pn -T5 -A']
    --uniq-ip                          show list ips

"""

import os
import sys

from docopt import docopt, DocoptExit

from utils import cli, subdomain_finder





def main():
    try:
        cli.banner()
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
        cli.banner()
        os.system('python3 subdomain_finder.py --help')
        sys.exit(1)

    if not wordlist:
        wordlist = os.path.join(os.getcwd(), os.path.dirname(__file__), 'data', 'wordlist.txt')

    try:
        domains_ips = subdomain_finder.finder(threads, wordlist, target)
    except:
        print("Wordlist {0} ERROR: {1}".format(wordlist, sys.exc_info()[1]))
        exit(0)

    if opt_uniq_ips:
        print("\n  IPs:")
        ips = subdomain_finder.ip_uniq(domains_ips)
        print("    Uniq: "+str(len(ips)))
        for ip in subdomain_finder.ip_uniq(domains_ips):
            print("        "+ip)

    if opt_scan:
        subdomain_finder.ip_scan(domains_ips, opt_scan_ports, opt_scan_options)

    if opt_whois:
        subdomain_finder.domain_whois(target)
        cli.banner()


if __name__ == '__main__':
    main()

