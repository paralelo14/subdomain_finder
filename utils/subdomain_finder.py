# coding: utf-8
import sys

from utils import scan_host, verifydomain
from lib import whois


def finder(threads, wordlist, target):

    # Converting wordlist file to list
    wlist = [line.rstrip('\n')+'.'+target for line in open(wordlist)]

    len_chuck = int(threads)
    # chunks of wordlist
    chunks = [wlist[x:x+len_chuck] for x in range(0, len(wlist), len_chuck)]

    # start threads
    threads_domain = []

    for chunk in chunks:
        t = verifydomain.ThDomain(chunk)
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
        print("WHOIS: Error!", sys.exc_info()[1])