# subdomain_finder
Python script to find subdomains

- (i think) only dep is docopt, so make sure you install with pip3 (the script is for python3)
- pip3 install docopt

obs: if you don't set threads, the default is 50.

ex usage:
$ python3 subdomain_finder.py --target='globo.com' --wordlist='wordlist.txt' --threads=150
