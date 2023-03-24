#!/usr/bin/env python
# encoding: utf-8


import sys
import argparse
import logging
import pprint
import base64
import binascii
import fleep 
import hashlib
import tqdm
import random
import hexdump
import shutil
from termcolor import colored, cprint
from scapy.all import *
from scapy.layers import http

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# open file
def open_pcap(inputfile):
    print('\n') 
    cprint(f"[+] Load PCAP.....", 'blue')
    try: 
        packets = sniff(offline=inputfile, session=TCPSession)
        cprint(f"[-] {inputfile} loaded\n",'green')  
    except:
        cprint(f"[!]File: {inputfile} loading failed\n", 'red')
        exit()
    return packets


if __name__ == '__main__';
    open_pcap(sys.argv[1])
