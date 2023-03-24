#!/usr/bin/env python
# encoding: utf-8

import re
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
def open_pcap(inputfile, f=None):
    print('\n') 
    cprint(f"[+] Load PCAP.....", 'blue')
    try: 
        if f:
            packets = sniff(offline=inputfile, filter=f, session=TCPSession)
        else:
            packets = sniff(offline=inputfile, session=TCPSession)
        cprint(f"[-] {inputfile} loaded\n",'green')  
    except:
        cprint(f"[!]File: {inputfile} loading failed\n", 'red')
        exit()
    return packets


def cred_search(inputfile):
    # frame matches "(?i)(passwd|pass|password)"
    pattern = b"(?i)(pass(wor)?d.*|user(name)?.*)"
    print('\n')     
    filt = 'frame matches "(?i)(passwd|pass|password)"'
    packets = open_pcap(inputfile)
    cprint(f"[+] Cred Search.....", 'blue')
    
    for packet in packets:
        if packet.haslayer('Raw'):
            payload = packet.getlayer('Raw').load
            if re.search(pattern,payload):
                try:
                    cprint(payload.decode('utf-8'), 'green')
                except UnicodeDecodeError:
                    cprint(payload.decode('utf-8', 'ignore'), 'green')
                    
    # return packets

if __name__ == '__main__':
    cred_search(sys.argv[1])
