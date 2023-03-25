# coding: utf-8

import socket
import os
import traceback
from argparse import ArgumentParser

from pcapctftool import manager, logger


def build_argument_parser() -> ArgumentParser:
    parser = ArgumentParser(
        description='Helps you solve common pcap ctf challenges')
    parser.add_argument("pcapfiles",
                        nargs='*',
                        help='pcap files you want to analyse')
    parser.add_argument('-s', '--string-inspection',action='store_true',
                        help='Extract strings ')
    parser.add_argument('-u', '--usb', action='store_true',
                        help='Extract usb keystroke data')
    parser.add_argument('-b64', '--base64-string-inspection', action='store_true',
                        help='Extract base64 strings in pcap')
    parser.add_argument('-nx', '--dns-exfil', action='store_true',
                        help='Extract dns exfiltrated data')
    parser.add_argument('-px', '--icmp-exfil', action='store_true',
                        help='Extract icmp exfiltrated data')
    parser.add_argument('-i', '--info', action='store_true',
                        help='show pcap summary')


    return parser


def main():
    parser = build_argument_parser()
    args = parser.parse_args()
    if not args.pcapfiles:
        parser.print_help()
        exit()

    for pcap in args.pcapfiles:

        try:
            manager.process_pcap(pcap,
                                 must_inspect_strings=args.string_inspection ,
                                 tshark_filter=None,
                                 debug=False,
                                 decode_as=None)
            if args.usb:
                manager.process_usb(pcap)

        except Exception as e:
            error_str = str(e)

            if error_str.startswith("[Errno"):  # Clean error message
                errno_end_index = error_str.find("]") + 2
                error_str = error_str[errno_end_index:]
                logger.error(error_str)

            else:
                traceback.print_exc()

if __name__ == "__main__":
    main()
