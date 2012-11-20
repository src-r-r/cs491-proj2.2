#!/usr/bin/env python

import pcapy
import getopt, sys

def generate_ip_list(pcap_src):
  pcapfile = pcapy.open_offline(pcap_src)

def throw_argv_error():
  print """
    Usage:
    ./port_scan.py tcpdumpfile.tcpdump
    """

def main():
  ## 1. Generate a list of the IP addresses/ports that appear to act as servers (e.g. web,mail,tcp).
  if len(sys.argv) != 2:
    throw_argv_error()
    return
  filename = sys.argv[1]
  generate_ip_list(filename)

if __name__=='__main__':
  main()