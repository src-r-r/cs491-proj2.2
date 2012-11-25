#!/usr/bin/env python

import pcapy
import getopt, sys
from dpkt import http
from dpkt import pcap
from dpkt import ip
import proto_dict

"""
def generate_ip_list(pcap_src):
  reader = pcapy.open_offline(pcap_src)
  # print "Got a reader: ", reader
  # myfilter = "smtp.rsp || http.server || tcp.analysis.ack_rtt || dns.resp.addr || arp.opcode==reply"
  myfilter = 'tcp'
  reader.setfilter(myfilter)
  list_values = generate_list(reader)
  for item in list_values:
    print item[0]
    """

def generate_ip_list(pcap_src):
  import dpkt
  f = open(pcap_src)
  pcap = dpkt.pcap.Reader(f)
  ##
  # Iteratively go through the packets in the dumpfile.
  # We'll need to check each packet to check if it's
  # IPv6 or IPv4...most (okay, all) for this project
  # are IPv4.
  
  ##
  # NOTE: The only protocols we care about are:
  #    * IPv4 and IPv6 (we won't check headers, so we'll
  #      just use the IP protocol)
  #    * DNS
  #    * ICMP
  for ts, buf in pcap:
    ## Get the transport layer
    eth = dpkt.ethernet.Ethernet(buf)
    ## Get the internet layer
    if (eth.type == dpkt.ethernet.ETH_TYPE_IP6) or (eth.type == dpkt.ethernet.ETH_TYPE_IP):
        # print "the protocol is ip6"    # DEBUG
        my_ip = eth.data;
        # Get the transport layer.
        if (my_ip.p == dpkt.ip.IP_PROTO_TCP):
            #print "We're using TCP"    #DEBUG
            my_tcp = my_ip.data
            pass
        elif (my_ip.p == dpkt.ip.IP_PROTO_UDP):
            #print "We're using UDP"    #DEBUG
            my_udp = my_ip.data
            pass
        elif (my_ip.p == dpkt.ip.IP_PROTO_SCTP):
            #print "We're using SCTP"    #DEBUG
            my_sctp = my_ip.data
            pass
        elif (my_ip.p == dpkt.ip.IP_PROTO_ICMP):
            #print "We're using ICMP"    #DEBUG
            my_icmp = my_ip.data
            pass
        elif (my_ip.p == dpkt.ip.IP_PROTO_IGP):
            #print "We're using IGP"    #DEBUG
            my_igp = my_ip.data
            pass
        else:
            print "I don't know what the heck we're using! ", my_ip.p
    elif (eth.type == dpkt.ethernet.ETH_TYPE_PPP):
        # print ("We're using PPP. Ignore...") #DEBUG
        pass
    elif (eth.type == dpkt.ethernet.ETH_TYPE_ARP):
        #print ("We're using ARP. Ignore...") #DEBUG
        pass
        
    ## We can also ignore loop-backs and LLC since those are internal
    ## protocols.

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