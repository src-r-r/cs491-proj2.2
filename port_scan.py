#!/usr/bin/env python

import pcapy
import getopt, sys
from dpkt import http
from dpkt import pcap
from dpkt import ip
import proto_dict
import socket

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
  server_list = []
  server_dict = {}
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
            
            ## Code recommended from dpkt docs.
            fin_flag = ( my_tcp.flags & dpkt.tcp.TH_FIN ) != 0
            syn_flag = ( my_tcp.flags & dpkt.tcp.TH_SYN ) != 0
            rst_flag = ( my_tcp.flags & dpkt.tcp.TH_RST ) != 0
            psh_flag = ( my_tcp.flags & dpkt.tcp.TH_PUSH) != 0
            ack_flag = ( my_tcp.flags & dpkt.tcp.TH_ACK ) != 0
            urg_flag = ( my_tcp.flags & dpkt.tcp.TH_URG ) != 0
            ece_flag = ( my_tcp.flags & dpkt.tcp.TH_ECE ) != 0
            cwr_flag = ( my_tcp.flags & dpkt.tcp.TH_CWR ) != 0
            
            if (syn_flag or rst_flag or ack_flag):
                
                # Get the IP address for the list.
                ip_str = socket.inet_ntoa(my_ip.dst)
                if ip_str not in server_dict.keys():
                    server_dict[ip_str] = 0
                    
                # Get the number of bytes sent.
                server_dict[ip_str] += len(my_ip.data)
                
        elif (my_ip.p == dpkt.ip.IP_PROTO_UDP):
            #print "We're using UDP"    #DEBUG
            my_udp = my_ip.data
        elif (my_ip.p == dpkt.ip.IP_PROTO_SCTP):
            #print "We're using SCTP"    #DEBUG
            my_sctp = my_ip.data
        elif (my_ip.p == dpkt.ip.IP_PROTO_ICMP):
            #print "We're using ICMP"    #DEBUG
            my_icmp = my_ip.data
        elif (my_ip.p == dpkt.ip.IP_PROTO_IGP):
            #print "We're using IGP"    #DEBUG
            my_igp = my_ip.data
  return server_dict
        
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
  list = generate_ip_list(filename)
  print "\n%d IP addresses acting as servers:\n%s\n" % (len(list), list.keys())
  for l in list.keys():
      print "%s sent %d bytes" % (l, list[l])

if __name__=='__main__':
    main()