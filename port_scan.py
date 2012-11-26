#!/usr/bin/env python

import pcapy
import getopt, sys
from dpkt import http
from dpkt import pcap
from dpkt import ip
import proto_dict
import socket
import random

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
  """
  Generate the IP list for the PCAP file.  In addition,
  get the list of opened ports and the number of bytes sent
  for each connection (these will be added up)
  The data structure of the return will look like the following:
  dictionary(
      "source.ip.address.1" => dict(
          "dest.ip.address.1" => bytes_served_1,
          "dest.ip.address.2" => bytes_served_2,
          ...,
          "dest.ip.address.n" => bytes_served_n
      ),
      source.ip.address.2" => dict( ... ),
      ...,
      source.ip.address.n" => dict( ... )
  )
  """
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
                src_str = socket.inet_ntoa(my_ip.src)
                dst_str = socket.inet_ntoa(my_ip.dst)
                if src_str not in server_dict:
                    server_dict[src_str] = {}
                if dst_str not in server_dict[src_str]:
                   server_dict[src_str][dst_str] = 0 
                server_dict[src_str][dst_str] += (len(my_ip.data))
                
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
  dict = generate_ip_list(filename)
  print "There are", len(dict), "servers:\n", dict.keys()
  for k1 in dict.keys():
      size = 0
      l = dict[k1]
      for item in l.keys():
          size += l[item]   # Add the bytes to the size.
      if len(dict[k1]) == 1:
        print k1, "has", len(dict[k1]), "connection and sent", size, "bytes"
      else:
        print k1, "has", len(dict[k1]), "connections and sent", size, "bytes"
        
  
  ports = range(0, 1023)
  random.shuffle(ports)

if __name__=='__main__':
    main()