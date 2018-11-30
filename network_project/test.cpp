#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <iostream>
#include <iomanip>
#include "header_processor.hpp"

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

void
callback(
         u_char *useless,
         const pcap_pkthdr *pkthdr,
         const u_char *packet) {
  process_packet(pkthdr,packet);
}

int main(int argc, char **argv)
{
  char *dev,*net,*mask,errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 netp,maskp;
  in_addr net_addr, mask_addr;
  bpf_program fp;
  pcap_t *pcd;  // packet capture descriptor

  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
    std::cerr << errbuf;
    exit(1);
  }
  std::cout << "DEV : " << dev << "\n";
  if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == -1) {
    std::cerr << errbuf << "\n";
    exit(1);
  }
  net_addr.s_addr = netp;
  net = inet_ntoa(net_addr);
  mask_addr.s_addr = maskp;
  mask = inet_ntoa(mask_addr);
  std::cout << "NET : " << net << "\n"
            << "MSK : " << mask << "\n"
            << "=======================\n";
  pcd = pcap_open_live(dev, 1200,  NONPROMISCUOUS, -1, errbuf);
  if (pcd == NULL) {
    std::cerr << errbuf << "\n";
    exit(1);
  }
  std::string filter;
  for(int i=2;i<argc;i++) {
    filter+=argv[i];
    filter+=" ";
  }
  if (pcap_compile(pcd, &fp, filter.c_str(), 0, netp) == -1) {
    std::cout << "compile error\n";
    exit(1);
  }
  if (pcap_setfilter(pcd, &fp) == -1) {
    std::cerr << "setfilter error\n";
    exit(0);
  }
  // argv[1] : loop count
  pcap_loop(pcd, atoi(argv[1]), callback, NULL);
}
