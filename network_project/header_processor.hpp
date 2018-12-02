#ifndef HEADER_PROCESSOR
#define HEADER_PROCESSOR
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <iostream>
#include <vector>
#include <boost/format.hpp>

struct basic_dnshdr {
    u_short tran_id;
    u_short flags;
    u_short qst;
    u_short ans;
    u_short auth;
    u_short add;
};

struct basic_bittorhdr {
    uint32_t message_length;
    u_char message_type;
};

struct bittorhdr_have {
    uint32_t message_length;
    u_char message_type;
    uint32_t piece_index;
};

struct bittorhdr_request {
    uint32_t message_length;
    u_char message_type;
    uint32_t piece_index;
    uint32_t begin_offset_of_piece;
    uint32_t piece_length;
};

struct bittorhdr_piece {
    uint32_t message_length;
    u_char message_type;
    uint32_t index;
    uint32_t begin_offset_of_piece;
};

struct bittorhdr_cancel {
    uint32_t message_length;
    u_char message_type;
    uint32_t piece_index;
    uint32_t begin_offset_of_piece;
    uint32_t piece_length;
};

#define ETHER_FLAG 0x1
#define IP_FLAG 0x2
#define ARP_FLAG 0x4
#define TCP_FLAG 0x8
#define UDP_FLAG 0x10
#define HTTP_FLAG 0x20
#define DNS_FLAG 0x40
#define SMTP_FLAG 0x80
#define BITTORRENT_FLAG 0x100
#define SSDP_FLAG 0x200
struct HeaderInfo {
    std::string source;
    std::string destination;
    std::string protocol;
    uint32_t cap_len;
    std::string info;
    void reset() {
        source.clear();
        destination.clear();
        protocol.clear();
        cap_len = 0;
        info.clear();
    }
};

struct ProcessedHeader {
  std::string ether_info;
  std::string ether;
  std::string ip_info;
  std::string ip;
  std::string arp;
  std::string tcp_info;
  std::string tcp;
  std::string udp_info;
  std::string udp;
  std::vector<std::string> http;
  std::vector<std::string> dns;
  std::vector<std::string> smtp;
  std::vector<std::string> bittorrent;
  std::vector<std::string> ssdp;
  std::string hex;
  uint32_t flags;
  HeaderInfo header_info;
  inline void reset() {
      ether_info.clear();
      ether.clear();
      ip_info.clear();
      ip.clear();
      arp.clear();
      tcp_info.clear();
      tcp.clear();
      udp_info.clear();
      http.clear();
      dns.clear();
      smtp.clear();
      bittorrent.clear();
      hex.clear();
    flags=0;
    header_info.reset();
  }
};

ProcessedHeader& process_packet(const pcap_pkthdr*,const u_char*);
void process_packet_L0(const pcap_pkthdr*,const u_char*);
void process_ether_L1(const pcap_pkthdr*,const u_char*);
void process_ip_L2(const pcap_pkthdr*,const u_char*,const ether_header*);
void process_arp_L2(const pcap_pkthdr*,const u_char*,const ether_header*);
void process_tcp_L3(const pcap_pkthdr*,const u_char*,
                    const ether_header*,const iphdr*);
void process_udp_L3(const pcap_pkthdr*,const u_char*,
                    const ether_header*,const iphdr*);
void process_http_L4(const pcap_pkthdr*,const u_char*,const ether_header*,
                     const iphdr*,const tcphdr*);
void process_dns_L4(const pcap_pkthdr*,const u_char*,const ether_header*,
                    const iphdr*,const udphdr*);
void process_smtp_L4(const pcap_pkthdr*,const u_char*,const ether_header*,
                     const iphdr*,const tcphdr*);
void process_bittorrent_L4(const pcap_pkthdr*,const u_char*,const ether_header*,
                           const iphdr*,const tcphdr*);
void process_ssdp_L4(const pcap_pkthdr*,const u_char*,const ether_header*,
                     const iphdr*,const udphdr*);
void process_hex_L1(const pcap_pkthdr*,const u_char*);

#endif
