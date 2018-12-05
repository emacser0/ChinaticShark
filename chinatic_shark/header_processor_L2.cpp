#include "header_processor.hpp"
void process_ip_L2(ProcessedHeader &ph,
                   const pcap_pkthdr *pkthdr,
                   const u_char *packet,
                   const ether_header *eh) {
  auto *iph      = (iphdr*)packet;
  std::string
    src_addr(inet_ntoa(*(in_addr*)&iph->saddr)),
    dst_addr(inet_ntoa(*(in_addr*)&iph->daddr));
  uint32_t
    version      = iph->version,
    header_len   = iph->ihl,
    total_len    = ntohs(iph->tot_len),
    id           = ntohs(iph->id),
    frag_off     = ntohs(iph->frag_off),
    time_to_live = iph->ttl,
    protocol     = iph->protocol,
    checksum     = ntohs(iph->check);
  ph.header_info.destination=dst_addr;
  ph.header_info.source=src_addr;
  ph.header_info.protocol="IP";
  ph.ip_info = (boost::format(
                  "IP Protocol Version %u, Src: %s, Dst: %s")
                % version % src_addr % dst_addr).str();
  ph.ip = (boost::format(
             "Version: %u\n"
             "Header Length: %u bytes (%u)\n"
             "Total Length: %u\n"
             "Identificaion: 0x%x (%u)\n"
             "Flags: 0x%x\n"
             "Time to live: %u\n"
             "Protocol: %u\n"
             "Header checksum: 0x%x\n"
             "Source: %s\n"
             "Destination: %s")
           % version
           % (header_len*4) % header_len
           % total_len
           % id % id
           % frag_off
           % time_to_live
           % protocol
           % checksum
           % src_addr
           % dst_addr).str();
  ph.flags|=IP_FLAG;
  if (protocol == IPPROTO_TCP) {
    ph.header_info.protocol = "TCP";
    process_tcp_L3(ph,pkthdr,packet+iph->ihl*4,eh,iph);
  }
  else if(protocol == IPPROTO_UDP) {
    ph.header_info.protocol = "UDP";
    process_udp_L3(ph,pkthdr,packet+iph->ihl*4,eh,iph);
  }
}

void process_arp_L2(ProcessedHeader &ph,
                    const pcap_pkthdr *pkthdr,
                    const u_char *packet,
                    const ether_header *eh) {
  arphdr *arph = (arphdr*)packet;
  uint32_t
    hardware_type = arph->ar_hrd,
    hardware_size = arph->ar_hln,
    protocol_type = arph->ar_pro,
    protocol_size = arph->ar_pln,
    opcode        = arph->ar_op;
  ph.flags|=ARP_FLAG;
  ph.arp = (boost::format(
              "Hardware type: %d\n"
              "Protocol type: %d\n"
              "Hardware size: %d\n"
              "Protocol size: %d\n"
              "Opcode: %d")
            % hardware_type
            % protocol_type
            % hardware_size
            % protocol_size
            % opcode).str();
}
