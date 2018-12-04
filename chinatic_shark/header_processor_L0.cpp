#include "header_processor.hpp"

void process_packet_L0(ProcessedHeader &ph,
                       const pcap_pkthdr *pkthdr,
                       const u_char *packet) {
  ph.header_info.cap_len = pkthdr->caplen;
  process_ether_L1(ph,pkthdr,packet);
  process_hex_L1(ph,pkthdr,packet);
}
