#include <net/ethernet.h>
#include <netinet/in.h>
#include "header_processor.hpp"
ProcessedHeader ph;
ProcessedHeader& process_packet(ProcessedHeader &ph,
                                const pcap_pkthdr *pkthdr,
                                const u_char *packet) {
  ph.reset();
  process_packet_L0(ph,pkthdr,packet);
  return ph;
}
