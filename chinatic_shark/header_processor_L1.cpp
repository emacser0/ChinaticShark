#include "header_processor.hpp"

void process_ether_L1(ProcessedHeader &ph,
                      const pcap_pkthdr *pkthdr,
                      const u_char *packet) {
  auto *eh                = (ether_header *)packet;
  uint32_t ether_type     = ntohs(eh->ether_type);
  u_char
    *daddr                = eh->ether_dhost,
    *saddr                = eh->ether_shost;
  std::string dst_addr_str =
    (boost::format(
      "%02X:%02X:%02X:%02X:%02X:%02X")
     % (uint)daddr[0] % (uint)daddr[1] % (uint)daddr[2]
     % (uint)daddr[3] % (uint)daddr[4] % (uint)daddr[5]).str();
  std::string src_addr_str =
    (boost::format(
      "%02X:%02X:%02X:%02X:%02X:%02X")
     % (uint)saddr[0] % (uint)saddr[1] % (uint)saddr[2]
     % (uint)saddr[3] % (uint)saddr[4] % (uint)saddr[5]).str();
  ph.header_info.source = src_addr_str;
  ph.header_info.destination = dst_addr_str;
  ph.ether_info = (boost::format(
                     "Ethernet II Src: %s Dst: %s")
                   % dst_addr_str % src_addr_str).str();
  ph.ether = (boost::format(
                "Destination: %s\n"
                "Source: %s\n"
                "Type : 0x%x")
              % dst_addr_str
              % src_addr_str
              % ether_type).str();
  ph.flags |= ETHER_FLAG;
  if (ether_type == ETHERTYPE_IP) {
    process_ip_L2(ph,pkthdr,packet+sizeof(struct ether_header),eh);
  }
  else if(ether_type == ETHERTYPE_ARP) {
    ph.header_info.protocol="ARP";
    process_arp_L2(ph,pkthdr,packet+sizeof(struct ether_header),eh);
  }
}

void process_hex_L1(ProcessedHeader &ph,
                    const pcap_pkthdr *pkthdr,
                    const u_char *packet) {
  int ix, iy, iz,addr = 0,len = pkthdr->len;
  u_char * p = (u_char*)packet;
  ph.hex.clear();
  for(ix = 0, iz = 0; ix < len/16+1; ++ix)
  {
    ph.hex += (boost::format("0x%04X    ")%addr).str();
    for(iy = 0; iy < 16; ++iy)
    {
      if(iz < len) {
        ph.hex += (boost::format("%02X ") % (uint)(*p)).str();
      }
      else {
        ph.hex += "00 ";
      }
      ++p;
      ++iz;
    }
    p -= 16;
    iz -= 16;
    ph.hex += "   ";
    for(iy = 0; iy < 16; ++iy)
    {
      if((0x21 <= *p) && (0x7E >= *p) && (iz < len)) {
        ph.hex += (boost::format("%c") % (*p)).str();
      }
      else {
        ph.hex += ".";
      }
      ++p;
    }
    ph.hex += "\n";
    addr += 16;
  }
}
