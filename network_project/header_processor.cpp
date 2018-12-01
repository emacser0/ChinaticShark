#include <net/ethernet.h>
#include <netinet/in.h>
#include "header_processor.hpp"
ProcessedHeader ph;
ProcessedHeader& process_packet(const pcap_pkthdr *pkthdr,
                                       const u_char *packet) {
  ph.reset();
  process_packet_L0(pkthdr,packet);
  return ph;
}

void process_packet_L0(const pcap_pkthdr *pkthdr,
                              const u_char *packet) {
  ph.header_info.cap_len = pkthdr->caplen;
  process_ether_L1(pkthdr,packet);
  process_hex_L1(pkthdr,packet);
}

void process_ether_L1(const pcap_pkthdr *pkthdr,
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
                     "Ethernet II Src: %s Dst: %s\n")
                   % dst_addr_str % src_addr_str).str();
  ph.ether = (boost::format(
                "Destination: %s\n"
                "Source: %s\n"
                "Type : 0x%x\n")
              % dst_addr_str
              % src_addr_str
              % ether_type).str();
  ph.flags |= ETHER_FLAG;
  if (ether_type == ETHERTYPE_IP) {
    process_ip_L2(pkthdr,packet+sizeof(struct ether_header),eh);
  }
  else if(ether_type == ETHERTYPE_ARP) {
    ph.header_info.protocol="ARP";
    process_arp_L2(pkthdr,packet+sizeof(struct ether_header),eh);
  }
}

void process_ip_L2(const pcap_pkthdr *pkthdr,
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
  ph.ip_info = (boost::format(
                  "IP Protocol Version %u, Src: %s, Dst: %s\n")
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
             "Destination: %s\n")
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
  ph.header_info.protocol="IP";
  if (protocol == IPPROTO_TCP) {
      ph.header_info.protocol = "TCP";
    process_tcp_L3(pkthdr,packet+iph->ihl*4,eh,iph);
  }
  else if(protocol == IPPROTO_UDP) {
      ph.header_info.protocol = "UDP";
    process_udp_L3(pkthdr,packet+iph->ihl*4,eh,iph);
  }
}

void process_arp_L2(const pcap_pkthdr *pkthdr,
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
              "Opcode: %d\n")
              % hardware_type
              % protocol_type
              % hardware_size
              % protocol_size
              % opcode).str();
}

void process_tcp_L3(const pcap_pkthdr *pkthdr,
                           const u_char *packet,
                           const ether_header *eh,
                           const iphdr *iph) {
  auto *tcph    = (tcphdr*)packet;
  uint32_t
    src_port    = ntohs(tcph->source),
    dst_port    = ntohs(tcph->dest),
    seq         = ntohl(tcph->seq),
    ack_seq     = ntohl(tcph->ack_seq),
    segment_len = ntohs(iph->tot_len)-(tcph->doff * 4) - (iph->ihl * 4),
    doff        = tcph->doff,
    header_len  = doff*4,
    flags       = tcph->th_flags,
    win_size    = ntohs(tcph->window),
    checksum    = ntohs(tcph->check),
    urg_ptr     = ntohs(tcph->urg_ptr);
  ph.tcp_info = (boost::format(
              "Transmission Control Protocl, Src Port: %s Dst Port: %s Seq: %u Len: %u\n")
              % src_port % dst_port % seq % segment_len).str();
  ph.tcp = (boost::format(
              "Source Port: %u\n"
              "Destination Port: %u\n"
              "[TCP Segment Len: %u]\n"
              "Sequence number: %u\n"
              "Acknowledgement number: %u\n"
              "Header Length: %u bytes (%u)\n"
              "Flags: 0x%x\n"
              "Window size value: %u\n"
              "Checksum: 0x%x\n"
              "Urgent pointer: %u\n")
            % src_port
            % dst_port
            % segment_len
            % seq
            % ack_seq
            % header_len % doff
            % flags
            % win_size
            % checksum
            % urg_ptr).str();
  ph.flags |= TCP_FLAG;
  if(src_port == 80 || dst_port == 80){
    ph.header_info.protocol="HTTP";
    process_http_L4(pkthdr,packet+tcph->doff*4,eh,iph,tcph);
  }
  else if(src_port == 25 || dst_port == 25) {
    ph.header_info.protocol="SMTP";
    process_smtp_L4(pkthdr,packet+tcph->doff*4,eh,iph,tcph);
  }
}

void process_udp_L3(const pcap_pkthdr *pkthdr,
                           const u_char *packet,
                           const ether_header *eh,
                           const iphdr *iph) {
  auto *udph        = (udphdr*)packet;
  uint32_t
    src_port        = ntohs(udph->source),
    dst_port        = ntohs(udph->dest),
    len             = ntohs(udph->len),
    check_sum       = ntohs(udph->check);
  ph.udp_info = (boost::format(
    "User Datagram Protocol, Src Port: %s Dst Port: %s\n")
    % src_port % dst_port).str();
    ph.udp = (boost::format(
              "Source Port: %s\n"
              "Destination Port: %s\n"
              "Length %s\n"
              "Checksum: 0x%x\n")
            % src_port
            % dst_port
            % len
            % check_sum).str();
  ph.flags |= UDP_FLAG;
  if(src_port == 53 || dst_port == 53) {
    ph.header_info.protocol="DNS";
    process_dns_L4(pkthdr,packet+sizeof(pkthdr),eh,iph,udph);
  }
}

void process_http_L4(const pcap_pkthdr *pkthdr,
                            const u_char *packet,
                            const ether_header* eh,
                            const iphdr *iph,
                            const tcphdr *tcph) {
  const u_char *pkt = packet;
  int len = pkthdr->caplen - 14 - iph->ihl*4 - tcph->doff*4;
  ph.flags |= HTTP_FLAG;
  ph.http.push_back("");
  for(;len;pkt++,len--) {
      if(*pkt=='\n') {
          ph.http.push_back("");
      }
      else if(*pkt=='\r') {
          ph.http.push_back("");
          pkt++;
      }
      else {
          ph.http.back()+=(*pkt);
      }
  }
}

void process_dns_L4(const pcap_pkthdr *pkthdr,
                           const u_char *packet,
                           const ether_header *eh,
                           const iphdr *iph,
                           const udphdr *udph) {
    basic_dnshdr *dnsh = (basic_dnshdr*)packet;
    ph.flags |= DNS_FLAG;
    uint32_t
      tran_id = ntohs(dnsh->tran_id),
      flags   = ntohs(dnsh->flags),
      qst     = ntohs(dnsh->qst),
      ans     = ntohs(dnsh->ans),
      auth    = ntohs(dnsh->auth),
      add     = ntohs(dnsh->add);
    ph.dns = (boost::format(
              "Transaction ID: 0x%x\n"
              "Flags: 0x%x\n"
              "Questions: %d\n"
              "Answer RRs: %d\n"
              "Authority RRs: %d\n"
              "Additional RRs: %d\n")
              % tran_id
              % flags
              % qst
              % ans
              % auth
              % add).str();
}

void process_smtp_L4(const pcap_pkthdr *pkthdr,
                     const u_char *packet,
                     const ether_header *eh,
                     const iphdr *iph,
                     const tcphdr *tcph) {
    const u_char *pkt = packet;
    int len = pkthdr->caplen - 14 - iph->ihl*4 - tcph->doff*4;
    ph.flags |= SMTP_FLAG;
    ph.smtp.push_back("");
    for(;len;pkt++,len--) {
        if(*pkt=='\n') {
            ph.smtp.push_back("");
        }
        else if(*pkt=='\r') {
            ph.smtp.push_back("");
            pkt++;
        }
        else {
            ph.smtp.back()+=(*pkt);
        }
    }
}

void process_bittorrent_L4(const pcap_pkthdr *pkthdr,
                           const u_char *packet,
                           const ether_header *eh,
                           const iphdr *iph,
                           const tcphdr *tcph) {
    ph.flags |= BITTORRENT_FLAG;
}

void process_hex_L1(const pcap_pkthdr *pkthdr,
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
