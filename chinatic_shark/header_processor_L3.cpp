#include "header_processor.hpp"
std::vector<uint32_t> bittorrent_handshake_count;
std::vector<std::string> bittorrent_peer_list;
const std::string make_tcp_flags_string(uint32_t flags);
uint32_t is_bittorrent_protocol(const pcap_pkthdr*,const u_char*,
                                const ether_header*, const iphdr*,
                                const tcphdr*);

void process_tcp_L3(ProcessedHeader &ph,const pcap_pkthdr *pkthdr,
                    const u_char *packet,
                    const ether_header *eh,
                    const iphdr *iph) {
  auto *tcph    = (tcphdr*)packet;
  uint32_t
    src_port    = ntohs(tcph->source),
    dst_port    = ntohs(tcph->dest),
    seq         = ntohl(tcph->seq),
    ack_seq     = ntohl(tcph->ack_seq),
    doff        = tcph->doff,
    segment_len = ntohs(iph->tot_len)-(doff * 4) - (iph->ihl * 4),
    header_len  = doff*4,
    flags       = tcph->th_flags,
    win_size    = ntohs(tcph->window),
    checksum    = ntohs(tcph->check),
    urg_ptr     = ntohs(tcph->urg_ptr);
  ph.tcp_info = (boost::format(
              "Transmission Control Protocl, Src Port: %s Dst Port: %s Seq: %u Len: %u")
              % src_port % dst_port % seq % segment_len).str();
  ph.header_info.info = (boost::format(
                             "%d -> %d")
                         % src_port
                         % dst_port).str();
  std::string flag_str = make_tcp_flags_string(flags);
  ph.header_info.info += " [" +flag_str + "]";
  ph.tcp = (boost::format(
              "Source Port: %u\n"
              "Destination Port: %u\n"
              "[TCP Segment Len: %u]\n"
              "Sequence number: %u\n"
              "Acknowledgement number: %u\n"
              "Header Length: %u bytes (%u)\n"
              "Flags: 0x%x (%s)\n"
              "Window size value: %u\n"
              "Checksum: 0x%04x\n"
              "Urgent pointer: %u")
            % src_port
            % dst_port
            % segment_len
            % seq
            % ack_seq
            % header_len % doff
            % flags
            % flag_str
            % win_size
            % checksum
            % urg_ptr).str();
  ph.flags |= TCP_FLAG;
  const u_char *nextpkt = packet + tcph->doff*4;
  if(src_port == 80 || dst_port == 80){
    process_http_L4(ph,pkthdr,nextpkt,eh,iph,tcph);
  }
  else if(src_port == 25 || dst_port == 25) {
    process_smtp_L4(ph,pkthdr,nextpkt,eh,iph,tcph);
  }
  else {
      uint32_t bittorrent_flags = is_bittorrent_protocol(pkthdr,nextpkt,eh,iph,tcph);
      if(bittorrent_flags){
         process_bittorrent_L4(ph,pkthdr,nextpkt,eh,iph,tcph,bittorrent_flags,
                               calc_length_tcp_L4(pkthdr,iph,tcph));
      }
  }
}

const std::string make_tcp_flags_string(uint32_t flags) {
    std::string flags_str;
    if(flags) {
        if(flags & 0x1) {
            flags_str += "FIN, ";
        }
        if(flags & 0x2) {
            flags_str += "SYN, ";
        }
        if(flags & 0x4) {
            flags_str += "RST, ";
        }
        if(flags & 0x8) {
            flags_str += "PSH, ";
        }
        if(flags & 0x10) {
            flags_str += "ACK, ";
        }
        if(flags & 0x20) {
            flags_str += "URG, ";
        }
        flags_str.resize(flags_str.size()-2);
    }
    return flags_str;
}

uint32_t protocol_name_test(const pcap_pkthdr *pkthdr,const u_char *packet,
                            const iphdr *iph, const tcphdr *tcph);

uint32_t is_bittorrent_protocol(const pcap_pkthdr *pkthdr,
                            const u_char *packet,
                            const ether_header *eh,
                            const iphdr *iph,
                            const tcphdr *tcph){
    if(protocol_name_test(pkthdr,packet,iph,tcph)) {
        return 0x3;
    }
    for(uint32_t i=0;i<bittorrent_peer_list.size();i++) {
        std::string
                saddr = inet_ntoa(*(in_addr*)&iph->saddr),
                daddr = inet_ntoa(*(in_addr*)&iph->daddr);
        const std::string &current = bittorrent_peer_list[i];
        if(current == saddr || current == daddr) {
            basic_bittorhdr *bh = (basic_bittorhdr*)packet;
            if(current == saddr && tcph->fin) {
                bittorrent_peer_list.erase(bittorrent_peer_list.begin()+i);
            }
            if(tcph->psh) {
                return 0x1;
            }
            return 0x0;
        }
    }
}

uint32_t protocol_name_test(const pcap_pkthdr *pkthdr,
                        const u_char *packet,
                        const iphdr *iph,
                        const tcphdr *tcph) {
    int pktlen = calc_length_tcp_L4(pkthdr,iph,tcph);
    if(pktlen < 20 + sizeof(bittorhdr_handshake)) {
        return 0x0;
    }
    const u_char *tmp_pktptr = packet;
    std::string protocol_name;
    u_char *protocol_name_length = (u_char*)tmp_pktptr;
    if(*protocol_name_length < 19) {
        return 0x0;
    }
    int len = 19;
    for(tmp_pktptr+=sizeof(u_char);len;tmp_pktptr++,len--) {
        protocol_name += *tmp_pktptr;
    }
    if(protocol_name == "BitTorrent protocol") {
        std::string daddr = inet_ntoa(*(in_addr*)&iph->daddr);
        int index = std::find(bittorrent_peer_list.begin(),
                              bittorrent_peer_list.end(),
                              daddr) - bittorrent_peer_list.begin();
        if(index < 0 ) {
            bittorrent_peer_list.push_back(daddr);
        }
        else {
            for(int i=0;i<bittorrent_peer_list.size();i++) {
                if(bittorrent_peer_list[i] == daddr) {
                    bittorrent_peer_list.erase(bittorrent_peer_list.begin()+1);
                }
            }
        }
        return 0x3;
    }
    else {
        return 0x0;
    }
}

void process_udp_L3(ProcessedHeader &ph, const pcap_pkthdr *pkthdr,
                           const u_char *packet,
                           const ether_header *eh,
                           const iphdr *iph) {
  auto *udph        = (udphdr*)packet;
  uint32_t
    src_port        = ntohs(udph->source),
    dst_port        = ntohs(udph->dest),
    len             = ntohs(udph->len),
    check_sum       = ntohs(udph->check);
  ph.header_info.info = (boost::format(
                             "%d -> %d Len=%d")
                         % src_port
                         % dst_port
                         % (len - sizeof(udphdr))).str();
  ph.udp_info = (boost::format(
    "User Datagram Protocol, Src Port: %s Dst Port: %s")
    % src_port % dst_port).str();
    ph.udp = (boost::format(
              "Source Port: %s\n"
              "Destination Port: %s\n"
              "Length %s\n"
              "Checksum: 0x%04x")
            % src_port
            % dst_port
            % len
            % check_sum).str();
  ph.flags |= UDP_FLAG;
  const u_char *nextpkt = packet + sizeof(udphdr);
  if(src_port == 53 || dst_port == 53) {
    ph.header_info.protocol="DNS";
    process_dns_L4(ph,pkthdr,nextpkt,eh,iph,udph);
  }
  else if(dst_port == 1900) {
      ph.header_info.protocol="SSDP";
      process_ssdp_L4(ph,pkthdr,nextpkt,eh,iph,udph);
  }
  else {

  }
}
