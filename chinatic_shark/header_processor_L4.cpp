#include "header_processor.hpp"
int32_t
calc_length_tcp_L4(const pcap_pkthdr *pkthdr,
                            const iphdr *iph,
                            const tcphdr *tcph) {
    return pkthdr->caplen - sizeof(ether_header) - iph->ihl*4 - tcph->doff*4;
}

int32_t
calc_length_udp_L4(const pcap_pkthdr *pkthdr,
                   const iphdr *iph) {
    return pkthdr->caplen - sizeof(ether_header) - iph->ihl*4 - sizeof(udphdr);
}

void
process_http_L4(ProcessedHeader &ph,
                const pcap_pkthdr *pkthdr,
                const u_char *packet,
                const ether_header* eh,
                const iphdr *iph,
                const tcphdr *tcph) {
  uint32_t len = calc_length_tcp_L4(pkthdr,iph,tcph);
  if(!len) {
      return;
  }
  const u_char *pkt = packet;
  ph.header_info.protocol="HTTP";
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

void
process_dns_L4(ProcessedHeader &ph,
               const pcap_pkthdr *pkthdr,
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
    ph.dns.push_back((boost::format(
              "Transaction ID: 0x%x\n"
              "Flags: 0x%x\n"
              "Questions: %d\n"
              "Answer RRs: %d\n"
              "Authority RRs: %d\n"
              "Additional RRs: %d")
              % tran_id
              % flags
              % qst
              % ans
              % auth
              % add).str());
    const u_char *pkt = packet+sizeof(basic_dnshdr)+1;
    int len = calc_length_udp_L4(pkthdr,iph);
    ph.dns.push_back("");
    for(;len;pkt++,len--) {
        if(*pkt=='\n') {
            ph.dns.push_back("");
        }
        else if(*pkt=='\r') {
            ph.dns.push_back("");
            pkt++;
        }
        else {
            if(*pkt >= '!' && *pkt <= '~') {
                ph.dns.back()+=(*pkt);
            }
            else {
                ph.dns.back()+='.';
            }
        }
    }
}

void process_smtp_L4(ProcessedHeader &ph,
                     const pcap_pkthdr *pkthdr,
                     const u_char *packet,
                     const ether_header *eh,
                     const iphdr *iph,
                     const tcphdr *tcph) {
    int len = calc_length_tcp_L4(pkthdr,iph,tcph);
    if(!len) {
        return;
    }
    const u_char *pkt = packet;
    ph.header_info.protocol="SMTP";
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
    ph.header_info.info = ph.smtp.front();
}

void process_bittorrent_L4(ProcessedHeader &ph,
                           const pcap_pkthdr *pkthdr,
                           const u_char *packet,
                           const ether_header *eh,
                           const iphdr *iph,
                           const tcphdr *tcph,
                           uint32_t flag,
                           int32_t remain) {
    if(flag == 0x3) {
        ph.flags |= BITTORRENT_FLAG;
        ph.header_info.protocol = "BitTorrent";
        ph.header_info.info = "handshake ";
        bittorhdr_handshake *bh = (bittorhdr_handshake*)(packet+20);
        std::string reserved_extension_bytes,hash,peer_ID;
        for(int i=0;i<8;i++) {
            reserved_extension_bytes+=(boost::format("%02x") % (u_short)bh->reserved_extension_bytes[i]).str();
        }
        for(int i=0;i<20;i++) {
            hash+=(boost::format("%02x") % (u_short)bh->hash[i]).str();
            peer_ID+=(boost::format("%02x") % (u_short)bh->peer_ID[i]).str();
        }
        std::string info_str = (boost::format(
                                    "Protocol Name Length: 19\n"
                                    "Protocol Name: BitTorrent Protocol\n"
                                    "Reserved Extension Bytes: %s\n"
                                    "SHA1 Hash of info dictionary: %s\n"
                                    "Peer ID: %s\n")
                                    % reserved_extension_bytes
                                    % hash
                                    % peer_ID).str();
        ph.bittorrent.push_back(info_str);
        int32_t remained_packet_len = remain - 20 - sizeof(bittorhdr_handshake);
        if(remained_packet_len) {
            process_bittorrent_L4(ph,pkthdr,packet+20+sizeof(bittorhdr_handshake),eh,iph,tcph,0x1,
                                  remained_packet_len);
        }
        return;
    }
    basic_bittorhdr *bh = (basic_bittorhdr*)packet;
    int32_t remained_packet_len = remain;
    //test
    uint32_t message_length = ntohs(bh->message_length);
    ph.flags |= BITTORRENT_FLAG;
    ph.header_info.protocol = "BitTorrent";
    std::string format_string_test = (boost::format(
                "Message Length: 0x%x\n")
                % message_length).str();
    ph.bittorrent.push_back(format_string_test);
    if(remained_packet_len < message_length || message_length == 0) {
        return;
    }
    std::string format_string = (boost::format(
                "Message Length: %d\n"
                "Message Type: ")
                % bh->message_length).str();
    ph.bittorrent.push_back(format_string);
    if(bh->message_type == BITTORRENT_CHOKE) {
        ph.header_info.info += "Choke  ";
        ph.bittorrent.back() += "Choke (0)\n";
    }
    else if(bh->message_type == BITTORRENT_UNCHOKE) {
        ph.header_info.info += "Unchoke  ";
        ph.bittorrent.back() += "Unchoke (1)\n";
    }
    else if(bh->message_type == BITTORRENT_INTERESTED) {
        ph.header_info.info += "Interested  ";
        ph.bittorrent.back() += "Interested (2)\n";
    }
    else if(bh->message_type == BITTORRENT_NOT_INTERESTED) {
        ph.header_info.info += "Not Interested  ";
        ph.bittorrent.back() += "Not Interested (3)\n";
    }
    else if(bh->message_type == BITTORRENT_HAVE) {
        bittorhdr_have *bh_have = (bittorhdr_have*)packet;
        ph.header_info.info += (boost::format("Have, Piece (Idx:0x%x)  ")
                                % bh_have->index).str();
        ph.bittorrent.back() += "Have (4)\n";
    }
    else if(bh->message_type == BITTORRENT_BITFIELD) {
        ph.header_info.info += (boost::format("Bitfield, Len: 0x%x  ")
                                % (bh->message_length - sizeof(u_char))).str();
        ph.bittorrent.back() += "Bitfield (5)\n";
    }
    else if(bh->message_type == BITTORRENT_REQUEST) {
        bittorhdr_reject *bh_reject = (bittorhdr_reject*)packet;
        ph.header_info.info += (boost::format("Request, Piece (Idx:0x%x,Begin:0x%x,Len:0x%x)  ")
                                % bh_reject->index
                                % bh_reject->begin
                                % bh_reject->length).str();
        ph.bittorrent.back() += "Request (6)\n";
    }
    else if(bh->message_type == BITTORRENT_PIECE) {
        ph.header_info.info += "Piece, ";
        ph.bittorrent.back() += "Piece (7)\n";
    }
    else if(bh->message_type == BITTORRENT_CANCEL) {
        ph.header_info.info += "Cancel  ";
        ph.bittorrent.back() += "Cancel (8)\n";
    }
    else if(bh->message_type == BITTORRENT_PORT) {
        ph.header_info.info += "Port  ";
        ph.bittorrent.back() += "Port (9)\n";
    }
    else if(bh->message_type == BITTORRENT_SUGGEST) {
        ph.header_info.info += "Suggest  ";
        ph.bittorrent.back() += "Suggest (13)";
    }
    else if(bh->message_type == BITTORRENT_HAVEALL) {
        ph.header_info.info += "Haveall  ";
        ph.bittorrent.back() += "Haveall (14)";
    }
    else if(bh->message_type == BITTORRENT_HAVENONE) {
        ph.header_info.info += "Havenone  ";
        ph.bittorrent.back() += "Havenone (15)\n";
    }
    else if(bh->message_type == BITTORRENT_REJECT) {
        ph.header_info.info += "Reject  ";
        ph.bittorrent.back() += "Reject (16)";
    }
    else if(bh->message_type == BITTORRENT_ALLOWEDFAST) {
        ph.header_info.info += "AllowedFast  ";
        ph.bittorrent.back() += "AllowedFast (17)";
    }
    else if(bh->message_type == BITTORRENT_EXTENDED) {
        ph.header_info.info += "Extended  ";
        ph.bittorrent.back() += "Extended (20)";
    }
}

void process_ssdp_L4(ProcessedHeader &ph, const pcap_pkthdr *pkthdr,
                     const u_char * packet,
                     const ether_header *eh,
                     const iphdr *iph,
                     const udphdr *udph) {
    int len = pkthdr->caplen - sizeof(ether_header) - iph->ihl*4 - sizeof(udphdr);
    if(!len) {
        return;
    }
    const u_char *pkt = packet;
    ph.header_info.protocol="SSDP";
    ph.flags |= SSDP_FLAG;
    ph.ssdp.push_back("");
    for(;len;pkt++,len--) {
        if(*pkt=='\n') {
            ph.ssdp.push_back("");
        }
        else if(*pkt=='\r') {
            ph.ssdp.push_back("");
            pkt++;
        }
        else {
            ph.ssdp.back()+=(*pkt);
        }
    }
}
