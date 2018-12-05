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
  const u_char *pkt = packet+sizeof_nopad(dnsh);
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
  uint32_t remained_packet_len = remain;
  uint32_t message_length = nlcast(bh->message_length);
  if(remained_packet_len < message_length || message_length == 0) {
    return;
  }
  if(!(ph.flags & BITTORRENT_FLAG)) {
    ph.header_info.info = "";
  }
  ph.header_info.protocol = "BitTorrent";
  ph.flags |= BITTORRENT_FLAG;
  std::string type_str;
  if(bh->message_type == BITTORRENT_CHOKE) {
    ph.header_info.info += "Choke  ";
    type_str += "Choke (0)\n";
    remained_packet_len -= sizeof_nopad(bh);
    packet += sizeof_nopad(bh);
  }
  else if(bh->message_type == BITTORRENT_UNCHOKE) {
    ph.header_info.info += "Unchoke  ";
    type_str += "Unchoke (1)\n";
    remained_packet_len -= sizeof_nopad(bh);
    packet += sizeof_nopad(bh);
  }
  else if(bh->message_type == BITTORRENT_INTERESTED) {
    ph.header_info.info += "Interested  ";
    type_str += "Interested (2)\n";
    remained_packet_len -= sizeof_nopad(bh);
    packet += sizeof_nopad(bh);
  }
  else if(bh->message_type == BITTORRENT_NOT_INTERESTED) {
    ph.header_info.info += "Not Interested  ";
    type_str += "Not Interested (3)\n";
    remained_packet_len -= sizeof_nopad(bh);
    packet += sizeof_nopad(bh);
  }
  else if(bh->message_type == BITTORRENT_HAVE) {
    bittorhdr_have *bh_have = (bittorhdr_have*)packet;
    ph.header_info.info += (boost::format("Have, Piece (Idx:0x%x)  ")
                            % nlcast(bh_have->index)).str();
    type_str += (boost::format(
                   "Have (4)\n"
                   "Piece index: %d")
                 % nlcast(bh_have->index)).str();
    remained_packet_len -= sizeof_nopad(bh_have);
    packet += sizeof_nopad(bh_have);
  }
  else if(bh->message_type == BITTORRENT_BITFIELD) {
    ph.header_info.info += (boost::format("Bitfield, Len: 0x%x  ")
                            % (message_length - sizeof(bh->message_type))).str();
    packet += sizeof_nopad(bh);
    std::string binary_str;
    int dlen = message_length - sizeof(bh->message_type);
    for(auto i = 0;i<((dlen<20)?dlen:20);i++) {
      binary_str += (boost::format("%02x")
                     % (int)*(packet + i)).str();
    }
    type_str += (boost::format("Bitfield (5)\n"
                               "Bitfield data: %s...\n")
                 % binary_str).str();
    remained_packet_len -= sizeof_nopad(bh) + dlen;
    packet += dlen;
  }
  else if(bh->message_type == BITTORRENT_REQUEST) {
    bittorhdr_request *bh_request = (bittorhdr_request*)packet;
    ph.header_info.info += (boost::format("Request, Piece (Idx:0x%x,Begin:0x%x,Len:0x%x)  ")
                            % nlcast(bh_request->index)
                            % nlcast(bh_request->begin)
                            % nlcast(bh_request->length)).str();
    type_str += (boost::format(
                   "Request (6)\n"
                   "Piece index: 0x%x\n"
                   "Begin offset of piece: 0x%x\n"
                   "Piece Length: 0x%x")
                 % nlcast(bh_request->index)
                 % nlcast(bh_request->begin)
                 % nlcast(bh_request->length)
      ).str();
    remained_packet_len -= sizeof_nopad(bh_request);
    packet += sizeof_nopad(bh_request);
  }
  else if(bh->message_type == BITTORRENT_PIECE) {
    bittorhdr_piece *bh_piece = (bittorhdr_piece*)packet;
    ph.header_info.info += (boost::format("Piece Idx:0x%x,Begin:0x%x,Len:0x%x  ")
                            % nlcast(bh_piece->index)
                            % nlcast(bh_piece->begin)
                            % (nlcast(bh->message_length)-sizeof(bh->message_length))).str();
    packet += sizeof_nopad(bh_piece);
    std::string binary_str;
    int dlen = message_length - (sizeof_nopad(bh_piece) - sizeof(bh->message_length));
    for(auto i = 0;i<((dlen<20)?dlen:20);i++) {
      binary_str += (boost::format("%02x")
                     % (int)*(packet + i)).str();
    }
    type_str += (boost::format(
                   "Piece (7)\n"
                   "Piece index: 0x%x\n"
                   "Begin offset of piece: 0x%x\n"
                   "Data in a piece: %s\n")
                 % nlcast(bh_piece->index)
                 % nlcast(bh_piece->begin)).str();
    remained_packet_len = sizeof_nopad(bh_piece) + dlen;
    packet += dlen;
  }
  else if(bh->message_type == BITTORRENT_CANCEL) {
    bittorhdr_cancel *bh_cancel = (bittorhdr_cancel*)packet;
    ph.header_info.info += (boost::format("Cancel (Idx:0x%x,Begin:0x%x,Len:0x%x)  ")
                            % nlcast(bh_cancel->index)
                            % nlcast(bh_cancel->begin)
                            % nlcast(bh_cancel->length)).str();
    type_str += (boost::format(
                   "Message length: %d"
                   "Cancel (8)\n"
                   "Piece index: 0x%x\n"
                   "Begin offset of piece: 0x%x\n"
                   "Piece Length: 0x%x\n")
                 % message_length
                 % nlcast(bh_cancel->index)
                 % nlcast(bh_cancel->begin)
                 % nlcast(bh_cancel->length)).str();
    remained_packet_len -= sizeof_nopad(bh_cancel);
    packet += sizeof_nopad(bh_cancel);
  }
  else if(bh->message_type == BITTORRENT_PORT) {
    bittorhdr_port *bh_port = (bittorhdr_port*)packet;
    ph.header_info.info += "Port  ";
    type_str += (boost::format(
                   "Port (9)\n"
                   "Port: %d\n")
                 % nscast(bh_port->port)).str();
    remained_packet_len -= sizeof_nopad(bh_port);
    packet += sizeof_nopad(bh_port);
  }
  else if(bh->message_type == BITTORRENT_SUGGEST) {
    bittorhdr_suggest *bh_suggest = (bittorhdr_suggest*)packet;
    ph.header_info.info += (boost::format("Suggest (Idx:0x%x)  ")
                            % nlcast(bh_suggest->index)).str();
    type_str += (boost::format(
                   "Suggest (13)\n"
                   "Piece index: %d\n")
                 % nlcast(bh_suggest->index)).str();
    remained_packet_len -= sizeof_nopad(bh_suggest);
    packet += sizeof_nopad(bh_suggest);
  }
  else if(bh->message_type == BITTORRENT_HAVEALL) {
    ph.header_info.info += "Haveall  ";
    type_str += "Haveall (14)\n";
    remained_packet_len -= sizeof_nopad(bh);
    packet += sizeof_nopad(bh);
  }
  else if(bh->message_type == BITTORRENT_HAVENONE) {
    ph.header_info.info += "Havenone  ";
    type_str += "Havenone (15)\n";
    remained_packet_len -= sizeof_nopad(bh);
    packet += sizeof_nopad(bh);
  }
  else if(bh->message_type == BITTORRENT_REJECT) {
    bittorhdr_reject *bh_reject = (bittorhdr_reject*)packet;
    ph.header_info.info += (boost::format("Reject, Request (Idx:0x%x,Begin:0x%x,Len:0x%x)  ")
                            % nlcast(bh_reject->index)
                            % nlcast(bh_reject->begin)
                            % nlcast(bh_reject->length)).str();
    type_str += (boost::format(
                   "Message length: %d"
                   "Reject Request (16)\n"
                   "Piece index: 0x%x\n"
                   "Begin offset of piece: 0x%x\n"
                   "Piece Length: 0x%x\n")
                 % message_length
                 % nlcast(bh_reject->index)
                 % nlcast(bh_reject->begin)
                 % nlcast(bh_reject->length)).str();
    remained_packet_len -= sizeof_nopad(bh_reject);
    packet += sizeof_nopad(bh_reject);
  }
  else if(bh->message_type == BITTORRENT_ALLOWEDFAST) {
    bittorhdr_allowedfast *bh_allowedfast = (bittorhdr_allowedfast*)packet;
    ph.header_info.info += (boost::format("AllowedFast (Idx:0x%x)  ")
                            % nlcast(bh_allowedfast->index)).str();
    type_str += (boost::format(
                   "AllowedFast (17)\n"
                   "Piece index: %d\n")
                 % nlcast(bh_allowedfast->index)).str();
    remained_packet_len -= sizeof_nopad(bh_allowedfast);
    packet += sizeof_nopad(bh_allowedfast);
  }
  else if(bh->message_type == BITTORRENT_EXTENDED) {
    packet += sizeof_nopad(bh);
    std::string binary_str;
    int dlen = message_length - sizeof(bh->message_type);
    for(auto i = 0;i<((dlen<20)?dlen:20);i++) {
      binary_str += (boost::format("%02x")
                     % (int)(*(packet + i))).str();
    }
    ph.header_info.info += "Extended  ";
    type_str += (boost::format(
                   "Extended (20)\n"
                   "Extended Message: %s...\n")
                 % binary_str).str();
    remained_packet_len -= sizeof_nopad(bh) + dlen;
    packet += dlen;
  }
  else {
    ph.header_info.info += "Continuation data  ";
    return;
  }
  ph.bittorrent.push_back((boost::format(
                             "Message Length: %u\n"
                             "Message Type: %s")
                           % message_length
                           % type_str).str());
  if(remained_packet_len) {
    process_bittorrent_L4(ph,pkthdr,packet,eh,iph,tcph,0x1,remained_packet_len);
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
