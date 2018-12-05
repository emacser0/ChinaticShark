#include "pcap_thread.hpp"
#include <thread>
#include <deque>
std::deque<ProcessedHeader> result_header;
bool stop = 0;
void
callback(u_char *useless,
         const pcap_pkthdr *pkthdr,
         const u_char *packet) {
  if(stop) {
    std::this_thread::yield();
  }
  else {
    ProcessedHeader ph;
    process_packet(ph,pkthdr,packet);
    result_header.push_front(ph);
  }
}

void init_pcap_thread(const std::string &dev_name,const std::string &filter) {
  char *net,*mask,errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *dev;
  bpf_u_int32 netp,maskp;
  in_addr net_addr, mask_addr;
  bpf_program fp;
  pcap_t *pcd;
  if (pcap_findalldevs(&dev,errbuf) < 0) {
    std::cerr << errbuf;
    return;
  }
  if (pcap_lookupnet(dev_name.c_str(), &netp, &maskp, errbuf) == -1) {
    std::cerr << errbuf << "\n";
    return;
  }
  net_addr.s_addr = netp;
  net = inet_ntoa(net_addr);
  mask_addr.s_addr = maskp;
  mask = inet_ntoa(mask_addr);
  pcd = pcap_open_live(dev_name.c_str(), 4000,  NONPROMISCUOUS, -1, errbuf);
  if (pcd == NULL) {
    std::cerr << errbuf << "\n";
    return;
  }
  pcap_freealldevs(dev);
  if (pcap_compile(pcd, &fp, filter.c_str(), 0, netp) == -1) {
    std::cerr << "compile error\n";
    return;
  }
  if (pcap_setfilter(pcd, &fp) == -1) {
    std::cerr << "setfilter error\n";
    return;
  }
  pcap_loop(pcd, 0, callback, NULL);
  pcap_close(pcd);
}
