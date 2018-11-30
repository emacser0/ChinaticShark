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
    result_header.push_front(process_packet(pkthdr,packet));
  }
}

void init_pcap_thread(int argc, char **argv) {

    char *net,*mask,errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *dev;
    bpf_u_int32 netp,maskp;
    in_addr net_addr, mask_addr;
    bpf_program fp;
    pcap_t *pcd;  // packet capture descriptor
    if (pcap_findalldevs(&dev,errbuf) < 0) {
      std::cerr << errbuf;
      exit(1);
    }
    std::cout << "DEV : " << dev->name << "\n";
    if (pcap_lookupnet(dev->name, &netp, &maskp, errbuf) == -1) {
      std::cerr << errbuf << "\n";
      exit(1);
    }
    net_addr.s_addr = netp;
    net = inet_ntoa(net_addr);
    mask_addr.s_addr = maskp;
    mask = inet_ntoa(mask_addr);
    std::cout << "NET : " << net << "\n"
              << "MSK : " << mask << "\n"
              << "=======================\n";
    pcd = pcap_open_live(dev->name, 4000,  NONPROMISCUOUS, -1, errbuf);
    if (pcd == NULL) {
      std::cerr << errbuf << "\n";
      exit(1);
    }
    std::string filter;
    for(int i=1;i<argc;i++) {
      filter+=argv[i];
      filter+=" ";
    }
    pcap_freealldevs(dev);
    if (pcap_compile(pcd, &fp, filter.c_str(), 0, netp) == -1) {
      std::cout << "compile error\n";
      exit(1);
    }
    if (pcap_setfilter(pcd, &fp) == -1) {
      std::cerr << "setfilter error\n";
      exit(0);
    }
    pcap_loop(pcd, 0, callback, NULL);
}
