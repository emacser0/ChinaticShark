#include "pcap_thread.hpp"
bool pcap_test(const std::string &dev_name,const std::string &filter) {
    char *net,*mask,errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *dev;
    bpf_u_int32 netp,maskp;
    in_addr net_addr, mask_addr;
    bpf_program fp;
    pcap_t *pcd;
    if (pcap_findalldevs(&dev,errbuf) < 0) {
      return false;
    }
    if (pcap_lookupnet(dev_name.c_str(), &netp, &maskp, errbuf) == -1) {
        return false;
    }
    net_addr.s_addr = netp;
    net = inet_ntoa(net_addr);
    mask_addr.s_addr = maskp;
    mask = inet_ntoa(mask_addr);
    pcd = pcap_open_live(dev_name.c_str(), 4000,  NONPROMISCUOUS, -1, errbuf);
    if (pcd == NULL) {
      return false;
    }
    pcap_freealldevs(dev);
    if (pcap_compile(pcd, &fp, filter.c_str(), 0, netp) == -1) {
      return false;
    }
    if (pcap_setfilter(pcd, &fp) == -1) {
      return false;
    }
    pcap_close(pcd);
    return true;
}
