#ifndef PCAP_THREAD_HPP
#define PCAP_THREAD_HPP
#include <QApplication>
#include <pcap/pcap.h>
#include <iostream>
#include <deque>
#include "header_processor.hpp"
#define PROMISCUOUS 1
#define NONPROMISCUOUS 0
extern bool stop;
extern std::deque<ProcessedHeader> result_header;

void
callback(u_char *useless,
         const pcap_pkthdr *pkthdr,
         const u_char *packet);
void init_pcap_thread(int argc, char **argv);
#endif // PCAP_THREAD_HPP
