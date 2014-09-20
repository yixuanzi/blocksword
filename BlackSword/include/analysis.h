#ifndef __ANALYSIS__
#define __ANALYSIS__  
#include <pcap.h>
#include "type.h"
void displayMac(uchar *mac);
void displayIP(uchar *ip);
void udpanalysis(uchar *packet);
void tcpanalysis(uchar *packet);
void ipanalysis(uchar *packet);
void arpanalysis(uchar *packet);
void analysis(struct pcap_pkthdr *pkthdr,const uchar *packet);
#endif
