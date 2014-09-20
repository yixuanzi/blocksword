#include <stdio.h>
#include <pcap/pcap.h>
 
int main()
{
	pcap_t* pd;
	char ebuf[PCAP_ERRBUF_SIZE], *dev;
	const u_char* pkt;
	struct pcap_pkthdr ph;				 
	dev = pcap_lookupdev(ebuf);
	if (!dev) {
		fprintf(stderr, "%s\n", ebuf);
		return -1;
	 }
				   
	 printf("get net device -> %s\n", dev);
						  
	 pd = pcap_open_live(dev, 65535, 0, 0, ebuf);
	if (!pd) {
	      fprintf(stderr, "%s\n", ebuf);
	   return -1;
	}
						    
	pkt = pcap_next(pd, &ph);
	printf("A packet is captured.\n");
				  
	 pcap_close(pd);
									 
	return 0;
}
