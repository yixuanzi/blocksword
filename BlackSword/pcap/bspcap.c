#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif
#include "pdata.h"
#include "pcap.h"
#include <time.h>
#include "bspcap.h"

u_char data[1600]={0};
/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void getcurrent(){
	time_t rawtime;
	struct tm * timeinfo;
	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	printf ( "\007The current date/time is: %s", asctime (timeinfo) );
}
int run()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	struct bpf_program filter;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the device */
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	//filter
	pcap_compile(adhandle,&filter,"icmp||tcp||udp",1,0);
	pcap_setfilter(adhandle,&filter);

	/* start the capture */
	pcap_loop(adhandle, -1, packet_handler, NULL);
	pcap_close(adhandle);
	return 0;
}
void debug_printf_data(struct info *cinfo,u_char *data){
	int lenght=cinfo->lenght;
	int i=0;
	for(i=0;i<lenght;i++){
		printf("%02x ",data[i]);
		if((i+1)%16==0)
			printf("\n");
	}
	printf("\n");
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	struct info cinfo={0};
//	if(pkt_data[12]!=8)
	//	return;
	memcpy(data,pkt_data,header->caplen);
	cinfo.lenght=header->caplen;
	//debug_printf_data(&cinfo,data);
	//* convert the timestamp to readable format 
	local_tv_sec = header->ts.tv_sec;
	ltime=localtime(&local_tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	sprintf(cinfo.time,"%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	//printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	start_packet(&cinfo,data);
}
