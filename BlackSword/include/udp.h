#ifndef udp_h
#define udp_h
#include "sysconfig.h"
#include "ip.h"
struct udpp{
	ushort sport;
	ushort dport;
	ushort lenght;
	ushort chucksum;
};
int udp_checusum(struct udpp*);
unsigned char* udp_getdata(struct udpp*);
struct udpp* udp_getstruct(struct ipp *);
#endif
