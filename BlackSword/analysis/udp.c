#include "udp.h"
#include "sysconfig.h"
#include "ip.h"
#include "platform.h"
uchar *udp_getdata(struct udpp *udp){
	uchar *p=(uchar *)udp;
	return p+sizeof(struct udpp);
}
struct udpp* udp_getstruct(struct ipp *ip){
	struct udpp *udp=(void*)0;
	int l=ip_gethlenght(ip);
	udp=(struct tcpp *)((uchar*)ip+l);
	udp->sport=ntohs(udp->sport);
	udp->dport=ntohs(udp->dport);
	return udp;
}
