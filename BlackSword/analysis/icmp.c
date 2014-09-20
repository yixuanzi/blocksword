#include "icmp.h"
#include "sysconfig.h"
#include "ip.h"
#include "platform.h"
struct icmpp* icmp_getstruct(struct ipp *ip){
	struct icmpp *icmp=(void*)0;
	int l=ip_gethlenght(ip);
	icmp=(struct icmpp *)((uchar*)ip+l);
	return icmp;
}
