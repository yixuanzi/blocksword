#ifndef icmp_h
#define icmp_h
#include "sysconfig.h"
#include "ip.h"
struct icmpp{
	uchar type;
	uchar code;
	ushort checksum;
	union{
		struct{
			ushort id;
			ushort seq;
		}echo; /* echo datagram */
		uint gateway; /* gateway address */
		struct{
			ushort __unused;
			ushort mtu;
		}frag; /* path mtu discovery */
	}un;
};

struct icmpp *icmp_getstruct(struct ipp*);
#endif
