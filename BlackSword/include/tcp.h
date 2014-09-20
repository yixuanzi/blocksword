#ifndef tcp_h
#define tcp_h
#include "sysconfig.h"
struct tcpp{
	ushort sport;
	ushort dport;
	uint seq;
	uint ack;
	struct dss{
		ushort offset:4;
		ushort retain:6;
		ushort urg:1;
		ushort ack:1;
		ushort psh:1;
		ushort rst:1;
		ushort syn:1;
		ushort fin:1;
	}ds;
	ushort window;
	ushort checksum;
	ushort urgp;
};
int tcp_checusum(struct tcpp*);
uchar* tcp_getdata(struct tcpp*);
int tcp_ishttp(uchar *);
#endif