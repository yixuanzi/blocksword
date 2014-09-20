#include "ip.h"
#include "sysconfig.h"
#include <stdio.h>
#include <stdlib.h>
#include "platform.h"
#include "tcp.h"
int ip_gethlenght(struct ipp *ip){
	if(ip==NULL){
		printf("function:ip_gethlenght参数错误，ip指针不能为空\n");
		exit(1);
	}
	return ip->vl.len*ip->vl.version;
}
struct tcpp* tcp_getstruct(struct ipp *ip){
	struct tcpp *tcp=NULL;
	ushort *offset=NULL;
	ushort value=0;
	int l=ip_gethlenght(ip);
	tcp=(struct tcpp *)((uchar *)ip+l);
	tcp->sport=ntohs(tcp->sport);
	tcp->dport=ntohs(tcp->dport);
	offset=(ushort *)&(tcp->ds);
	value=ntohs(*offset);
	tcp->ds.offset=value>>12;
	tcp->ds.retain=0;
	tcp->ds.fin=value&1?1:0;
	tcp->ds.syn=value&2?1:0;
	tcp->ds.rst=value&4?1:0;
	tcp->ds.psh=value&8?1:0;
	tcp->ds.ack=value&16?1:0;
	tcp->ds.urg=value&32?1:0;
	return tcp;
}

struct ipp* ip_getstruct(uchar *packet){
	struct ipp *ip=NULL;
	if(packet==NULL){
		printf("function:ip_getstruct参数错误，packet指针不能为空\n");
		exit(1);
	}
	ip=(struct ipp *)(packet+ETHERNET);
	//ip->sip=ntohl(ip->sip);
	//ip->dip=ntohl(ip->dip);
	return ip;
}
