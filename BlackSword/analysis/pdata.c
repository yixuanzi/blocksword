#include "pdata.h"
#include "http.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "abuse.h"
#include "derule.h"
#include "platform.h"
#include "eth.h"
extern struct sys_config gv;
void debug_printf_ip(struct ipp *ip){
	struct in_addr ip1,ip2;
	//int ip_int1=ntohl(ip->sip);
	//int ip_int2=ntohl(ip->dip);
	//ip1.S_un.S_addr=ip->sip;
	//ip2.S_un.S_addr=ip->dip;
	//printf("IP INT IP：%08x -> %08x\n",ip->sip,ip->dip);
	//printf("IP地址：%s ->",inet_ntoa(ip1));
	//printf(" %s\n",inet_ntoa(ip2));
}
void debug_printf_tcp(struct tcpp *tcp){
	printf("TCP端口：%d -> %d\n",tcp->sport,tcp->dport);
}
void debug_printf_udp(struct udpp *udp){
	printf("UDP端口：%d -> %d\n",udp->sport,udp->dport);
}
void debug_printf_icmp(struct icmpp *icmp){
	printf("ICMP数据：类型：%d	代码：%d\n",icmp->type,icmp->code);
}
void debug_printf_httpr(struct http_request *hr){
	printf("REQUEST：%s\n",hr->request.str);
	printf("HOST：%s\n",hr->host.str);
	printf("AGENT：%s\n",hr->agent);
	printf("COOKIE：%s\n",hr->cookie);
	printf("POST：%s\n",hr->post.str);
}
void debug_printf_httpp(struct http_response *hp){
	printf("CODE：%d\n",hp->code);
	printf("DESC：%s\n",hp->desc);
	printf("SERVER：%s\n",hp->server);
	printf("LOCATION：%s\n",hp->location);
}

int start_packet(struct info *cinfo,u_char *data){
	struct ipp *ip=ip_getstruct(data);
	//struct eth *ed=(struct eth *)data;
	struct iport ipt={0};
	int fg=0;
	ipt.sip = ip->sip;
	ipt.dip = ip->dip;
	debug_printf_ip(ip);
	if(ip->tp==6 &&(gv.sv.btcp || gv.sv.bhttp)){//开启tcp或http协议检测
		struct tcpp *tcp=tcp_getstruct(ip);
		uchar *dd=(uchar*)tcp;
		ipt.sport=tcp->sport;
		ipt.dport=tcp->dport;
		dd=tcp_getdata(tcp);
		fg=tcp_ishttp(dd);
		debug_printf_tcp(tcp);
		if(fg && gv.sv.bhttp){
			if(fg==1){
				struct http_request hr={0};
				printf("http request\n");
				http_getrequest(dd,&hr);
				debug_printf_httpr(&hr);
				abuse_http_request(&hr,cinfo,&ipt);
			}else if(fg==2){
				struct http_response hp={0};
				printf("http response\n");
				http_getresponse(dd,&hp);
				debug_printf_httpp(&hp);
				abuse_http_response(&hp,cinfo,&ipt);
			}
		}
		abuse_tcp(tcp,cinfo,&ipt);
	}else if(ip->tp==17 && gv.sv.budp){ //udp
		struct udpp *udp=udp_getstruct(ip);
		ipt.sport=udp->sport;
		ipt.dport=udp->dport;
		debug_printf_udp(udp);
		abuse_udp(udp,cinfo,&ipt);
	}else if(ip->tp==1 && gv.sv.bicmp){//icmp
		struct icmpp *icmp=icmp_getstruct(ip);
		ipt.sport=0;
		ipt.dport=0;
		debug_printf_icmp(icmp);
		abuse_icmp(icmp,cinfo,&ipt);
	}
	printf("========================================\n");
	return 0;
}
