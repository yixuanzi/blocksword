#ifndef pdata_h
#define pdata_h
#include <time.h>
#include "pcap.h"
#include "sysconfig.h"
#include "bspcap.h"

struct tcp_stream{
	int ts;
};
union tyhead{
	struct head_icmp *hi; //icmp协议关键数据结构指针
	struct head_tcp *ht;//同上，tcp协议
	struct head_udp *hu;//同上，udp协议
	struct head_http_request *hrq;//同上，http请求
	struct head_http_respon *hrs;//同上，http响应
};
struct pdata{
	int type;//类型，packet或者stream
	union tyhead td;
};
struct packet{
	time_t time;//接收数据包时间
	int protocol;//最上层协议
	union tyhead th;//
	char *data;
	int len;
};
struct stream{
	struct head_http_request *hrq;
	struct head_http_respon *hrs;
	struct tcp_stream *ts;//tcp流结构
};
union tydata{
	struct packet *pt;
	struct stream *sm;
};
struct head_http_requst{
	char *request;//http请求行，包括方法，url和http协议版本
	char *method;
	char *url;
	char *host;
	char *cookie;
	struct http_args **hargs;//http请求参数二维数组指针
};

int start_packet(struct info *,u_char *);

int start_stream(struct tcp_stream *,time_t);

#endif