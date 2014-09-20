#ifndef ip_h
#define ip_h
#include "sysconfig.h"

struct ipp{
	struct{
		unsigned char version:4; //版本号
		unsigned char len:4; //头长度=version*len
	}vl;
	unsigned char tos;//tos,服务代码
	ushort lenght;//包长度
	ushort id;
	struct{
		ushort flag:3;
		ushort offset:13;
	}fos;
	unsigned char ttl; //生存时间
	unsigned char tp; //协议类型
	ushort chsum;
	uint sip;
	uint dip;
};
#define ETHERNET 14
struct ipp* ip_getstruct(uchar *);//返回ipp指针
int ip_gethlenght(struct ipp *);//返回IP包头长
struct tcpp * tcp_getstruct(struct ipp *);//返回数据指针
int ip_checksum(struct ipp *);//校验和是否正确
#endif

