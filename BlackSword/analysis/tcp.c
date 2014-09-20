#include "tcp.h"
#include "sysconfig.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include "platform.h"
uchar* tcp_getdata(struct tcpp *tcp){
	uchar *p=NULL;
	if(tcp==NULL){
		printf("function:tcp_getdata参数错误，tcp指针不能为空\n");
		exit(1);
	}
	p=(uchar *)tcp;
	return p+(tcp->ds.offset*4);
}
int tcp_ishttp(uchar *data){
	char ds[8]={0};
	memcpy(ds,data,7);
	ds[7]='\0';
	if(strstr(ds,"GET") ||
		strstr(ds,"POST") ||
		strstr(ds,"HEAD")||
		strstr(ds,"PUT")||
		strstr(ds,"DELETE")||
		strstr(ds,"OPTIONS")){
			return 1;
	}
	if(strstr(ds,"HTTP"))
		return 2;
	return 0;
}
	