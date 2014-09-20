#ifndef http_h
#define http_h
#include "sysconfig.h"
typedef struct{ //字符串结构
	char *str;
	int lenght;
}str,*pstr;

typedef struct{ //参数结构
	str name[10]; //参数名
	str value[10];//参数值
	int l;
}args,*pargs;

struct http_request{
	char *sip;
	char *dip;
	ushort sport;
	ushort dport;
	int method;
	str request;//请求行数据据
	str post;
	args httpargs;//请求参数
	str host;
	char *referer;
	char *agent;
	char *cookie;
	int lenght;
};

struct http_response{
	int code;//状态代码
	char desc[10];//描述
	char *location;//跳转
	char *server;//服务器
};
char *http_getline(char *);
int http_getrequest(uchar *,struct http_request *);
int http_getresponse(uchar *,struct http_response *);
int http_getmethod(char *);
int http_geturllen(char *);
int http_getvalue(char *, int *);
int http_isargs(struct http_request *);
int http_setarg(char *, struct http_request *);
int http_setresponse(char *, struct http_response *);
int search_c(char *, char);
int strlen_h(char *);
int strsearch_fl(char *, char *, int);
int strtoks(char *, char, int, int *);
#endif
