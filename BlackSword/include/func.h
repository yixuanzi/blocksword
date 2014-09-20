#ifndef func_h
#define func_h
#include "derule.h"

#define FUNC_LOG 11
#define FUNC_ALERT 12
#define FUNC_GO 13
#define FUNC_ICMPINFO 14
#define FUNC_ICMPDATA 15
#define FUNC_TCPINFO 16
#define FUNC_TCPDATA 17
#define FUNC_UDPINFO 18
#define FUNC_UDPDATA 19
#define FUNC_HTTPINFO 20
#define FUNC_HTTPURL 21
#define FUNC_HTTPARGS 22
#define FUNC_HTTPGARGS 23
#define FUNC_HTTPPARGS 24
#define FUNC_HTTPCOOKIE 25
#define FUNC_HTTPAGENT 26
#define FUNC_HTTPSERVER 27
#define FUNC_HTTPHEAD 28

#define ICMP_TEYP 101
#define ICMP_CODE 102
#define ICMP_LDATA 103

#define TCP_SIP 111
#define TCP_SPORT 112
#define TCP_DIP 113
#define TCP_DPORT 114
#define TCP_FLAG 115

#define UDP_SIP 121
#define UDP_SPORT 122 
#define UDP_DIP 123
#define UDP_DPORT 124

#define HTTP_STATUS 131
#define HTTP_DESC 132
#define HTTP_LURL 133
#define HTTP_LHOST 134

int set_addself(struct rule *,struct function *,char *);
int set_delself(struct rule *,struct function *,char *);
int set_greater(struct rule *,struct function *,char *,char *);
int set_less(struct rule *,struct function *,char *,char *);
int set_equal(struct rule *,struct function *,char *,char *);
int set_unequal(struct rule *,struct function *,char *,char *);
int set_function(struct rule *,struct function *,char *);
int set_log(struct rule *,struct function *,char *);
int set_alert(struct rule *,struct function *,char *);
int set_go(struct rule *,struct function *,char *);
int set_icmpinfo(struct rule *,struct function *,char *,char *);
int set_icmpdata(struct rule *,struct function *,char *);
int set_tcpinfo(struct rule *,struct function *,char *,char *);
int set_tcpdata(struct rule *,struct function *,char *);
int set_udpinfo(struct rule *,struct function *,char *,char *);
int set_udpdata(struct rule *,struct function *,char *);
int set_httpinfo(struct rule *,struct function *,char *,char *);
int set_httpurl(struct rule *,struct function *,char *);
int set_httpargs(struct rule *,struct function *,char *,char *);
int set_httpgargs(struct rule *,struct function *,char *,char *);
int set_httppargs(struct rule *,struct function *,char *,char *);
int set_httpcookie(struct rule *,struct function *,char *);
int set_httpagent(struct rule *,struct function *,char *);
int set_httpserver(struct rule *,struct function *,char *);
int set_httphead(struct rule *,struct function *,char *);

int getfuncid(char *);
int getvarid(char *,struct rule*,int);
int getvarid_r(char *,struct rule *,int);
int getvarid_f(char *);
char *blank(char *);
char * isstring(char *);
#endif