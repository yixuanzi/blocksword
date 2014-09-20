#ifndef abuse_h
#define abuse_h
#include "tcp.h"
#include "sysconfig.h"
#include "icmp.h"
#include "udp.h"
#include "http.h"
#include "derule.h"
#include <pcap.h>
#include "bspcap.h"
int abuse_tcp(struct tcpp *,struct info *,struct iport *);
int abuse_http_request(struct http_request *,struct info *,struct iport *);
int abuse_http_response(struct http_response *,struct info *,struct iport *);
int abuse_udp(struct udpp *,struct info *,struct iport *);
int abuse_icmp(struct icmpp *,struct info *,struct iport *);

int getfuncid(char *);
int callfunc(struct rule *,struct function *,void *,int);
int getvarvalue_i(struct rule *r,struct variable_func *var);
char *getvarvalue_s(struct rule *r,struct variable_func *var);

int _addself(struct rule *,struct variable_func *);
int _delself(struct rule *,struct variable_func *);
int _greater(struct rule *,struct variable_func *);
int _less(struct rule *,struct variable_func *);
int _equal(struct rule *,struct variable_func *);
int _unequal(struct rule *,struct variable_func *);

int _log(struct rule *,struct variable_func *);
int _alert(struct rule *,struct variable_func *);
int _go(struct rule *,struct variable_func *);
int _icmpinfo(struct rule *,struct variable_func *);
int _icmpdata(struct rule *,struct variable_func *);
int _tcpinfo(struct rule *,struct variable_func *);
int _tcpdata(struct rule *,struct variable_func *);
int _udpinfo(struct rule *,struct variable_func *);
int _udpdata(struct rule *,struct variable_func *);
int _httpinfo(struct rule *,struct variable_func *);
int _httpurl(struct rule *,struct variable_func *);
int _httpargs(struct rule *,struct variable_func *);
int _httpgargs(struct rule *,struct variable_func *);
int _httppargs(struct rule *,struct variable_func *);
int _httpcookie(struct rule *,struct variable_func *);
int _httpagent(struct rule *,struct variable_func *);
int _httpserver(struct rule *,struct variable_func *);
int _httphead(struct rule *,struct variable_func *);
#endif
