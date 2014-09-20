#include "func.h"
#include <string.h>
#include <memory.h>
#include <stdlib.h>
#include <stdio.h>

extern char *cufile;
extern int culine;
int getfuncid(char *s){
	int i=0;
	char *p=s;
	if(s==NULL){
		printf("function error:getfuncid 参数错误，指针不可为空\n");
		exit(1);
	}
	p=s+i;
	if(strcmp("httpurl",p)==0)
		return FUNC_HTTPURL;
	if(strcmp("httpinfo",p)==0)
		return FUNC_HTTPINFO;
	if(strcmp("httpargs",p)==0)
		return FUNC_HTTPARGS;
	if(strcmp("httpgargs",p)==0)
		return FUNC_HTTPGARGS;
	if(strcmp("httppargs",p)==0)
		return FUNC_HTTPPARGS;
	if(strcmp("httpcookie",p)==0)
		return FUNC_HTTPCOOKIE;
	if(strcmp("httpagent",p)==0)
		return FUNC_HTTPAGENT;
	if(strcmp("httpserver",p)==0)
		return FUNC_HTTPSERVER;
	if(strcmp("httphead",p)==0)
		return FUNC_HTTPHEAD;
	if(strcmp("log",p)==0)
		return FUNC_LOG;
	if(strcmp("alert",p)==0)
		return FUNC_ALERT;
	if(strcmp("go",p)==0)
		return FUNC_GO;
	if(strcmp("icmpinfo",p)==0)
		return FUNC_ICMPINFO;
	if(strcmp("icmpdata",p)==0)
		return FUNC_ICMPDATA;
	if(strcmp("tcpinfo",p)==0)
		return FUNC_TCPINFO;
	if(strcmp("tcpdata",p)==0)
		return FUNC_TCPDATA;
	if(strcmp("udpinfo",p)==0)
		return FUNC_UDPINFO;
	if(strcmp("udpdata",p)==0)
		return FUNC_UDPDATA;
	return 0;
}
int getvarid_r(char *name,struct rule *r,int type){
	int i=0;
	for(i=0;i<10;i++){
		if(r->vb[i].name[0]=='\0')
			break;
		if(strcmp(name,r->vb[i].name)==0)
			return i;
	}
	if(i<10){
		strcpy(r->vb[i].name,name);
		if(type==1 ||type==2)
			r->vb[i].type=type; //标识变量类型，1 int ；2 string
		else
			r->vb[i].type=1;
		return i;
	}
	return 0;
}
int getvarid_f(char *name){
	if(strcmp(name,"#ICMP_TEYP")==0)
		return ICMP_TEYP;
	if(strcmp(name,"#ICMP_CODE")==0)
		return ICMP_CODE;
	if(strcmp(name,"#ICMP_LDATA")==0)
		return ICMP_LDATA;
	if(strcmp(name,"#TCP_SIP")==0)
		return TCP_SIP;
	if(strcmp(name,"#TCP_SPORT")==0)
		return TCP_SPORT;
	if(strcmp(name,"#TCP_DIP")==0)
		return TCP_DIP;
	if(strcmp(name,"#TCP_DPORT")==0)
		return TCP_DPORT;
	if(strcmp(name,"#HTTP_STATUS")==0)
		return HTTP_STATUS;
	if(strcmp(name,"#HTTP_DESC")==0)
		return HTTP_DESC;
	if(strcmp(name,"#HTTP_LURL")==0)
		return HTTP_LURL;
	if(strcmp(name,"#HTTP_LHOST")==0)
		return HTTP_LHOST;
	printf("Sytax error in %s ,line %d \n",cufile,culine);
	exit(1);
}
int getvarid(char *name,struct rule *r,int type){
	char *p=blank(name);
	if(p[0]=='$'){
		return getvarid_r(p,r,type);
	}else if(p[0]=='#'){
		return getvarid_f(p);
	}
	return 0;
}



char *blank(char *str){
	int i=0;
	while(str[i]){
		if(str[i]!=' ')
			return str+i;
		i++;
	}
	return NULL;
}
char *isstring(char *str){
	int i=0;
	char *p=blank(str);
	int two=0;
	while(str[i]){
		if(str[i]=='"' && two){
			str[i]='\0';
			return p+1;
		}else if(str[i]=='"' && !two){
			two=1;
		}
		i++;
	}
	return NULL;
}

int set_function(struct rule *r,struct function *f,char *fl){
	char *v1=NULL;
	char *v2=NULL;
	int i=0;
	int fid=0;
	while(fl[i]){
		if(fl[i]=='('){
			fl[i]='\0';
			v1=fl+i+1;
		}
		if(fl[i]==','){
			fl[i]='\0';
			v2=fl+i+1;
		}
		if(fl[i]==')'){
			fl[i]='\0';
		}
		i++;
	}
	fid=getfuncid(fl);
	switch (fid){
	case FUNC_LOG:
		set_log(r,f,v1);
		break;
	case FUNC_ALERT:
		set_alert(r,f,v1);
		break;
	case FUNC_GO:
		set_go(r,f,v1);
		break;
	case FUNC_ICMPINFO:
		set_icmpinfo(r,f,v1,v2);
		break;
	case FUNC_ICMPDATA:
		set_icmpdata(r,f,v1);
		break;
	case FUNC_TCPINFO:
		set_tcpinfo(r,f,v1,v2);
		break;
	case FUNC_TCPDATA:
		set_tcpdata(r,f,v1);
		break;
	case FUNC_UDPINFO:
		set_udpinfo(r,f,v1,v2);
		break;
	case FUNC_UDPDATA:
		set_udpdata(r,f,v1);
		break;
	case FUNC_HTTPINFO:
		set_httpinfo(r,f,v1,v2);
		break;
	case FUNC_HTTPURL:
		set_httpurl(r,f,v1);
		break;
	case FUNC_HTTPARGS:
		set_httpargs(r,f,v1,v2);
		break;
	case FUNC_HTTPGARGS:
		set_httpgargs(r,f,v1,v2);
	case FUNC_HTTPPARGS:
		set_httppargs(r,f,v1,v2);
		break;
	case FUNC_HTTPCOOKIE:
		set_httpcookie(r,f,v1);
		break;
	case FUNC_HTTPSERVER:
		set_httpserver(r,f,v1);
		break;
	case FUNC_HTTPAGENT:
		set_httpagent(r,f,v1);
		break;
	case FUNC_HTTPHEAD:
		set_httphead(r,f,v1);
	}
	return 0;
}
int set_addself(struct rule *r, struct function *f, char *var){
	int id = getvarid(var, r, 1);
	if (id>0){
		f->pt[0].id = id;
	}
	else{
		id = atoi(var);
		f->pt[0].value.var = id;
	}
	f->fid = 1;
	return 0;
}

int set_delself(struct rule *r, struct function *f, char *var){
	int id = getvarid(var, r, 1);
	if (id>0){
		f->pt[0].id = id; //规则变量编号
	}
	else{
		id = atoi(var);
		f->pt[0].value.var = id;//规则常量
	}
	f->fid = 2;
	return 0;
}
int set_greater(struct rule *r, struct function *f, char *var1,char *var2){
	int id1 = getvarid(var1, r, 1);
	int id2 = getvarid(var2,r,2);
	if (id1>0){
		f->pt[0].id = id1; //规则变量编号
	}
	else{
		id1 = atoi(var1);
		f->pt[0].value.var = id1;//规则常量
	}
	if (id2>0){
		f->pt[1].id = id2; //规则变量编号
	}
	else{
		id2 = atoi(var2);
		f->pt[1].value.var = id2;//规则常量
	}
	f->fid = 3;
	return 0;
}
int set_less(struct rule *r, struct function *f, char *var1,char *var2){
	int id1 = getvarid(var1, r, 1);
	int id2 = getvarid(var2,r,2);
	if (id1>0){
		f->pt[0].id = id1; //规则变量编号
	}
	else{
		id1 = atoi(var1);
		f->pt[0].value.var = id1;//规则常量
	}
	if (id2>0){
		f->pt[1].id = id2; //规则变量编号
	}
	else{
		id2 = atoi(var2);
		f->pt[1].value.var = id2;//规则常量
	}
	f->fid = 4;
	return 0;
}
int set_equal(struct rule *r, struct function *f, char *var1,char *var2){
	int id1 = getvarid(var1, r, 1);
	int id2 = getvarid(var2,r,2);
	if (id1>0){
		f->pt[0].id = id1; //规则变量编号
	}
	else{
		id1 = atoi(var1);
		f->pt[0].value.var = id1;//规则常量
	}
	if (id2>0){
		f->pt[1].id = id2; //规则变量编号
	}
	else{
		id2 = atoi(var2);
		f->pt[1].value.var = id2;//规则常量
	}
	f->fid = 5;
	return 0;
}
int set_unequal(struct rule *r, struct function *f, char *var1,char *var2){
	int id1 = getvarid(var1, r, 1);
	int id2 = getvarid(var2,r,2);
	if (id1>0){
		f->pt[0].id = id1; //规则变量编号
	}
	else{
		id1 = atoi(var1);
		f->pt[0].value.var = id1;//规则常量
	}
	if (id2>0){
		f->pt[1].id = id2; //规则变量编号
	}
	else{
		id2 = atoi(var2);
		f->pt[1].value.var = id2;//规则常量
	}
	f->fid = 6;
	return 0;
}
int set_log(struct rule *r, struct function *f, char *var){
	int id = getvarid(var, r, 2);
	char *p=NULL;
	if (id){
		if (r->vb[id].type != 2){
			printf("rule sytax error in %s ,line %d,函数log参数不合法\n", cufile, culine);
			exit(1);
		}
		f->pt[0].id = id;
		return 0;
	}
	if (!(p=isstring(var))){
		printf("rule sytax error in %s ,line %d,函数log参数不合法\n", cufile, culine);
		exit(1);
	}
	f->pt[0].value.str =(char*)malloc(strlen(p));
	strcpy(f->pt[0].value.str,p);
	f->fid=FUNC_LOG;
	return 0;
}
int set_alert(struct rule *r, struct function *f, char *var){
	int id = getvarid(var, r, 2);
	char *p=NULL;
	if (id){
		if (r->vb[id].type != 2){
			printf("rule sytax error in %s ,line %d,函数alert参数不合法\n", cufile, culine);
			exit(1);
		}
		f->pt[0].id = id;
		return 0;
	}
	if (!(p=isstring(var))){
		printf("rule sytax error in %s ,line %d,函数alert参数不合法\n", cufile, culine);
		exit(1);
	}
	f->pt[0].value.str =(char*)malloc(strlen(p));
	strcpy(f->pt[0].value.str,p);
	f->fid=FUNC_ALERT;
	return 0;
}
int set_go(struct rule *r, struct function *f, char *var){
}
int set_icmpinfo(struct rule *r, struct function *f, char *var1, char *var2){
}
int set_icmpdata(struct rule *r, struct function *f, char *var){
}
int set_tcpinfo(struct rule *r, struct function *f, char *var1, char *var2){
}
int set_tcpdata(struct rule *r, struct function *f, char *var){
}
int set_udpinfo(struct rule *r, struct function *f,char *var1,char *var2){
}
int set_udpdata(struct rule *r, struct function *f, char *var){
}
int set_httpinfo(struct rule *r, struct function *f,char *var1,char *var2){
}
int set_httpurl(struct rule *r, struct function *f, char *var){
	int id = getvarid(var, r, 2);
	char *p=NULL;
	if (id){
		if (r->vb[id].type != 2){
			printf("rule sytax error in %s ,line %d,函数alert参数不合法\n", cufile, culine);
			exit(1);
		}
		f->pt[0].id = id;
		return 0;
	}
	if (!(p=isstring(var))){
		printf("rule sytax error in %s ,line %d,函数alert参数不合法\n", cufile, culine);
		exit(1);
	}
	f->pt[0].value.str =(char*)malloc(strlen(p));
	strcpy(f->pt[0].value.str,p);
	f->fid=FUNC_HTTPURL;
	return 0;
}
int set_httpargs(struct rule *r, struct function *f, char *var1, char *var2){
}
int set_httpgargs(struct rule *r, struct function *f, char *var1, char *var2){
}
int set_httppargs(struct rule *r, struct function *f, char *var1, char *var2){
}
int set_httpcookie(struct rule *r, struct function *f, char *var){
}
int set_httpagent(struct rule *r, struct function *f, char *var){
}
int set_httpserver(struct rule *r, struct function *f, char *var){
}
int set_httphead(struct rule *r, struct function *f, char *var){
}


