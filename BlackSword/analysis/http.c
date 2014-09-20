#include "http.h"
#include "sysconfig.h"
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <string.h>
#include <stdlib.h>


int http_getmethod(char *data){
	if(strsearch_fl(data,"GET",3)){
		return 1;
	}
	if(strsearch_fl(data,"POST",4)){
		return 2;
	}
	if(strsearch_fl(data,"HEAD",4)){
		return 3;
	}
	if(strsearch_fl(data,"DELETE",6)){
		return 4;
	}
	if(strsearch_fl(data,"OPTIONS",7)){
		return 5;
	}
	if(strsearch_fl(data,"PUT",3)){
		return 6;
	}
	return 0;
}

int strsearch_fl(char *src,char *sub,int l){
	int i=0;
	if(l){
		for(i=0;i<l;i++){
			if(src[i]!=sub[i])
				return 0;
		}
		return 1;
	}
	return 0;
}
int http_getvalue(char *data,int *l){
	
	if(strsearch_fl(data,"Host:",5)){
		*l=6;
		return 1;
	}else if(strsearch_fl(data,"User-Agent:",11)){
		*l=12;
		return 2;
	}else if(strsearch_fl(data,"Cookie:",7)){
		*l=8;
		return 3;
	}else if(strsearch_fl(data,"Referer:",8)){
		*l=9;
		return 4;
	}else if(strsearch_fl(data,"Content-Length:",15)){
		*l=16;
		return 5;
	}else if(strsearch_fl(data,"Server:",7)){
		*l=8;
		return 6;
	}else if(strsearch_fl(data,"Location:",9)){
		*l=10;
		return 7;
	}
	return 0;
}
//根据换行符进行字符串分割，并返回长度
int strlen_h(char *s){
	int i=0;
	while(s[i]!='\r'){
		i++;
	}
	s[i]='\0';
	return i;
}
int http_geturllen(char *url){
	int i =0;
	while(url[i]!=' ')
		i++;
	url[i]='\0';
	return i;
}
int http_isargs(struct http_request *hr){
	if(hr->method==1 || hr->method==2)
		return 1;
	return 0;
}
char httpdata[1600]={0};
int http_getrequest(uchar *data,struct http_request *hr){
	char *cu=(char*)data;
	int len=0;
	int tmp=0;
	int status=0;
	memcpy(httpdata,data,1600);
	len=strlen_h(cu);
	if(len>500)
		printf("why");
	memset(httpdata,0,15*1024);
	hr->method=http_getmethod(cu);
	hr->request.str=cu;
	hr->request.lenght=len;
	cu=cu+len+2;
	len=strlen_h(cu);
	while(cu){
		status=http_getvalue(cu,&tmp);
		switch (status)
		{
		case 1:
			hr->host.str=cu+tmp;
			hr->host.lenght=len-tmp;
			cu=cu+len+2;
			break;
		case 2:
			hr->agent=cu+tmp;
			cu=cu+len+2;
			break;
		case 3:
			hr->cookie=cu+tmp;
			cu=cu+len+2;
			break;
		case 4:
			hr->referer=cu+tmp;
			cu=cu+len+2;
			break;
		case 5:
			hr->lenght=atoi(cu+tmp);
			cu=cu+len+2;
			break;
		default:
			printf("%s\n",cu);
			cu=cu+len+2;
			break;
		}
		if(!(len=strlen_h(cu)))
			break;
	}
	if(hr->method==1){//GET 参数格式化
		char request[1024]={0};
		char *delim = "&";
		char *args=NULL;
		char *arg=NULL;
		strncpy(request,hr->request.str,1023);
		args=(char*)(request+search_c(request,'?')+1);
		printf("%s\n",args);
		/*
		arg=strtok(args, delim);
		while(arg){
			http_setarg(arg, hr);
			arg = strtok(NULL, delim);
		}
		*/
	}else if(hr->method==2){//POST
		hr->post.str=cu+2;
		hr->post.lenght=hr->lenght;
	}
	/*	int lenght=hr->lenght;
		int vl=0;
		int seq=0;
		char *arg=NULL;
		cu=cu+2;
		seq = strtoks(cu, '&', lenght, &vl);
		arg = cu + seq;
		while(seq!=-1){
			http_setarg(arg, hr, vl);
			seq = strtoks(NULL, '&',0, &vl);
			arg = cu + seq;
		}*/
return 0;
}
int strtoks(char *data,char c,int len,int *vl){
	static int i=0;
	static char *pd=NULL;
	static int lenght=0;
	int p = -1;
	int j=0;
	if (data != NULL){
		i = 0;
		pd = data;
		lenght = len;
	}
	p = i;
	while (i<lenght){
		if (pd[i] == c){
			pd[i] = '\0';
			*vl = j;
			i++;
			return p;
		}
		i++;
		j++;
	}
	return 0;
}
char *getvarname(char *data){
	int i=0;
	char *p=NULL;
	while(data[i]!='=' && data[i])
		i++;
	p=(char*)malloc(i+1);
	if(!p){
		printf("分配内存失败，函数getvarname\n");
		exit(1);
	}
	strncpy(p,data,i);
	return p;
}
char *getvarvalue(char *data){
	int i=0;
	char *p=NULL;
	char *value=NULL;
	while(data[i]!='=' && data[i])
		i++;
	value=data+i+1;
	i=0;
	while(value[i] && value[i]!=' ')
		i++;
	p=(char*)malloc(i+1);
	if(!p){
		printf("分配内存失败，函数getvarvalue\n");
		exit(1);
	}
	strncpy(p,value,i);
	return p;
}
int http_setarg(char *data,struct http_request *hr){
	int l=hr->httpargs.l;
	char *name=NULL;
	char *value=NULL;
	int lname = 0;
	int lvalue = 0;
	if(l>=10)
		return -1;
	name=getvarname(data);
	lname=strlen(name);
	value=getvarvalue(data);
	lname=strlen(value);
	hr->httpargs.name[l].str=name;
	hr->httpargs.name[l].lenght=lname;
	hr->httpargs.value[l].str=value;
	hr->httpargs.value[l].lenght=lvalue;
	hr->httpargs.l=l+1;
	/*
	while(i<len){
		if(data[i]=='\0')
			break;
		if(data[i]=='='){
			data[i]='\0';
			lname=i;
		}
		i++;
	}
	if(len==1024)
		lvalue=i-lname-1;
	else
		lvalue=i-lname;
	hr->httpargs.name[i].str=data;
	hr->httpargs.name[i].lenght=lname;
	hr->httpargs.value[i].str=data+lname+1;
	hr->httpargs.value[i].lenght=lvalue;
	hr->httpargs.l=l+1;
	return 0;*/
}
int search_c(char *s,char c){
	int i=0;
	while(s[i]){
		if(s[i]==c)
			return i;
		i++;
	}
	return -1;
}
int http_setresponse(char *s,struct http_response *hp){
	int i=0;
	char *p=strtok(s," ");
	while(p){
		if(i==1)
			hp->code=atoi(p);
		else if(i==2)
			strcpy(hp->desc,p);
		p=strtok(NULL," ");
		i++;
	}
	return 0;
}

int http_getresponse(uchar *data,struct http_response *hp){
	char *cu=(char*)data;
	int status=0;
	int tmp=0;
	int len=0;
	memcpy(httpdata,data,1600);
	len=strlen_h(cu);
	http_setresponse(cu,hp);
	cu=cu+len+2;
	len=strlen_h(cu);
	while(cu){
		status=http_getvalue(cu,&tmp);
		switch (status)
		{
		case 6:
			hp->server=cu+tmp;
			cu=cu+len+2;
			break;
		case 7:
			hp->location=cu+tmp;
			cu=cu+len+2;
			break;
		default:
			printf("%s\n",cu);
			cu=cu+len+2;
			break;
		}
		if(!(len=strlen_h(cu)))
			break;
	}
	return 0;
}

