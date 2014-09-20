#include "abuse.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "func.h"
struct http_request *chr=NULL; //1
struct http_response *chp=NULL;//2
struct tcpp *ctcp=NULL;//3
struct udpp *cudp=NULL;//4
struct icmpp *cicmp=NULL;//5
int getvarvalue_i(struct rule *r,struct variable_func *var){
	int id=var->id;
	if(id)
		return r->vb[id].value.var;
	else
		return var->value.var;
}
char *getvarvalue_s(struct rule *r,struct variable_func *var){
	int id=var->id;
	if(id)
		return r->vb[id].value.str;
	else
		return var->value.str;
}
int callfunc(struct rule *r,struct function *f,void *dp,int type){
	int i=0;
	int fid=f->fid;	
	for(i=0;i<10;i++){
		if(!fid)
			break;
		switch (fid)
		{
		case 1:
			_addself(r,f->pt);
			break;
		case 2:
			_delself(r,f->pt);
			break;
		case 3:
			_greater(r,f->pt);
			break;
		case 4:
			_less(r,f->pt);
			break;
		case 5:
			_equal(r,f->pt);
			break;
		case 6:
			_unequal(r,f->pt);
			break;
		case FUNC_LOG:
			_log(r,f->pt);
		case FUNC_ALERT:
			_alert(r,f->pt);
		
		}
	}
}

int _addself(struct rule *r,struct variable_func *var){
	int id=var->id;
	if(id){
		r->vb[id].value.var++;
		return 1;
	}
	return -1;
}
int _delself(struct rule *r,struct variable_func *var){
	int id=var->id;
	if(id){
		r->vb[id].value.var--;
		return 1;
	}
	return -1;
}

int _greater(struct rule *r,struct variable_func *var){
	int v1=getvarvalue_i(r,var);
	int v2=getvarvalue_i(r,(struct variable_func *)(var+1));
	if(v1>v2)
		return 1;
	return 0;
}
int _less(struct rule *r,struct variable_func *var){
	int v1=getvarvalue_i(r,var);
	int v2=getvarvalue_i(r,(struct variable_func *)(var+1));
	if(v1<v2)
		return 1;
	return 0;
}
int _equal(struct rule *r,struct variable_func *var){
	int v1=getvarvalue_i(r,var);
	int v2=getvarvalue_i(r,(struct variable_func *)(var+1));
	if(v1==v2)
		return 1;
	return 0;
}
int _unequal(struct rule *r,struct variable_func *var){
	int v1=getvarvalue_i(r,var);
	int v2=getvarvalue_i(r,(struct variable_func *)(var+1));
	if(v1!=v2)
		return 1;
	return 0;
}

int _log(struct rule *r,struct variable_func *var){
	char *s=getvarvalue_s(r,var);
	printf("\nLOG: %s\n\n",s);
	return 1;
}
int _alert(struct rule *r,struct variable_func *var){
	char *s=getvarvalue_s(r,var);
	printf("\nALERT: %s\n\n",s);
	return 1;
}
int _go(struct rule *r,struct variable_func *var){
}
int _icmpinfo(struct rule *r,struct variable_func *var){
}
int _icmpdata(struct rule *r,struct variable_func *var){
}
int _tcpinfo(struct rule *r,struct variable_func *var){
}
int _tcpdata(struct rule *r,struct variable_func *var){
}
int _udpinfo(struct rule *r,struct variable_func *var){
}
int _udpdata(struct rule *r,struct variable_func *var){
}

