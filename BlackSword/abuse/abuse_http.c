#include "abuse.h"
#include "derule.h"
#include <stdio.h>
#include <stdlib.h>

extern struct rulelink *rks;
extern struct http_request *chr;
extern struct http_response *chp;

int abuse_http_request(struct http_request *hr,struct info *cinfo,struct iport *ipt){
	/*struct rulelink *current=rks;
	struct rule *r=rks->hlk;
	chr=hr;
	if(!hr || !cinfo){
		printf("function error:abuser_http_request 参数hr和info不能为空\n");
		exit(1);
	}
	while(current){
		if(!isame(ipt,(struct iport*)current)){
			current=current->next;
			continue;
		}
		if(r->type==1){
			struct rtime *rt=(struct rtime*)r->tp.rt;
			callfunc(r,rt->fn,hr,1);
		}else if(r->type==2){
			struct rprocess *rp=(struct rprocess*)r->tp.rp;
		}
		current=current->next;
	}*/

	return 0;
}
int abuse_http_response(struct http_response *hp, struct info *cinfo, struct iport *ipt){
}
int _httpinfo(struct rule *r,struct variable_func *var){
}
int _httpurl(struct rule *r,struct variable_func *var){
}
int _httpargs(struct rule *r,struct variable_func *var){
}
int _httpgargs(struct rule *r,struct variable_func *var){
}
int _httppargs(struct rule *r,struct variable_func *var){
}
int _httpcookie(struct rule *r,struct variable_func *var){
}
int _httpagent(struct rule *r,struct variable_func *var){
}
int _httpserver(struct rule *r,struct variable_func *var){
}
int _httphead(struct rule *r,struct variable_func *var){
}


