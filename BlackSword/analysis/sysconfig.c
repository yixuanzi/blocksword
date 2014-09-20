#include "sysconfig.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "platform.h"

struct sys_config gv={0};
char *rulep[20]={0};
char *modulep[20]={0};

int sysconfig(char *p){
	FILE *fp=NULL;
	char line[1024]={0};
	int ln=0;
	int status=0;
	if(!p)
		return 1;
	fp=fopen(p, "r");
	if(!fp)
		return 2;
	while(1){
		if(fgets(line,1023,fp)){
			ln++;
			if(line[0]=='#' || line[0]=='\r' || line[0]=='\n')
				continue;
			if(lineto(line,ln)==1){
				status=1;
			}
		}else
			break;
	}
	if(status)
		exit(0);
	fclose(fp);
	return 0;
}
//解析配置文件，根据数据行
int lineto(char *p,int line){
	char *name=NULL;
	char *value=NULL;
	int i = 0;
	int l=0;
	while(p[i]){
		if(p[i]=='='){
			name=p;
			value=p+i+1;
			p[i]='\0';
		}else if(p[i]=='\n'){
			p[i]='\0';
		}
		i++;
	}
	if(!value || !name){
		printf("配置文件发送语法错误，在%d行\n",line);
		return 1;
	}

	l=strlen(value);
	if(strcmp(LOCAL_IP,name)==0){
		gv.sv.ip=inet_addr(value);
		return 0;
	}
	if(strcmp(LOCAL_MASK,name)==0){
		gv.sv.mask = inet_addr(value);
		return 0;
	}
	if(strcmp(LOCAL_PATH,name)==0){
		gv.sv.rpath=(char *)malloc(l+1);
		memcpy(gv.sv.rpath,value,l+1);
		return 0;
	}
	if(strcmp(INSPERCT_HTTP,name)==0){
		if(strcmp(value,"on")==0)
			gv.sv.bhttp=1;
		else
			gv.sv.bhttp=0;
		return 0;
	}
	if(strcmp(INSPERCT_TCP,name)==0){
		if(strcmp(value,"on")==0)
			gv.sv.btcp=1;
		else
			gv.sv.btcp=0;
		return 0;
	}
	if(strcmp(INSPERCT_UDP,name)==0){
		if(strcmp(value,"on")==0)
			gv.sv.budp=1;
		else
			gv.sv.budp=0;
		return 0;
	}
	if(strcmp(INSPERCT_ICMP,name)==0){
		if(strcmp(value,"on")==0)
			gv.sv.bicmp=1;
		else
			gv.sv.bicmp=0;
		return 0;
	}
	if(strcmp(AUDIT_ALERT,name)==0){
		if(strcmp(value,"on")==0)
			gv.sv.alert=1;
		else
			gv.sv.alert=0;
		return 0;
	}
	if(strcmp(AUDIT_LOG,name)==0){
		if(strcmp(value,"on")==0)
			gv.sv.log=1;
		else
			gv.sv.log=0;
		return 0;
	}
	if(strcmp(DYNAMIC_MODULE,name)==0){
		if(strcmp(value,"on")==0)
			gv.sv.dym=1;
		else
			gv.sv.dym=0;
		return 0;
	}
	if(strcmp(DECODE_STREAM,name)==0){
		if(strcmp(value,"on")==0)
			gv.dd.stream=1;
		else
			gv.dd.stream=0;
		return 0;
	}
	if(strcmp(IGNORE_IP,name)==0){
		for(i=0;i<10;i++){
			if (gv.dd.igip[i] == 0){
				gv.dd.igip[i] = inet_addr(value);
				break;
			}
		}
		return 0;
	}
	if(strcmp(IGNORE_PORT,name)==0){
		for (i = 0; i < 10; i++){
			if(gv.dd.igport[i]==0){
				gv.dd.igport[i]=atoi(value);
				break;
			}
		}
		return 0;
	}
	if(strcmp(RULE_IGNORE_CHAR,name)==0){
		strncpy(gv.dr.ic,value,9);
		return 0;
	}
	if(strcmp(RULE_IGNORE_IP,name)==0){
		for(i=0;i<10;i++){
			if(gv.dr.igip[i]==0){
				gv.dr.igip[i] = inet_addr(value);
				break;
			}
		}
		return 0;
	}
	if(strcmp(RULE_IGNORE_PORT,name)==0){
		for(i=0;i<10;i++){
			if(gv.dr.igport[i]==0){
				gv.dr.igport[i]=atoi(value);
				break;
			}
		}
		return 0;
	}
	if(strcmp(RULE_DECODE_MSG1,name)==0){
		gv.dr.msg1=(char *)malloc(l+1);
		memcpy(gv.dr.msg1,value,l+1);
		return 0;
	}
	if(strcmp(RULE_DECODE_MSG2,name)==0){
		gv.dr.msg2=(char *)malloc(l+1);
		memcpy(gv.dr.msg2,value,l+1);
		return 0;
	}
	if(strcmp(RULE_DECODE_MSG3,name)==0){
		gv.dr.msg3=(char *)malloc(l+1);
		memcpy(gv.dr.msg3,value,l+1);
		return 0;
	}
	if(strcmp(OUT_TYPE,name)==0){
		if(strcmp(value,"text")==0){
			gv.op.type=1;
		}
		return 0;
	}
	if(strcmp(ABUSER_ALERT,name)==0){
		gv.op.abalert=(char *)malloc(l+1);
		memcpy(gv.op.abalert,value,l+1);
		return 0;
	}
	if(strcmp(ABUSER_LOG,name)==0){
		gv.op.ablog=(char *)malloc(l+1);
		memcpy(gv.op.ablog,value,l+1);
		return 0;
	}
	if(strcmp(REASON_ALERT,name)==0){
		gv.op.realert=(char *)malloc(l+1);
		memcpy(gv.op.realert,value,l+1);
		return 0;
	}
	if(strcmp(REASON_LOG,name)==0){
		gv.op.relog=(char *)malloc(l+1);
		memcpy(gv.op.relog,value,l+1);
		return 0;
	}
	if(strcmp(ABUSER_ALERT_FORMAT,name)==0){
		gv.op.abaformat=(char *)malloc(l+1);
		memcpy(gv.op.abaformat,value,l+1);
		return 0;
	}
	if(strcmp(ABUSER_LOG_FORMAT,name)==0){
		gv.op.ablformat=(char *)malloc(l+1);
		memcpy(gv.op.ablformat,value,l+1);
		return 0;
	}
	if(strcmp(REASON_ALERT_FORMAT,name)==0){
		gv.op.reaformat=(char *)malloc(l+1);
		memcpy(gv.op.reaformat,value,l+1);
		return 0;
	}
	if(strcmp(REASON_LOG_FORMAT,name)==0){
		gv.op.relformat=(char *)malloc(l+1);
		memcpy(gv.op.relformat,value,l+1);
		return 0;
	}
	if(strcmp(RULE_FILE,name)==0){
		for(i=0;i<20;i++){
			if(rulep[i]==NULL){
				rulep[i]=(char *)malloc(l+1);
				strcpy(rulep[i],value);
				break;
			}
		}
	}
	if(strcmp(DYNAMIC_FILE,name)==0){
		for(i=0;i<20;i++){
			if(modulep[i]==NULL){
				modulep[i]=(char *)malloc(l+1);
				strcpy(modulep[i],value);
				break;
			}
		}
	}
	return 0;
}

