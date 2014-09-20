#include "derule.h"
#include "abuse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "func.h"
extern char *rulep[20];
extern struct sys_config gv;
struct rulelink *rks=NULL;
char *cufile=NULL;
int culine;

int createrulelink(){//从规则文件路径数组中创建规则链
	int i=0;
	int status;
	while(rulep[i]){
		status=createrulelink_f(rulep[i]);
		if(status==1){
			printf("规则文件打开失败，请检测：%s\n",rulep[i]);
		}
		if(i==19)
			break;
		i++;
	}
	return 0;
}
int getpath(char *path,char *file){
	char *p=NULL;
	if(file[0]=='$'){
		if(!(p=strstr(file,"\\"))){
			if(!(p=strstr(file,"/"))){
				return -1;
			}
		strcpy(path,gv.sv.rpath);
		strcat(path,p);
	}else{
		strcpy(path,file);
	}
	}
	return 0;
}
int createrulelink_f(char *file){ //解析文件
	char path[120]={0};
	char line[1024] = { 0 };
	char *data[10]={0};
	struct ruledata rd={0};
	FILE *fp;
	int status=0;
	culine=0;
	getpath(path,file);
	cufile=path;
	if(!(fp=fopen(path,"r"))){
		printf("指定规则文件%s不存在\n",path);
		exit(1);
	}
	while (1){ //遍历规则文件，以行模式
		int i = 0;
		int j = 1;
		if(!fgets(line, 1023, fp))
			break;
		culine++;
		if(isignore(line[0])) //判断行首字符是不是注释符
			break;
		data[0] = line;
		while (line[i]){ //以空格分割规则成10部分
			if (line[i] == ' '){
				line[i] = '\0';
				data[j] = (char *)(line + i+1);
				j++;
			}
			i++;
			if (j == 10)
				break;
		}
		if(islegal(data,culine)){ //验证规则合法性
			exit(0);
		}
		
		datatostruct(data,&rd); //从规则中提取出数据，获得ruledata结构
		linetorules(&rd);//使用ruledata数据结构中数据转化成规则体，挂载到rks规则链中
	}
	return 0;
}

int isame(struct iport *iport1, struct iport *iport2){
	if (iport1->sip == 0 ||
		iport2->sip == 0 ||
		iport1->sip == iport2->sip){
		if (iport1->sport == 0 ||
			iport2->sport == 0 ||
			iport2->sport == iport2->sport){
			if (iport1->dip == 0 ||
				iport2->dip == 0 ||
				iport1->sip == iport2->dip){
				if (iport1->dport == 0 ||
					iport2->dport == 0 ||
					iport2->dport == iport2->dport){
					return 1;
				}
			}
		}
	}
	return 0;
}
//对比地址是否相等
int isame_both(struct iport *iport1, struct iport *iport2,int both){
	//两者单向数据流
	struct iport ipt = { 0 };
	if (!both){
		return isame(iport1, iport2);
	}
	//第二个参数双向
	if (both == 2){
		ipt.sip = iport2->dip;
		ipt.sport = iport2->dport;
		ipt.dip = iport2->sip;
		ipt.dport = iport2->sport;
		return isame(iport1, iport2) || isame(iport1, &ipt)+2;
	}
	//第一个参数双向
	if (both == 1){
		ipt.sip = iport1->dip;
		ipt.sport = iport1->dport;
		ipt.dip = iport1->sip;
		ipt.dport = iport1->sport;
		return isame(iport1, iport2) || isame(&ipt, iport2)+1;
	}
	return 0;
}
int isignore(char c){
	int i = 0;
	while (gv.dr.ic[i] != '\0'){
		if (gv.dr.ic[i] == c)
			return 1;
		i++;
	}
	return 0;
}
int isip(char *ip){
	return 1;
}
int isport(char *port){
	return 1;
}
int isuniq(int id){
	return 1;
}
int isid(char *id){
	return 1;
}
int islegal(char *data[],int ln){
	int id=0;
	if (strcmp(data[0], "BSRule") != 0){
		printf("规则语句出现语法错误，规则头应为BSRule，在 %d 行\n",ln);
		return 1;
	}
	if (strcmp(data[1], "http") != 0 &&
		strcmp(data[1], "tcp") != 0 &&
		strcmp(data[1], "udp") != 0 &&
		strcmp(data[1], "tcp") != 0){
		printf("规则语句出现语法错误，协议类型错误，在 %d 行\n",ln);
		return 2;
	}
	if (!isip(data[2]) || !isport(data[3])){
		printf("规则语句出现语法错误，第一部分IP或端口数据错误，在 %d 行\n",ln);
		return 3;
	}
	if (strcmp(data[4],"->")!=0 &&
		strcmp(data[4],"<-")!=0 &&
		strcmp(data[4],"<->")!=0 ){
			printf("规则语句出现语法错误，数据流方向符错误，在 %d 行\n",ln);
			return 4;
	}
	if(!isip(data[5]) || !isport(data[6])){
		printf("规则语句出现语法错误，第二部分IP或端口数据错误，在 %d 行\n",ln);
		return 5;
	}
	if(!isid(data[8])){
		printf("规则语句出现语法错误，规则ID号不合法，在 %d 行\n",ln);
		return 8;
	}
	if(!isuniq(id)){
		id = atoi(data[8]);
		printf("规则语句出现语法错误，规则ID号不唯一，在 %d 行\n",ln);
		return 8;
	}
	return 0;
}

//根据结构处理规则函数串
int linetorule(struct rulelink *rk,struct ruledata *rd){
	struct rule *cu = { 0 };
	struct rule *prev = { 0 };
	//遍历rulelink结构，获得预操作rule结构体指针
	if(rd->pt==1){ //http
		if(rk->hlk==NULL){
			rk->hlk=(struct rule*)calloc(1,sizeof(struct rule));
			cu=rk->hlk;
		}else{
			cu=rk->hlk;
			while(cu!=NULL){
				prev=cu;
				cu=cu->next;
			}
			cu=(struct rule *)calloc(1,sizeof(struct rule));
			prev->next=cu;
		}
	}else if(rd->pt==2){ //tcp
		if(rk->tlk==NULL){
			rk->tlk=(struct rule*)calloc(1,sizeof(struct rule));
			cu=rk->tlk;
		}else{
			cu=rk->tlk;
			while(cu!=NULL){
				prev=cu;
				cu=cu->next;
			}
			cu=(struct rule *)calloc(1,sizeof(struct rule));
			prev->next=cu;
		}
	}else if(rd->pt==3){ //udp
		if(rk->ulk==NULL){
			rk->ulk=(struct rule*)calloc(1,sizeof(struct rule));
			cu=rk->ulk;
		}else{
			cu=rk->ulk;
			while(cu!=NULL){
				prev=cu;
				cu=cu->next;
			}
			cu=(struct rule *)calloc(1,sizeof(struct rule));
			prev->next=cu;
		}
	}else if(rd->pt==4){ //icmp
		if(rk->ilk==NULL){
			rk->ilk=(struct rule*)calloc(1,sizeof(struct rule));
			cu=rk->ilk;
		}else{
			cu=rk->ilk;
			while(cu!=NULL){
				prev=cu;
				cu=cu->next;
			}
			cu=(struct rule *)calloc(1,sizeof(struct rule));
			prev->next=cu;
		}
	}
	cu->type=rd->rt;
	linetofunc(cu->type,cu,rd);
	return 0;
}

//分割规则函数字符串
int bpfuncline(char *line,char *p[]){
	int i = 0;
	int j = 0;
	while(line[i]!='}'&& j<=9){
		if(line[i]==';'){
			p[j]=(char*)(line+i+1);
			line[i]='\0';
			j++;
		}else if(line[i]=='{'){
			p[j]=(char*)(line+i+1);
			j++;
		}
		i++;
	}
	return j;
}

//规则子函数字符串
int opfunc(struct function *fc,struct rule *r,char *fl){ //根据函数动作如：alert（"test");转化成函数结构
	//处理表达式字符串
	char *v1=NULL;
	char *v2=NULL;
	char *p=NULL;
	if((p=strstr(fl,"++"))){
		p[0]='\0'; //切割出表达式参数
		v1=fl;
		set_addself(r,fc,v1);
		return 1;
	}
	if((p=strstr(fl,"--"))){
		p[0]='\0';
		v1=fl;
		set_delself(r,fc,v1);
		return 2;
	}
	if((p=strstr(fl,">"))){
		p[0]='\0';
		v1=fl;
		v2=p+1;
		set_greater(r,fc,v1,v2);
		return 3;
	}
	if((p=strstr(fl,"<"))){
		p[0]='\0';
		v1=fl;
		v2=p+1;
		set_less(r,fc,v1,v2);
		return 4;
	}
	if((p=strstr(fl,"=="))){
		p[0]='\0';
		v1=fl;
		v2=p+2;
		set_equal(r,fc,v1,v2);
		return 5;
	}
	if((p=strstr(fl,"!="))){
		p[0]='\0';
		v1=fl;
		v2=p+2;
		set_unequal(r,fc,v1,v2);
		return 6;
	}
	set_function(r,fc,fl);
	return 0;
}
//操作函数串，填充rule结构
int linetofunc(int type,struct rule *r,struct ruledata *rd){
	int i=0;
	if(type==1){
		char *func[10]={0};
		struct rtime *p=NULL;
		int num=0;
		p=(struct rtime*)calloc(1,sizeof(struct rtime));
		r->tp.rt=p;
		p->name=rd->name;
		p->id=rd->id;
		num=bpfuncline(rd->func,func);
		for(i=0;i<num;i++){
			opfunc(&p->fn[i],r,func[i]);
		}
	}else if(type==2){
		struct rprocess *p=NULL;
		p=(struct rprocess *)calloc(10,sizeof(struct rprocess));//每个过程支持10条子规则
	}
	return 0;
}

int linetorules(struct ruledata *rd){
	struct rulelink *current=NULL;
	struct rulelink *prev=NULL;
	struct iport cip;
	int first=1;
	cip.sip=rd->sip;
	cip.dip=rd->dip;
	cip.sport=rd->sport;
	cip.dport=rd->dport;
	if(!rks){
		rks=(struct rulelink*)calloc(1,sizeof(struct rulelink));//申请内存，第一个rulelink
		first=0;
	}
	current=rks;
	
	while(current && first){
		if(rd->both){
			if(isame_both(&cip,(struct iport *)current,1)){ //判断地址是否相同
				current->both=1;
				break;
			}
		}else{
			if(isame(&cip,(struct iport *)current)){ //判断地址是否相同
				break;
			}
		}
		prev=current;
		current=current->next;
	}
	if(current==NULL){
		current=(struct rulelink*)calloc(1,sizeof(struct rulelink));//新增一个rulelink结构
		prev->next=current;
	}
	current->sip = rd->sip;
	current->dip = rd->dip;
	current->sport = rd->sport;
	current->dport = rd->dport;
	current->both=rd->both;
	linetorule(current,rd);
	return 0;
}
int setiport(struct ruledata *rd,char *sip,char *dip,char *sport,char *dport){
	if(strcmp(sip,"any")==0)
		rd->sip=0;
	else
		rd->sip=inet_addr(sip);
	if(strcmp(dip,"any")==0)
		rd->dip=0;
	else
		rd->dip=inet_addr(dip);
	if(strcmp(sport,"any")==0)
		rd->sport=0;
	else
		rd->sport=atoi(sport);
	if(strcmp(dport,"any")==0)
		rd->dport=0;
	else
		rd->dport=atoi(dport);
}
//结构化规则数据，提取数据填充ruledata结构
int datatostruct(char *data[],struct ruledata *rd){
	int i=0;
	char *bp[3]={0};
	if(data[1][0]=='h')
		rd->pt=1;
	else if(data[1][0]=='t')
		rd->pt=2;
	else if(data[1][0]=='u')
		rd->pt=3;
	else if(data[1][0]=='i')
		rd->pt=4;
	if(strcmp(data[4],"->")==0){
		setiport(rd,data[2],data[5],data[3],data[6]);
		rd->both=0;
	}else if(strcmp(data[4],"<-")==0){
		setiport(rd,data[3],data[6],data[2],data[5]);
		rd->both=0;
	}else{
		setiport(rd,data[2],data[5],data[3],data[6]);
		rd->both=1;
	}
	bp[0] = data[7];
	while(data[7][i]){
		if(data[7][i]=='_'){
			data[7][i]='\0';
			if (bp[1]==0)
				bp[1]=(char*)(data[7]+i+1);
			else
				bp[2]=(char*)(data[7]+i+1);
		}
		i++;
	}
	if (strcmp("process",bp[0])==0)
		rd->rt=2;
	else if(strcmp("time",bp[0])==0)
		rd->rt=1;
	if(bp[1]!=0)
		rd->name=bp[1];
	if(bp[2]!=0)
		rd->pid=atoi(bp[2]);
	rd->id=atoi(data[8]);
	rd->func=data[9];
	return 0;
}

void summary(){ //输出所有规则处理后的总结信息
}