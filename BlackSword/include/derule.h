#ifndef derule_h
#define derule_h
#include "sysconfig.h"

struct variable_func{
	int id;//标识规则变量
	int type;//变量类型
	union{
		char *str;
		int var;
	}value;
};

struct function{
	int fid;//函数id号
	struct variable_func pt[2];//函数参数链表头指针
};
struct variable_rule{
//	int id;
	int type;
	char name[24];
	union{
		char *str;
		int var;
	}value;
};
struct rprocess{ //过程式检测规则集合链表
	char *name;//子规则名
	int id;//子规则唯一id号
	struct function fn[10];//子规则函数链表头指针
	struct rprocess *next;//下一子规则结构
};
struct rtime{
	char *name;//time型规则名
	int id;//规则唯一id号
	struct function fn[10];//time型函数数组，最大支持10个表达式
};

struct iport{
	uint sip;
	uint dip;
	ushort sport;
	ushort dport;
};
struct rulelink{
	uint  sip;//规则源ip地址
	uint  dip;//规则目标ip地址
	ushort sport;//规则源端口地址
	ushort dport;//规则目标端口地址
	int both;
	struct rule *tlk;//检测tcp协议规则链头指针
	struct rule *ulk;//检测udp协议规则链头指针
	struct rule *ilk;//检测icmp协议规则链头指针
	struct rule *hlk;//检测http协议规则链头指针
	struct rulelink *next;//下一个地址规则结构体指针
};
struct ruledata{
	uchar pt;//protocol type
	uchar rt;//rule type
	uchar dt;//data direction
	uchar pid;//process of rule id
	int both;
	uint sip;
	uint dip;
	ushort sport;
	ushort dport;
	char *name;
	int id;
	char *func;
};

union tprule{
	struct rtime *rt;
	struct rprocess *rp;
};
struct rule{
	int type;//规则类型，time或者process
	union tprule tp;//共用体，根据type指向rrule或rprocess数组结构,每个过程支持10条子规则
	struct variable_rule vb[10];//规则变量链表头指针
	struct rule *next;//下一地址检测类别
};
//function 
int createrulelink();//从规则文件路径数组中创建规则链

int createrulelink_f(char *);//解析文件

int isame(struct iport *iport1,struct iport *iport2);//判断两个地址是否相等
int isame_both(struct iport *iport1,struct iport *iport2,int);//判断两个地址是否相等
int isignore(char);

int isip(char *);

int islegal(char *[],int);

int isport(char *);

int isuniq(int);

int linetorule(struct rulelink *,struct ruledata *);

int linetorules(struct ruledata *);

int linetofunc(int,struct rule *,struct ruledata *);

int datatostruct(char *[],struct ruledata *);

int bpfuncline(char *,char **);

void summary();//输出所有规则处理后的总结信息
#endif
