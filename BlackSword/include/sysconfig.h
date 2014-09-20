#ifndef sysconfig_h
#define sysconfig_h
typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
#define LOCAL_IP "BSLocal_ip"
#define LOCAL_MASK "BSLocal_mask"
#define LOCAL_PATH "BSLocal_Path"
#define INSPERCT_HTTP "BSInsperct_http"
#define INSPERCT_TCP "BSInsperct_tcp"
#define INSPERCT_UDP "BSInsperct_udp"
#define INSPERCT_ICMP "BSInsperct_icmp"
#define AUDIT_ALERT "BSAudit_alert"
#define AUDIT_LOG "BSAudit_log"
#define DYNAMIC_MODULE "BSDynamic_module"
#define DECODE_STREAM "BSDecode_stream"
#define IGNORE_IP "BSIgnore_ip"
#define IGNORE_PORT "BSIgnore_port"
#define DYNAMIC_FILE "BSDynamic_file"
#define RULE_FILE "BSRule_file"
#define RULE_IGNORE_CHAR "BSRule_ignore_char"
#define RULE_IGNORE_IP "BSRule_ignore_ip"
#define RULE_IGNORE_PORT "BSRule_ignore_port"
#define RULE_DECODE_MSG1 "BSRule_decode_msg1"
#define RULE_DECODE_MSG2 "BSRule_decode_msg2"
#define RULE_DECODE_MSG3 "BSRule_decode_msg3"
#define OUT_TYPE "BSOut_type"
#define ABUSER_ALERT "BSAbuser_alert"
#define ABUSER_LOG "BSAbuser_log"
#define REASON_ALERT "BSReason_alert"
#define REASON_LOG "BSReason_log"
#define ABUSER_ALERT_FORMAT "BSAbuser_alert_format"
#define REASON_ALERT_FORMAT "BSReason_alert_format"
#define ABUSER_LOG_FORMAT "BSAbuser_log_format"
#define REASON_LOG_FORMAT "BSReason_log_format"


struct sys_variable{
	uint ip; //表示本机ip地址，ipaddr是一个ip地址结构
	uint mask;//表示网络掩码，用于识别本网段ip
	char *rpath;//系统根路径
	int bhttp;//是否分析http协议
	int btcp;//是否分析tcp协议
	int budp;//是否分析udp协议
	int bicmp;//是否分析icmp协议
	int alert;//是否产生警告信息
	int log;//是否产生记录信息
	int dym;//是否支持动态模块加载
};
struct decode_data{
	int stream;//是否开启流重组
	uint igip[10];//过滤ip数组 ,最大支持10个
	ushort igport[10];//过滤port数组,最大支持10个
};

struct dynamic_module {
	char *mpath;//模块路径
	struct mvariable *mv;//模块配置变量
	struct dynamic_module *next;//下一模块指针
};
struct mvariable{
	char **mvname;//模块变量名
	char **mvvalue;//模块变量值
};
struct decode_rule{
	char ic[10];//忽略符数组
	uint igip[10];
	ushort igport[10];
	char *msg1;//预定于消息1
	char *msg2;//同上
	char *msg3;//同上
};
struct out_print{
	int type;//设置输出方式
	char *abalert;//滥用检测告警日志路径
	char *ablog;//滥用检测记录日志路径
	char *realert;//推理告警路径
	char *relog;//推理记录路径
	char *abaformat;//滥用告警输出格式
	char *ablformat;//滥用记录输出格式
	char *reaformat;//推理警告输出格式
	char *relformat;//推理记录输出格式
};

struct global_variable {
	void *gvp; //变量指针
	struct global_variable *next;//下一个变量结构指针
};
struct sys_config{
	struct sys_variable sv; //系统变量指针
	struct global_variable gv;//全局变量指针
	struct decode_data dd;//数据解码器(预处理模块)指针
	struct dynamic_module dm;//动态模块指针
	struct decode_rule dr;//规则解码器指针
	struct out_print op;//输出结构指针
};

int sysconfig(char *);
int lineto(char *,int);
#endif
