#ifndef output_h
#define output_h
struct note{
	int type; //输出信息类型
	char *time;
	int id;
	int protocol;//协议
	char * msg;//alert或log参数
	struct pdata *op;//数据结构指针
};
#endif