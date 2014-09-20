#ifndef reasoning_h
#define reasoning_h
struct bskl{
	int id;//知识唯一id号
	int type;//知识类型，有alone和CNF型，即单例型和合取型。
	union proof{//证据指针
		int *id;
		struct klfunc *fc;
	};*pf;
	char *result;//推理结果
	int probability;//可信度
	int risk;//风险等级
};
struct klfunc{
	int funcid;
	char *parameter;
};
#endif