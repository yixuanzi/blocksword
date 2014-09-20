#ifndef eth_h
#define eth_h
#include "sysconfig.h"
struct eth{
	uchar smac[6];
	uchar dmac[6];
	ushort protocol;
};
#endif