#include <stdio.h>
#include "sysconfig.h"
#include "derule.h"
#include "bspcap.h"

int main(int argc,char *argv[]){
	int status=0;
	char *syspath="F:\\Paper\\BlockSword\\config\\bs.conf";
	status=sysconfig(syspath);
	status=createrulelink();
	run();
}
