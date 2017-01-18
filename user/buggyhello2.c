// buggy hello world 2 -- pointed-to region extends into unmapped memory
// kernel should destroy user environment in response

#include <inc/lib.h>

const char *hello = "hello, world\n";

void
umain(int argc, char **argv)
{
    //系统调用接口
	sys_cputs(hello, 1024*1024);
}

