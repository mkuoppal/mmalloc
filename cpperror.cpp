#include <stdio.h>

#include "mmalloc.h"

class Test {
public:

private:
	unsigned char buf[100];
};

void dummy()
{	
	Test* t= new Test[10];
}

int main(int argc, char *argv[])
{
	dummy();
	
	mmalloc_exit(0);

	return 0;
}
