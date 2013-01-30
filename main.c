#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#ifndef WIN32
#include <unistd.h>
#endif

#include "mmalloc.h"

#define OUT_LOOP_COUNT 200
#define LOOP_COUNT  100000

void corrupt_block(void* ptr, int block_size, int offset)
{
	unsigned char *p = (unsigned char *)ptr;
	p += block_size + offset;

#if 0
	*p = 'a';
	*(p+1) = 'b';
	*(p+2) = 'c';
	*(p+3) = 'd';
#endif

#if 1
	*(p+4) = 'e';
	*(p+5) = 0xAA;
#endif

#if 0
	*(p+6) = 'g';
	*(p+7) = 'h';
	*(p+8) = 'i';
	*(p+9) = 'j';
#endif

 }

void func1();
void func2();
void func3();

void func1()
{
	func2();
}

void func2()
{
	func3();
}

void func3()
{
	char* p = mmalloc(120);

	corrupt_block(p, 120, 0);

	mcheck_regions(0);
	mcheck_regions(0);
	mcheck_regions(0);

}

int alloc_free_chain();

int main(int argc, char *argv[])
{
	int k = 0;
	int pid = getpid();
	
	printf("pid = %d\n", pid);
	srand(pid); /* 30538); */
	
	mmalloc_init();

#if 1
	func1();
	
	mmalloc_cleanup(1);

	return 0;
#endif

	while(k++ < OUT_LOOP_COUNT)
	{	
		alloc_free_chain();
	}
	
	mmalloc_cleanup(1);
	
	return 0;
}

int alloc_free_chain()
{
	static char* p[LOOP_COUNT];
	int i;
	int block_size;
	int rand_count;

	if( (rand() % 20) == 0)
		alloc_free_chain();
	
	rand_count = rand() % LOOP_COUNT;
	for(i = 0; i < rand_count; i++)
	{
		if( (rand() % 5) == 0)
			block_size = rand() % (1024*8);
		else
			block_size = rand() % 32;

		p[i] = mmalloc( block_size );
		if(!p[i])
			printf("Error in alloc\n");
	}
	
	for(i = 0; i < rand_count; i++)
	{
		if(p[i])
			mfree(p[i]);
		
	}
	
	return 0;
}	

