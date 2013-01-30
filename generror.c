#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifndef WIN32
#include <unistd.h>
#endif

#include "mmalloc.h"

#define OUT_LOOP_COUNT 200
#define LOOP_COUNT  1000


static const char *cmd = 0;

int alloc_free_chain();
void func1();
void func2();
void func3();

void corrupt_block(void* ptr, int block_size, int offset)
{
	unsigned char *p = (unsigned char *)ptr;
	p += block_size + offset;

	*(p+4) = 'e';
	*(p+5) = 0xAA;
}

void test_stress()
{
	int k = 0;
	
	while(k++ < OUT_LOOP_COUNT)
	{	
		alloc_free_chain();
	}	
}

void test_corrupt()
{
	char* p = (char *)malloc(40);
	strcpy(p, "testblockdata");

	corrupt_block(p, 40, 0);
}

void test_leak()
{
	char* leak = (char *)malloc(100);
	
	leak[0] = 0;
}

void test_usefreed()
{
	char* p = (char *)malloc(100);
	free(p);
	
	p[4] = 'j';
}

void test_strdup()
{
	static const char* s1 = "string one";
	static const char* s2 = "string two";
	char *s1_copy, *s2_copy;
	char *s1_mcopy, *s2_mcopy;
	char *stmp;
	
	mmalloc_state_t m_state1;

	s1_copy = strdup(s1);
	s2_copy = strdup(s2);

	s1_mcopy = strndup(s1, 5);
	s2_mcopy = strndup(s2, 5);
	
	m_state1 = mmalloc_get_state();

	stmp = strndup(s1, 5);

	mmalloc_report_state(m_state1);
	
	free(stmp);
	
	free(s1_copy);
	free(s2_copy);
	
	free(s1_mcopy);
	free(s2_mcopy);
}

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
#define CHECK_TEST( x ) if(strcmp( #x, cmd) == 0) { printf("Running test: %s\n", #x ); test_##x(); ; printf("Test %s done.\n", #x ); return;}
	
	CHECK_TEST( leak );
	CHECK_TEST( stress );
	CHECK_TEST( corrupt );
	CHECK_TEST( usefreed );
	CHECK_TEST( strdup );
	
	printf("no such test as: %s\n", cmd);

#undef CHECK_TEST

}

int main(int argc, char *argv[])
{
	if(argc != 2)
	{
		printf("Usage: %s [leak|stress|corrupt|usefreed|strdup]\n", argv[0]);
		return 1;
	}

	cmd = argv[1];

	func1();

	mmalloc_exit(0);

	printf("%s exit\n", argv[0]);

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

		p[i] = (char *)mmalloc( block_size );
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

