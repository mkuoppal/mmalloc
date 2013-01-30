#include <dlfcn.h>
/* #include <stdlib.h> */
#include "mmalloc.h"

void* (*o_malloc)(size_t size) = 0;
void  (*o_free)(void *) = 0;
void* (*o_realloc)(void *, size_t size) = 0;
void* (*o_calloc)(size_t nmemb, size_t size) = 0;

extern void* (*__libc_malloc)(size_t size);

extern void* (*malloc)(size_t);
extern void  (*free)(void *);
extern void* (*realloc)(void *, size_t);
extern void* (*calloc)(size_t, size_t);

#ifdef MMALLOC_DYNLIB

static int init_done = 0;

#define INIT if(init_done == 0) { libinit(); }

void _init() 
{
    fprintf(stderr, "_init() called\n");
    o_malloc = __libc_malloc;
    printf(stderr, "Previous malloc = %lx\n", o_malloc);

    mmalloc_init();

    fprintf(stderr, "mmalloc_init done\n");

	fprintf(stderr, "malloc: %lx\n", malloc);
	fprintf(stderr, "free: %lx\n", free);

	fprintf(stderr, "__libc_malloc: %lx\n", __libc_malloc);
	malloc = __libc_malloc;
	fprintf(stderr, "malloc: %lx\n", malloc);

#if 0



	free = __libc_free;
	realloc = __libc_realloc;
	calloc = __libc_calloc;
#endif

    init_done = 1;
}

void _fini()
{
    fprintf(stderr, "_fini() called\n");
}
#endif
