/*
 *  mmalloc - dynamic memory checker 
 *
 *  Copyright (C) 2002,2003,2004 Mika Kuoppala <miku@iki.fi>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *
 */

#ifndef __MMALLOC_H__
#define __MMALLOC_H__

#if !defined(MMALLOC_DISABLED) && !defined(MMALLOC_LIB)

#define malloc(x)    mmalloc(x)
#define free(x)      mfree(x)
#define calloc(x,y)  mcalloc(x,y)
#define realloc(x,y) mrealloc(x,y)

#define strdup(x)    mstrdup(x)
#define strndup(x,y) mstrndup(x,y)

#include <stdlib.h>

#endif

#ifdef __cplusplus
extern "C" {
#endif

#define BREAK_TO_DEBUGGER()  asm("int3")
#ifndef massert
#include <stdio.h>
#define massert(x)   { if(!(x)) { fprintf(stderr, "massert (%s) FAILED! file: %s, line: %d\n", #x, __FILE__, __LINE__); fflush(stderr); BREAK_TO_DEBUGGER(); } }
#endif

typedef unsigned long mmalloc_state_t;

mmalloc_state_t mmalloc_get_state();
void mmalloc_report_state(mmalloc_state_t s);
void mmalloc_report_stats();
int  mmalloc_check();

void mmalloc_disable();
void mmalloc_enable();

int mmalloc_set_output_fd(FILE* fd);
int mmalloc_set_output_file(const char* const filename);

void mmalloc_exit(mmalloc_state_t s);

void* mcalloc(size_t nelems, size_t elemsize);
void* mmalloc(size_t size);
void* mrealloc(void *ptr, size_t size);
void  mfree(void *ptr);

char* mstrdup(const char *s);
char* mstrndup(const char* s, size_t size);

#ifdef __cplusplus
}
#endif

#endif
