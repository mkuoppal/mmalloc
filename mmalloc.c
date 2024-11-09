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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <execinfo.h>
#include <sys/time.h>
#include <stdint.h>

#define MMALLOC_LIB

#include "mmalloc.h"
#include "mconfig.h"

#define MIN_BLOCK_SIZE_B    3
#define MIN_BLOCK_SIZE      (1 << (MIN_BLOCK_SIZE_B))
#define MAX_BLOCK_SIZE_B    30
#define MAX_BLOCK_SIZE      (1 << (MAX_BLOCK_SIZE_B))
#define HEAD_MAGIC          0xBBADF00D
#define TAIL_MAGIC          0xF00DBADD

/* Time resolution */
#define ONE_MICROSECOND     1
#define ONE_MILLISECOND     (ONE_MICROSECOND * 1000)
#define ONE_SECOND          (ONE_MILLISECOND * 1000)

#define get_block_head(ptr) (struct block_head*) ((unsigned char *)(ptr) - sizeof(struct block_head))
#define get_block_ptr(head) (unsigned char*) ((unsigned char *)(head) + sizeof(struct block_head))

#define get_head_from_region(number, reg) \
                            (struct block_head *) ((unsigned char *)reg->blocks + \
                            ( (number) * (sizeof(struct block_head) + \
				    (reg)->block_size +		      \
				    sizeof(struct block_tail))))

#define MIN(a,b)             ((a) < (b) ? (a) : (b))

struct region {
	struct region*     next;
	struct region*     free_next;

	size_t        block_size;
	unsigned long free_count;

	unsigned char blocks[];
};

struct block_head {
	struct region*     myreg;
	size_t             mysize;

#if TRACE_DEPTH > 0
	void         *alloc_trace[TRACE_DEPTH];
	void         *free_trace[TRACE_DEPTH];
#endif

	unsigned long state_counter;
	unsigned long magic;
};

struct block_tail {
	unsigned long magic;
	unsigned long padding;
};

#if PERIOD_PRINT_STATISTICS > 0

struct region_chain_stats {
	unsigned long total_blocks;
	unsigned long blocks_alloc;
	unsigned long block_size;
	unsigned long bytes_alloced;
};

struct region_stats {
	unsigned long long bytes;
	unsigned long long total_alloc_count;
	unsigned long current_alloc_count;
};

static struct region_stats region_stats[MAX_BLOCK_SIZE_B] = { { 0, 0, 0}, };

static unsigned long          mmallocBytesAllocated = 0;
static unsigned long          applicationBytesAllocated = 0;
static unsigned long          lastApplicationBytesAllocated = 0;
static unsigned long          lastAllocCount = 0;
static unsigned long          lastCurrentAllocs = 0;
static unsigned long          maxApplicationBytesAllocated = 0;

#endif

static struct region* all_regions[MAX_BLOCK_SIZE_B] = { 0, };
static struct region* free_regions[MAX_BLOCK_SIZE_B] = { 0, };

static unsigned long          memPool1_Size = 0;
static unsigned char*         memPool1 = 0;
static unsigned long          memPool1_Allocated = 0;

static unsigned long          memPool2_Size = 0;
static unsigned char*         memPool2 = 0;
static unsigned long          memPool2_Allocated = 0;

static unsigned long          freq_check_all = 0;
static unsigned long          freq_statistics = 0;
static unsigned long          freq_check_region = 0;

static unsigned long          mmalloc_disabled = 0;

static unsigned long          alloc_count = 0;
static unsigned long          check_count = 0;
static unsigned long          not_mmalloc_alloc_count = 0;
static unsigned long          stop_on_error = 0;

static uint8_t                tailguard_data = 0;

static void merror(const struct block_head* head, const char *fmt, ...);
static void minfo(const char *fmt, ...);
static void print_block_data(const unsigned char *start, const unsigned char *end);


static unsigned long check_region(struct region *reg, int report_still_alloced, const unsigned long  start_stamp);
static unsigned long mcheck_regions(const int report_still_alloced, const unsigned long start_count);
static void mmalloc_init(void);
static int mmalloc_close_fd(void);

static const char mmalloc_version_str[] = "0.24";

static unsigned long error_count = 0;

static FILE*          output_fd = 0;

static struct timeval print_stats_timestamp;

void mmalloc_disable(void)
{
	if(mmalloc_disabled == 0)
		mmalloc_disabled = 1;
	else
		merror(NULL, "Disabling mmalloc while already disabled\n");
}

void mmalloc_enable(void)
{
	if(mmalloc_disabled == 1)
		mmalloc_disabled = 0;
	else
		merror(NULL, "Enabling mmalloc while already enabled\n");
}

#if PERIOD_PRINT_STATISTICS > 0
static void mdump_mmalloc_state(void);

static void report_stats(void)
{
	int i;
	unsigned long long totalAllocations = 0;
	unsigned long long totalBytes = 0;
	unsigned long long timeDiffInMicroseconds = 0;
	unsigned long current_allocs = 0;

	long bytesPerSec = 0;
	long allocDeltaPerSec = 0;
	unsigned long allocsPerSec = 0;

	struct timeval current_time;

	mdump_mmalloc_state();

	current_allocs = mcheck_regions(0,0);

	for(i = MIN_BLOCK_SIZE_B; i < MAX_BLOCK_SIZE_B; i++)
	{
		if(region_stats[i].total_alloc_count)
		{

#ifdef PRINT_REGION_STATISTICS
			minfo("Block(%d-%d) %llu allocations with %llu bytes, average %llu\n",
				(1 << (i-1)), (1 << i),
				region_stats[i].total_alloc_count, region_stats[i].bytes,
				region_stats[i].bytes / region_stats[i].total_alloc_count);
#endif
			totalAllocations += region_stats[i].total_alloc_count;
			totalBytes += region_stats[i].bytes;
		}
	}

	if(totalAllocations)
	{
		minfo("Current allocs %lu, total allocations %llu with %llu total bytes, average %llu\n",
			current_allocs, totalAllocations, totalBytes, totalBytes/totalAllocations);

		if(not_mmalloc_alloc_count)
			minfo("Not mmalloc handler blocks %lu\n", not_mmalloc_alloc_count);

		minfo("Allocated %lu, overhead %lu, total %lu, %3.2f%% free %3.2f%% eff\n",
			applicationBytesAllocated, (mmallocBytesAllocated - applicationBytesAllocated),
			memPool1_Allocated, 100.0 - (double)(memPool1_Allocated * 100.0)/(double)memPool1_Size,
			(double)(applicationBytesAllocated * 100.0) /
			((double)(memPool1_Allocated) + (double)memPool2_Allocated) );

		if(memPool2_Size != 0)
			minfo("Second pool in use %lu, %3.2f%% free\n",
				memPool2_Allocated, 100.0 - (double)(memPool2_Allocated * 100.0)/(double)memPool2_Size);
	}

	gettimeofday(&current_time, NULL);

	timeDiffInMicroseconds = (current_time.tv_sec * ONE_SECOND + current_time.tv_usec) -
		(print_stats_timestamp.tv_sec * ONE_SECOND + print_stats_timestamp.tv_usec);

	bytesPerSec = (long)(applicationBytesAllocated - lastApplicationBytesAllocated) * (long long)(ONE_SECOND) /
		(long long) timeDiffInMicroseconds;

	allocsPerSec = (alloc_count - lastAllocCount) * (unsigned long long)(ONE_SECOND) / timeDiffInMicroseconds;

	allocDeltaPerSec = (long)(current_allocs - lastCurrentAllocs) *
		(long long)ONE_SECOND / (long long)timeDiffInMicroseconds;

	minfo("Usage delta: %ld allocs, %ld bytes (%ld allocs/s %ld bytes/s) rate: %lu allocs/s\n",
		current_allocs - lastCurrentAllocs,
		applicationBytesAllocated - lastApplicationBytesAllocated,
		allocDeltaPerSec,
		bytesPerSec,
		allocsPerSec);

	minfo("Peak usage %ld application bytes, %ld total bytes\n",
		maxApplicationBytesAllocated,
		(memPool1_Allocated + memPool2_Allocated));

	lastApplicationBytesAllocated = applicationBytesAllocated;
	lastAllocCount = alloc_count;
	lastCurrentAllocs = current_allocs;
	print_stats_timestamp.tv_sec = current_time.tv_sec;
	print_stats_timestamp.tv_usec = current_time.tv_usec;
}
#endif

static inline void mmalloc_check_state(struct region* reg)
{
	if(freq_check_all && ((check_count % freq_check_all) == 0) )
	{
		mcheck_regions(0,0);
	}
	else if( reg && freq_check_region && ((check_count % freq_check_all) == 0) )
	{
		check_region(reg, 0, 0);
	}

	check_count++;

#if PERIOD_PRINT_STATISTICS > 0
	if( freq_statistics && ((check_count % freq_statistics) == 0) )
		report_stats();
#endif
}

static int is_initialized(void)
{
	if(memPool1_Size)
		return 1;

	return 0;
}

static void* alloc_from_pool(unsigned long size)
{
	void *p;

	if( memPool1_Size == 0 && memPool2_Size == 0)
	{
	    mmalloc_init();
	}

	if( (memPool1_Allocated + size) > memPool1_Size )
	{
		if( (memPool2_Allocated + size) > memPool2_Size )
		{
			merror(0, "Out of memory");
			return 0;
		}

		p = (void *) ((unsigned char *)memPool2 + memPool2_Allocated);

		memPool2_Allocated += size;

		return p;
	}

 	p = (void *) ((unsigned char*)memPool1 + memPool1_Allocated);

	memPool1_Allocated += size;

	return p;
}

static void print_stack_trace( void* const *a, const int size, FILE* out )
{
	int i;
	int stop = size;
	char **strings = 0;

#ifdef BACKTRACE_SYMBOLS
	strings = backtrace_symbols(a, size);
#endif
	for(i = 0; i < size; i++)
	{
		void* addr = a[i];
		if(addr == 0)
		{
			stop = i;
			break;
		}
	}

	for(i = stop-1; i >= 0; i--)
	{
		void* addr = a[i];

		fprintf(out, "#%-3d [0x%lx]: ", (stop) - i, (unsigned long)addr);

		if (strings)
			fprintf(out, "%s", strings[i]);

		fprintf(out, "\n");
	}
}

static void print_traces( const struct block_head* head, FILE* out )
{
#if (TRACE_DEPTH > 0)
	if( head->alloc_trace[0] )
	{
		fprintf(out, "\nAllocation Trace: \n");
		print_stack_trace( head->alloc_trace, TRACE_DEPTH, output_fd);
	}

	if( head->free_trace[0] )
	{
		fprintf(out, "\nFree Trace: \n");
		print_stack_trace( head->free_trace, TRACE_DEPTH, output_fd );
	}
#endif
}

static int get_stack_trace(void **array, int size)
{
	static void* trace[50];
	int trace_len;
	int i;
	int store_len;
	trace_len = backtrace(trace,
			      size + TRACE_START_OFFSET + TRACE_END_OFFSET );

	store_len = trace_len - TRACE_START_OFFSET - TRACE_END_OFFSET;
	if(store_len < 1)
		return 0;

	for(i = 0; (i < store_len) && (i < size); i++)
		array[i] = trace[TRACE_START_OFFSET + i];

	return i;
}

#ifdef I386_FIND_HIGH_BIT
static inline long find_high_bit(const unsigned long n)
{
	register long ret;
	asm ("bsr %1,%0" : "=g" (ret) : "r" (n));
	return ret + 1;
}
#else
static inline long find_high_bit(unsigned long n)
{
	unsigned long mask = 1UL << 31;
	long bit = 32;

	while (mask) {
		if (n & mask)
			return bit;

		bit--;
		mask >>= 1;
	}

	return 0;
}
#endif

#ifdef DEBUG_FREE_CHAINS
static void print_free_chain(const int size)
{
	struct region* reg;
	int entries = 0;

	reg = free_regions[size];
	while(reg)
	{
		printf("0x%x(%d free) -> ", (int)reg, reg->free_count);
		fflush(stdout);
		entries++;
		assert( reg->free_next != reg );
		reg = reg->free_next;
	}

	if(entries)
		printf( " NULL (freechain with %d entries)\n", entries);
}

static void print_region_chain(struct region* first)
{
	struct region* reg;
	int entries = 0;
	reg = first;

	while(reg)
	{
		printf("0x%x(%d free) -> ", (int)reg, reg->free_count);
		fflush(stdout);
		entries++;
		assert( reg->next != reg );
		reg = reg->next;
	}

	if(entries)
		printf( " NULL (with %d entries)\n", entries);
}
#endif

#ifdef CHECK_FREED_BLOCK_DATA
static inline void insert_freed_block_data(struct block_head* head)
{
	memset(get_block_ptr(head), FREED_DATA_MAGIC, head->myreg->block_size);
}
#else
#define insert_freed_block_data(x)
#endif

static struct region* allocate_new_region(const size_t size, const unsigned int block_count)
{
	struct region* region;
	struct block_head* head;
	struct block_tail* tail;
	unsigned char* block_ptr;
	unsigned long i;

	const unsigned long block_size =
		sizeof(struct block_head) + size + sizeof(struct block_tail);

	region = (struct region *)alloc_from_pool(sizeof(struct region) + (block_size * block_count));
	if(region == 0)
		return 0;

	region->next = 0;
	region->free_next = 0;

	region->block_size = size;
	region->free_count = block_count;

	for(i = 0; i < block_count; i++)
	{
		head = get_head_from_region(i, region);

		head->mysize = (size_t)-1;
		head->myreg = region;
		head->magic = HEAD_MAGIC;

#if (TRACE_DEPTH > 0)
		head->alloc_trace[0] = 0;
		head->free_trace[0] = 0;
#endif
		block_ptr = get_block_ptr(head);

		tail = (struct block_tail *) ((unsigned char *)(block_ptr) + size);
		assert(((unsigned char *)tail - (unsigned char *)block_ptr) == (int)size);

		insert_freed_block_data(head);

		tail->padding = TAIL_MAGIC;
		tail->magic = TAIL_MAGIC;
	}

	return region;
}

#if TAILGUARD_BYTES > 0
static inline void insert_tailguard(const struct block_head* head)
{
	uint8_t *s = (uint8_t *)(get_block_ptr(head) + head->mysize);
	const uint8_t * const e = s + TAILGUARD_BYTES;

	while (s < e)
		*s++ = tailguard_data;
}
#else
#define insert_tailguard(x)
#endif

#ifdef CHECK_FREED_BLOCK_DATA
static inline void check_freed_block_integrity(struct region* reg, struct block_head* head)
{
	const unsigned int block_size = reg->block_size;
	const unsigned char* ptr = get_block_ptr(head);
	unsigned int i;

	for(i = 0; i < block_size; i++)
	{
		if(ptr[i] != FREED_DATA_MAGIC)
		{
			merror(head, "FREED BLOCK USED");
		}
	}
}
#else
#define check_freed_block_integrity(x, y)
#endif

#if TAILGUARD_BYTES > 0
static void print_tailguard_corruption(struct block_head* head);

static inline void check_tailguard(struct block_head* head)
{
	const uint8_t *s = (uint8_t *)(get_block_ptr(head) + head->mysize);
	const uint8_t * const e = s + TAILGUARD_BYTES;

	while (s < e) {
		if(*s++ != tailguard_data)
			print_tailguard_corruption(head);
	}
}

static void print_tailguard_corruption(struct block_head* head)
{
	const unsigned char* start = 0;
	const unsigned char* end = 0;
	const unsigned char* tailstart  = (unsigned char *)(get_block_ptr(head) + head->mysize);

	int j = 0;

	while(j < TAILGUARD_BYTES)
	{
		if(tailstart[j] != TAILGUARD_DATA)
		{
			if(start == 0)
				start = &tailstart[j];
		}
		else
		{
			if(start)
			{
				if(end == 0)
					end = &tailstart[j];
			}
		}

		j++;
	}

	if(start)
	{
		if(end == 0)
			end = tailstart + TAILGUARD_BYTES;

#ifdef DUMP_BLOCK_DATA
		minfo("Block 0x%x (%d bytes) dump:\n", (unsigned long)get_block_ptr(head), head->mysize);

		print_block_data(get_block_ptr(head), get_block_ptr(head) + head->mysize);
#endif

		minfo("Block tail, 0x%x is valid tailguard:\n", TAILGUARD_DATA);
		print_block_data(get_block_ptr(head) + head->mysize, get_block_ptr(head) + head->mysize + TAILGUARD_BYTES);

		merror(head, "BLOCK TAIL OVERWRITE at offset %d, len %d",
			   start - tailstart, end - start);
	}
}

#else
#define check_tailguard(x)
#endif

static int check_block(struct region* orgreg, struct block_head* head)
{
	struct block_tail *tail = NULL;
	unsigned char* ptr = get_block_ptr(head);
	struct region* reg;

	reg = head->myreg;
	if(reg != orgreg)
		merror(head, "BLOCK %p REGION CORRUPTED", ptr);

	if(head->magic != HEAD_MAGIC)
		merror(head, "BLOCK HEADMAGIC CORRUPTED" );

	if(head->mysize == (size_t)-1)
	{
		check_freed_block_integrity(reg, head);
		return -1;
	}

	if(head->mysize > reg->block_size)
		merror(head, "Block has bigger size than region size");

	check_tailguard(head);

	insert_tailguard(head);

	tail = (struct block_tail *) ((unsigned char *)(ptr) + reg->block_size);

	if(tail->magic != TAIL_MAGIC)
		merror(head, "BLOCK TAILMAGIC CORRUPTED");

	return head->mysize;
}

static unsigned long check_region(struct region* reg, int report_still_alloced, const unsigned long start_stamp)
{
	struct block_head* head;
	unsigned long freecount = 0;
	unsigned int i = 0;

	for(i = 0; i < BLOCKS_IN_REGION; i++)
	{
	    head = get_head_from_region(i, reg);

	    if(check_block(reg, head) == -1)
			freecount++;
		else if(report_still_alloced && (head->state_counter >= start_stamp))
		{
			merror(head, "BLOCK NOT FREED");
		}
	}

	return BLOCKS_IN_REGION - freecount;
}

static unsigned long check_region_chain(struct region* reg, const int report_still_alloced, const int start_stamp)
{
	unsigned long currently_allocated = 0;

	if(reg == 0)
		return 0;

	while(reg)
	{
		currently_allocated += check_region(reg, report_still_alloced, start_stamp);

		reg = reg->next;
	}

	return currently_allocated;
}

static inline struct block_head* find_free_block(struct region* reg)
{
	unsigned int i = 0;
	struct block_head* head;

	while(i < BLOCKS_IN_REGION)
	{
		head = get_head_from_region(i, reg);
		if(head->mysize == (size_t)-1)
		{
			return head;
		}

		i++;
	}

	return 0;
}

#if (TRACE_DEPTH > 0)
static inline void store_alloc_trace(struct block_head* head)
{
	int stored;
	stored = get_stack_trace( head->alloc_trace, TRACE_DEPTH);
	if(stored < TRACE_DEPTH)
		head->alloc_trace[stored] = 0;

	head->free_trace[0] = 0;
}
#else
#define store_alloc_trace(x)
#endif

#if (TRACE_DEPTH > 0)
static inline void store_free_trace(struct block_head* head)
{
	int stored;
	stored = get_stack_trace( head->free_trace, TRACE_DEPTH);
	if(stored < TRACE_DEPTH)
		head->free_trace[stored] = 0;
}
#else
#define store_free_trace(x)
#endif

static inline struct block_head *
alloc_block_from_region(struct region* reg, const size_t size)
{
	struct block_head *head;

	head = find_free_block(reg);

	if(head)
	{
#if PERIOD_PRINT_STATISTICS > 0
		struct region_stats *stats;
		int sizeb;
#endif

#if TRACE_DEPTH > 0
		store_alloc_trace(head);
#endif

#if PERIOD_PRINT_STATISTICS > 0
		if( size < MIN_BLOCK_SIZE )
			sizeb = MIN_BLOCK_SIZE_B;
		else
			sizeb = find_high_bit( size );
		stats = &region_stats[sizeb];

		stats->current_alloc_count++;
		stats->total_alloc_count++;
		stats->bytes += size;

		applicationBytesAllocated += size;
		if(applicationBytesAllocated > maxApplicationBytesAllocated)
		{
			maxApplicationBytesAllocated = applicationBytesAllocated;
		}

		mmallocBytesAllocated += reg->block_size;
#endif
		head->state_counter = alloc_count++;
		head->mysize = size;

		insert_tailguard(head);
	}
	else
	{
		merror(0, "Couln't get free block from region %p\n", reg);
	}

	return head;
}

static inline void free_block(struct block_head* head)
{
	struct region* reg;

	reg = head->myreg;

	check_block(reg, head);

	if(head->mysize == (size_t)-1)
	{
		merror(head, "FREE ON ALREADY FREED BLOCK");
	}
	else
	{
		reg->free_count++;

		if(reg->free_count > BLOCKS_IN_REGION)
		{
			merror(head, "Internal error, block has %d free blocks in %d blocks",
			       reg->free_count, BLOCKS_IN_REGION);
		}

#if PERIOD_PRINT_STATISTICS > 0
		applicationBytesAllocated -= head->mysize;
		mmallocBytesAllocated -= reg->block_size;
#endif

		if(reg->free_count == 1)
		{
			struct region** free_list;
			const int bsize = find_high_bit((reg->block_size-1));

			free_list = &free_regions[bsize];

			/* assert(reg->free_next == 0); */

			if(*free_list)
			{
				reg->free_next = *free_list;
			}

			*free_list = reg;
		}

		head->mysize = (size_t)-1;

		insert_freed_block_data(head);
	}

#if TRACE_DEPTH > 0
	store_free_trace(head);
#endif

}

static inline struct region* find_block_region(const struct block_head* head)
{
	if(head->magic != HEAD_MAGIC)
	{
		return 0;
	}

	return head->myreg;
}

static struct region* get_free_region(const size_t size)
{
	struct region** free_list;
	struct region*  reg;
	int sizeb;

	if( size < MIN_BLOCK_SIZE )
		sizeb = MIN_BLOCK_SIZE_B;
	else
		sizeb = find_high_bit( size );

	free_list = &free_regions[sizeb];

	if(*free_list == 0)
	{
		struct region**      all_list;

		reg = allocate_new_region( (1 << sizeb), BLOCKS_IN_REGION );
		if(reg == 0)
			return 0;

		all_list = &all_regions[sizeb];

		/* Insert first to all list */
		if(*all_list)
		{
			reg->next = *all_list;
		}

		reg->free_next = 0;
		*all_list = reg;

		/* Insert first to free list */
		*free_list = reg;
	}

	reg = *free_list;

	assert( reg->free_count != 0 );

	reg->free_count--;
	if(reg->free_count == 0)
	{
		*free_list = (*free_list)->free_next;
		reg->free_next = 0;
	}

	return reg;
}

#if (PERIOD_PRINT_STATISTICS > 0)
static int dump_region_chain(struct region_chain_stats *data,
			     struct region *reg)
{
	struct block_head *head;
	int region_count;
	int i;

	region_count = 0;
	data->total_blocks = 0;
	data->blocks_alloc = 0;
	data->block_size = 0;
	data->bytes_alloced = 0;

	if(!reg)
		return 0;

	data->block_size = reg->block_size;

	while(reg)
	{
		region_count++;
		data->total_blocks += BLOCKS_IN_REGION;

		for(i = 0; i < BLOCKS_IN_REGION; i++)
		{
			head = get_head_from_region(i, reg);
			if(head->mysize == (size_t)-1)
				continue;

			data->blocks_alloc++;
			data->bytes_alloced += head->mysize;
		}

		reg = reg->next;
	}

	return region_count;
}

#ifdef PRINT_REGION_STATISTICS
static void print_region_data(region_chain_stats_t* data, FILE* out)
{
	fprintf(out, " Blocks: (%lu, allocated: %lu, free %lu)",
			data->total_blocks, data->blocks_alloc, (data->total_blocks - data->blocks_alloc));
	fprintf(out, " Bytes: (alloced %lu, free %lu) ",
			data->bytes_alloced, (data->total_blocks - data->blocks_alloc) * data->block_size);
}
#endif

static void mdump_mmalloc_state(void)
{
	struct region_chain_stats region_data;
	int total_bytes = 0;
	int total_allocs = 0;
	int count;
	int i;

	minfo("\n *** MMALLOC STATISTICS ***\n");

	for(i = MIN_BLOCK_SIZE_B; i < MAX_BLOCK_SIZE_B; i++) {
		count = dump_region_chain(&region_data, all_regions[i]);

		if(count) {
			total_bytes += region_data.bytes_alloced;
			total_allocs += region_data.blocks_alloc;

#ifdef PRINT_REGION_STATISTICS
			fprintf(out, "[%6d]: %-5d regions ", (1 << i), count);

			print_region_data(&region_data, out);

			fprintf(out, "\n");
#endif
		}
	}

	minfo(" MMALLOC has alloced %d bytes in %d allocs\n", total_bytes, total_allocs);
}
#endif

int mmalloc_set_output_file(const char* const filename)
{
	FILE* f;

	f = fopen(filename, "a");
	if (!f)
		return 0;

	return mmalloc_set_output_fd(f);
}

int mmalloc_set_output_fd(FILE* fd)
{
	int r;
	r = mmalloc_close_fd();
	output_fd = fd;

	return r;
}

static int mmalloc_close_fd(void)
{
	if(output_fd != stderr)
	{
		int r;
		r = fclose(output_fd);
		output_fd = 0;
		return r;
	}

	return 0;
}

void mmalloc_exit(mmalloc_state_t s)
{
	if(!is_initialized())
		return;

	mmalloc_report_state(s);
	mmalloc_report_stats();

	minfo("Total errors %u\n", error_count);
	minfo("mmalloc_exit() done\n");

	if(output_fd != stderr)
	{
		fclose(output_fd);
		output_fd = 0;
	}

	if(error_count == 0)
	{
		if(memPool1)
		{
			free(memPool1);
			memPool1 = 0;
			memPool1_Size = 0;
			memPool1_Allocated = 0;
		}

		if(memPool2)
		{
			free(memPool2);
			memPool2 = 0;
			memPool2_Size = 0;
			memPool2_Allocated = 0;
		}
	}
}

void mmalloc_init(void)
{
	char* ofilename;

	freq_check_all    = PERIOD_CHECK_EVERYTHING;
	freq_statistics   = PERIOD_PRINT_STATISTICS;
	freq_check_region = PERIOD_CHECK_NEAREST_BLOCKS;

	output_fd = stderr;

#if PERIOD_PRINT_STATISTICS > 0
	gettimeofday(&print_stats_timestamp, NULL);
#endif

	if( (ofilename = getenv("MMALLOC_FILENAME")) != NULL)
	{
		mmalloc_set_output_file(ofilename);
	}

	minfo("mmalloc v%s\n", mmalloc_version_str);

	if( MIN_BLOCK_SIZE_B < 2 )
	{
		merror(0, "MIN_BLOCK_SIZE have to be bigger than 1");
		abort();
	}

	if(memPool1_Size == 0 && memPool1 == 0)
	{
		unsigned long toAllocate = 0;

		/* Seems right for glibc (linux) */
		const unsigned long maxPerPool = 2046*1024*1024;
		const char* kString;

		kString = getenv("MMALLOC_MEMSIZE");

		if(kString == NULL)
		{
#ifndef MMALLOC_MEMSIZE
			merror(0, "Define environment variable MMALLOC_MEMSIZE (in kB) to preallocate mem");
			exit(1);
#endif
		}

#ifndef MMALLOC_MEMSIZE

		toAllocate = 1024 * strtol(kString, (char **)NULL, 10);
#else
		toAllocate = MMALLOC_MEMSIZE;
#endif
		if(toAllocate > maxPerPool)
		{
			memPool2_Size = toAllocate - maxPerPool;
			memPool1_Size = maxPerPool;
		}
		else
			memPool1_Size = toAllocate;

		memPool1 = (unsigned char *)malloc(memPool1_Size);

		if(memPool1 == NULL)
		{
			merror(0, "Pool1: Unable to allocate %ld bytes of memory", memPool1_Size);
			exit(1);
		}

		memPool2 = (unsigned char *)malloc(memPool2_Size);

		if(memPool2 == NULL)
		{
			merror(0, "Pool1: Unable to allocate %ld bytes of memory", memPool2_Size);
			exit(1);
		}

		memPool1_Allocated = 0;
		memPool2_Allocated = 0;

		minfo("Pool1: Allocated %lu bytes (%lu Megabytes) of memory\n",
			memPool1_Size, (memPool1_Size/(1024*1024)));

		if(memPool2_Size > 0)
		{
			minfo("Pool2: Allocated %lu bytes (%lu Megabytes) of memory\n",
				memPool2_Size, (memPool2_Size/(1024*1024)));
		}
	}

	stop_on_error = STOP_ON_ERROR;
}

void mmalloc_report_state(mmalloc_state_t mstamp)
{
	if(mstamp > 0)
	{
		stop_on_error = 0;
		minfo("MMALLOC State report START: from %ld to %ld\n", mstamp, alloc_count);
	}

	mcheck_regions(1, mstamp);

	if(mstamp > 0)
	{
		stop_on_error = STOP_ON_ERROR;

		minfo("MMALLOC State report END\n");
	}
}

void mmalloc_report_stats(void)
{
#if PERIOD_PRINT_STATISTICS > 0
	report_stats();
#endif
}

unsigned long mmalloc_get_state(void)
{
	return alloc_count;
}

void* mmalloc(size_t size)
{
	void *p;

	if(!mmalloc_disabled)
	{
		const int total_size = size + TAILGUARD_BYTES;
		struct region* reg;

		reg = get_free_region(total_size);
		if(reg == 0)
			return NULL;

		mmalloc_check_state(reg);

		p = get_block_ptr(alloc_block_from_region(reg, size));
	}
	else
	{
		not_mmalloc_alloc_count++;
		p = malloc(size);
	}

	return p;
}

void* mrealloc(void* ptr, size_t size)
{
	if(!mmalloc_disabled)
	{
		void* newptr;
		struct block_head* head;

		if (!ptr)
			return mmalloc(size);

		head = get_block_head(ptr);

		if(head->mysize == (size_t)-1)
			merror(head, "REALLOC FROM FREED BLOCK");

		newptr = mmalloc(size);
		if(newptr == NULL)
			return NULL;

		memcpy(newptr, ptr, MIN(head->mysize, size));
		mfree(ptr);

		return newptr;
	}
	else
	{
		return realloc(ptr, size);
	}
}

void* mcalloc(size_t nelems, size_t elemsize)
{
	if(!mmalloc_disabled)
	{
		void* ptr;
		struct region* reg;

		const size_t size = nelems * elemsize;

		reg = get_free_region( (nelems * size) + TAILGUARD_BYTES );

		if(reg == 0)
			return NULL;

		mmalloc_check_state(reg);

		ptr = get_block_ptr(alloc_block_from_region(reg, size));
		if(ptr)
			memset(ptr, 0, size);

		return ptr;
	}
	else
	{
		not_mmalloc_alloc_count++;
		return calloc(nelems, elemsize);
	}
}

void mfree(void *ptr)
{
	if (!ptr)
		return;

	if(!mmalloc_disabled)
	{
		struct region *reg;

		reg = find_block_region(get_block_head(ptr) );
		if(reg) {
			free_block(get_block_head(ptr));
		} else {
			merror(0, "FREEING UNKNOWN POINTER  %lx\n", ptr);
		}
	}
	else
	{
		not_mmalloc_alloc_count--;
		free(ptr);
	}
}

unsigned long mcheck_regions(const int report_still_alloced, const unsigned long start_count)
{
	int i = 0;

	unsigned long currently_allocated = 0;

	for(i = MIN_BLOCK_SIZE_B; i < MAX_BLOCK_SIZE_B; i++)
	{
		currently_allocated += check_region_chain(all_regions[i], report_still_alloced, start_count);

#ifdef DEBUG_FREE_CHAINS
		print_region_chain(all_regions[i]);
		print_free_chain(i);
#endif

	}

	return currently_allocated;
}

static void print_time(FILE *out)
{
#define TIME_BUFFER_LEN   1024
	char buf[TIME_BUFFER_LEN];
	time_t t;
	struct tm* currentTime;

	t = time(0);

	currentTime = localtime(&t);
	if(currentTime)
	{
		int len;
		len = strftime(buf, TIME_BUFFER_LEN-1, "%d.%m.%Y %H:%M:%S", currentTime);
		if(len)
		{
			buf[MIN(len, TIME_BUFFER_LEN-1)] = '\0';

			fprintf(out, "%s", buf);
		}
	}
}

void print_block_data(const unsigned char* start, const unsigned char* end)
{
#define BLOCK_LEN  16

	unsigned i;
	unsigned len;

	if(end < start)
		return;

	i = 0;
	len = end - start;

	while(i < len)
	{
		const unsigned left = len - i;
		int j;

		fprintf(output_fd, "0x%.0lx: ", (unsigned long)(start) + i);

		for(j = 0; j < BLOCK_LEN; j++)
		{
			if( left - j > 0)
				fprintf(output_fd, "%-3x", start[i+j]);
			else
				fprintf(output_fd, "%-3s", " ");
		}

		fprintf(output_fd, ": ");

		for(j = 0; j < BLOCK_LEN; j++)
		{
			if(left - j > 0)
			{
				if(isalpha(start[i+j]))
					fprintf(output_fd, "%-1c", start[i+j]);
				else
					fprintf(output_fd, "%-1s", ".");
			}
			else
				fprintf(output_fd, "%-1s", " ");
		}

		fprintf(output_fd, "\n");

		i += MIN(left, BLOCK_LEN);
	}
}

void minfo(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

	print_time(output_fd);

	fprintf(output_fd, " MMALLOC INFO: ");

	vfprintf(output_fd, fmt, ap);

	fflush(output_fd);
}

void merror(const struct block_head* head, const char *fmt, ...)
{
#define ERROR_TRACE_LEN   50

	void *strace[ERROR_TRACE_LEN];
	int tracelen = 0;
	va_list ap;

	error_count++;

	va_start(ap, fmt);

	print_time(output_fd);

	fprintf(output_fd, " ***** ERROR: ");

	vfprintf(output_fd, fmt, ap);
	fprintf(output_fd, " ******\n");

	va_end(ap);

	print_time(output_fd);
	fprintf(output_fd, " *** REPORT START ***: \n");

	if(head)
	{
		fprintf(output_fd, "\nBlock address 0x%p", get_block_ptr(head));

		if(head->mysize != (size_t)-1)
			fprintf(output_fd, ", size %ld bytes\n", head->mysize);

		print_traces(head, output_fd);
	}

	tracelen = get_stack_trace( strace, ERROR_TRACE_LEN-1);
	strace[MIN(tracelen, (ERROR_TRACE_LEN-1))] = 0;

	fprintf(output_fd, "\nError Trace: \n");
	print_stack_trace( strace, ERROR_TRACE_LEN, output_fd );
	fprintf(output_fd, "\n");

	print_time(output_fd);
	fprintf(output_fd, " *** REPORT END ***\n");

	fflush(output_fd);

	if( (stop_on_error != 0) && (error_count >= STOP_ON_ERROR) )
		BREAK_TO_DEBUGGER();
}

char* mstrdup(const char *s)
{
	const int len = strlen(s);
	char* new_s = (char *)mmalloc(len+1);

	if(new_s)
	{
		strcpy(new_s, s);
		return new_s;
	}
	else
		return NULL;
}

char* mstrndup(const char* s, size_t size)
{
	const size_t len = strlen(s);
	int newlen = MIN(len, size);
	char* new_s = (char *)mmalloc(newlen+1);

	if(new_s)
	{
		strncpy(new_s, s, newlen);
		new_s[newlen] = 0;
		return new_s;
	}
	else
		return NULL;
}

int mmalloc_check(void)
{
	mcheck_regions(0, 0);

	return 1;
}

#ifdef __cplusplus

void *operator new (size_t sz)
{
	return mmalloc(sz);
}

void *operator new[] (size_t sz)
{
	return mmalloc(sz);
}

void operator delete (void *p)
{
	mfree(p);
}

void operator delete[] (void *p)
{
	mfree(p);
}

#endif
