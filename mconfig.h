/*
 *  mmalloc - dynamic memory checker 
 *
 *  Copyright (C) 2002 Mika Kuoppala <miku@iki.fi>
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

#ifndef __MCONFIG_H__
#define __MCONFIG_H__

/*
 *  In Every memory management call PERIOD_CHECK_EVERYTHING value is 
 *  checked and if this is PERIOD_CHECK_EVERYTHING:th call, 
 *  then ALL memory regions and ALL blocks withing them are 
 *  checked for errors
 */

#define PERIOD_CHECK_EVERYTHING  1000

/*
 *  In Every memory management call PERIOD_CHECK_NEAREST_BLOCKS value is 
 *  checked and if this PERIOD_CHECK_NEAREST_BLOCKS:th call, then the 
 *  current memory memory region and all blocks within it are checked for
 *  errors
 */

#define PERIOD_CHECK_NEAREST_BLOCKS 10

/*
 *  Works as the CHECK_* values above and prints statistics of
 *  memory management in every PERIOD_PRINT_STATISTICS:th call
 *  Value of 0 means that STATISTICS is disabled.
 */

#define PERIOD_PRINT_STATISTICS  1000000

/*
 * Enabling this will give information about each region 
 * when statistics are printed
 *
 */

/* #define PRINT_REGION_STATISTICS */

/*
 * If memory management error is found, should be stop or continue
 * This is the number of errors before stopping 
 */

#define STOP_ON_ERROR 1

/*
 *  How many megs to allocate for pool
 *  MMALLOC_MEMSIZE environment variable can also be used, which is in 
 *  kilobytes
*/
#define KILOBYTE            1024ull
#define MEGABYTE            (1024ull * KILOBYTE)
#define GIGABYTE            (1024ull * MEGABYTE)
#define MMALLOC_MEMSIZE     (1 * GIGABYTE)

/*
  This is the count of blocks one region contains.
  Don't know why but 27 seems to be magically fast on my tests
  Tho ofcourse it depends on application
*/
#define BLOCKS_IN_REGION 16

/*
 * If DUMP_BLOCK_DATA is defined, raw memory dump of the erroneous block will
 * be printed
 */

#define DUMP_BLOCK_DATA

/*
 * Length of tailguards (bytes), keep this as aligned with 4 bytes
 */
#define TAILGUARD_LEN       8
#define TAILGUARD_CHAR      (unsigned char)(0xBF)

/*
 * If CHECK_FREED_BLOCK_DATA is defined, then when block is freed
 * it is filled with FREED_DATA_MAGIC pattern and this is used
 * to see if freed blocks has been used when region checks are made
*/

#define CHECK_FREED_BLOCK_DATA

/*
 *  Magic to fill freed blocks
 */
#ifdef  CHECK_FREED_BLOCK_DATA
#define FREED_DATA_MAGIC    (unsigned char)(0xFD)
#endif


/*
 * If BACKTRACE_SYMBOLS is defined, when displaying backtraces
 * also symbolic names for adresses are dug out.
 */

#define BACKTRACE_SYMBOLS

/*
 * TRACE_DEPTH controls how many items in trace will be stored.
 * TRACE_START and END offsets will cut trace items from beginning and
 * in end of trace so that you can avoid storing unnecessary information
 * ie your own malloc wrapper for example
 */
#define TRACE_DEPTH            16

#ifdef __cplusplus
#define TRACE_START_OFFSET     1   
#define TRACE_END_OFFSET       1
#else
#define TRACE_START_OFFSET     3
#define TRACE_END_OFFSET       2
#endif

/*
 * This will make finding memory blocks faster by using i386 assember
 */

#define I386_FIND_HIGH_BIT     

#endif
