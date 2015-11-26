/*
 *  Various backtrace handling routines. From glibc and gdb sources 
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

#include "mbacktrace.h"

#define MMALLOC_LIB

#if defined(__linux__) && defined(__i386__)

/*
 * ----------------------------------------------------------------------
 * Backtrace. Stolen from glibc. Linux/i386 only.
 * ----------------------------------------------------------------------
 */

struct layout
{
  struct layout *next;
  void *return_address;
};

int getbacktrace (void **array, int size)
{
  /* We assume that all the code is generated with frame pointers set.  */
  register void *ebp __asm__ ("ebp");
  register void *esp __asm__ ("esp");
  struct layout *current;
  int cnt = 0;

  /* We skip the call to this function, it makes no sense to record it.  */
  current = (struct layout *) ebp;
  while (cnt < size)
    {
#if 0
      /*
       * My libc doesn't have __libc_stack_end
       */
      if ((void *) current < esp || (void *) current > __libc_stack_end)
        /* This means the address is out of range.  Note that for the
           toplevel we see a frame pointer with value NULL which clearly is
           out of range.  */
        break;
#else
      if ((void *) current < esp || !current || !current->return_address) {
        break;
      }
#endif

      array[cnt++] = current->return_address;
      current = current->next;
    }

  return cnt;
}

#else

/*
 * ----------------------------------------------------------------------
 * Backtrace. Contributed by Steve Coleman. May work elsewhere -- tested
 * on SunOS/Sparc only.
 * ----------------------------------------------------------------------
 */

int getbacktrace (void **array, int size)
{
  void *retAddr = 0;
  unsigned int n = 0;

  while (1) {
    switch (n) {
    case  0: retAddr = __builtin_return_address(0);  break;
    case  1: retAddr = __builtin_return_address(1);  break;
    case  2: retAddr = __builtin_return_address(2);  break;
    case  3: retAddr = __builtin_return_address(3);  break;
    case  4: retAddr = __builtin_return_address(4);  break;
    case  5: retAddr = __builtin_return_address(5);  break;
    case  6: retAddr = __builtin_return_address(6);  break;
    case  7: retAddr = __builtin_return_address(7);  break;
    case  8: retAddr = __builtin_return_address(8);  break;
    case  9: retAddr = __builtin_return_address(9);  break;
    case 10: retAddr = __builtin_return_address(10); break;
    case 11: retAddr = __builtin_return_address(11); break;
    case 12: retAddr = __builtin_return_address(12); break;
    case 13: retAddr = __builtin_return_address(13); break;
    case 14: retAddr = __builtin_return_address(14); break;
    case 15: retAddr = __builtin_return_address(15); break;
    case 16: retAddr = __builtin_return_address(16); break;
    case 17: retAddr = __builtin_return_address(17); break;
    case 18: retAddr = __builtin_return_address(18); break;
    case 19: retAddr = __builtin_return_address(19); break;
    default: retAddr = 0; break;
    }

    if (retAddr && n<size) {
      array[n++] = retAddr;
    }
    else {
      break;
    }
  }

  return n;
}

#endif
