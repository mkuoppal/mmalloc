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

#include "msymtab.h"
#include <bfd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define MMALLOC_LIB

#if defined(__linux__) && defined(__i386__)
#include <link.h>
#endif

/*
 * ----------------------------------------------------------------------
 * Symbol Table Access. Stolen from binutils.
 * ----------------------------------------------------------------------
 */

static asymbol **thesyms;		/* Symbol table.  */
static bfd *thebfd = (bfd *) NULL;

static asymbol **slurp_symtab (bfd * abfd)
{
	long storage;
	long symcount;
	asymbol **syms;

	if ((bfd_get_file_flags (abfd) & HAS_SYMS) == 0)
		return NULL;

	storage = bfd_get_symtab_upper_bound (abfd);
	if (storage < 0) {
		fprintf (stderr, "bfd_get_symtab_upper_bound failed: %s: %s\n",
				 bfd_get_filename(abfd), bfd_errmsg (bfd_get_error()));
		exit (1);
	}

	syms = (asymbol **) malloc (storage);

	symcount = bfd_canonicalize_symtab (abfd, syms);
	if (symcount < 0) {
		fprintf (stderr, "bfd_canonicalize_symtab: %s: %s\n",
				 bfd_get_filename(abfd), bfd_errmsg (bfd_get_error ()));
		exit (1);
	}

	return syms;
}

static int init_symtab (const char *argv0)
{
	char **matching;

	if (thebfd) {
		return 0;
	}

	bfd_init ();
	/* set_default_bfd_target (); */

	thebfd = bfd_openr (argv0, NULL);
	if (thebfd == NULL) {
		fprintf (stderr, "bfd_openr failed for `%s': %s\n", argv0,
				 bfd_errmsg(bfd_get_error()));
		return -1;
	}

	if (bfd_check_format (thebfd, bfd_archive)) {
		fprintf (stderr, "can not get addresses from archive `%s': %s\n",
				 argv0, bfd_errmsg(bfd_get_error()));
		bfd_close (thebfd);
		thebfd = NULL;
		return -1;
	}

	if (!bfd_check_format_matches (thebfd, bfd_object, &matching)) {
		fprintf (stderr, "%s: %s\n", bfd_get_filename (thebfd),
				 bfd_errmsg (bfd_get_error ()));
		if (bfd_get_error () == bfd_error_file_ambiguously_recognized) {
			char **p = matching;
			fprintf (stderr, "%s: Matching formats:", bfd_get_filename (thebfd));
			while (*p) {
				fprintf (stderr, " %s", *p++);
			}
			fprintf (stderr, "\n");
			free (matching);
		}
		bfd_close (thebfd);
		thebfd = NULL;
		return -1;
	}

#if 0
	fprintf (stderr, "loading symbols from `%s' ... ", argv0);
	fflush  (stderr);
#endif
	thesyms = slurp_symtab (thebfd);
#if 0
	if (!thesyms) {
		fprintf (stderr, "(no symbols) ... ");
	}
	fprintf (stderr, "done.\n");
#endif

	return 0;
}

/*
 * ----------------------------------------------------------------------
 * Shared library stuff. Stolen from gdb. ELF only.
 * ----------------------------------------------------------------------
 */

#if defined(__linux__) || defined(__sun__)

struct section_table {
  PTR addr;               /* Lowest address in section */
  PTR endaddr;            /* 1+highest address in section */
  sec_ptr the_bfd_section;
  bfd *abfd;              /* BFD file pointer */
};

struct so_list {
  struct so_list * next;
  struct link_map lm;			/* copy of link map from inferior */
  struct link_map *lmaddr;		/* addr in inferior lm was read from */
  PTR lmend;
  char so_name[1024];
  bfd * abfd;
  struct section_table *sections;
  struct section_table *sections_end;
  struct section_table *textsection;
  asymbol ** syms;
};

#define LM_ADDR(so) (unsigned long)((so) -> lm.l_addr)
#define LM_NEXT(so) ((so) -> lm.l_next)
#define LM_NAME(so) ((so) -> lm.l_name)
/* Test for first link map entry; first entry is the exec-file. */
#define IGNORE_FIRST_LINK_MAP_ENTRY(x) ((x).l_prev == NULL)

static struct so_list *so_list_head = NULL;
static PTR debug_base;		/* Base of dynamic linker structures */

typedef struct {
  unsigned char d_tag[4];               /* entry tag value */
  union {
    unsigned char       d_val[4];
    unsigned char       d_ptr[4];
  } d_un;
} Elf32_External_Dyn;

static PTR
elf_locate_base (bfd * abfd)
{
  sec_ptr dyninfo_sect;
  int dyninfo_sect_size;
  PTR dyninfo_addr;
  char *buf;
  char *bufend;

  /* Find the start address of the .dynamic section.  */
  dyninfo_sect = bfd_get_section_by_name (abfd, ".dynamic");
  if (dyninfo_sect == NULL)
    return 0;
  dyninfo_addr = (void *) bfd_section_vma (abfd, dyninfo_sect);

#ifdef __sun__
  /*
   * XXX Sanity check. Is this relocation at work?
   */
  if ((unsigned long) dyninfo_addr == 1) {
    return 0;
  }
#endif

  /* Read in .dynamic section, silently ignore errors.  */
  dyninfo_sect_size = bfd_section_size (abfd, dyninfo_sect);
  buf = (char *) malloc (dyninfo_sect_size);
  memcpy (buf, dyninfo_addr, dyninfo_sect_size);

  /* Find the DT_DEBUG entry in the the .dynamic section.
     For mips elf we look for DT_MIPS_RLD_MAP, mips elf apparently has
     no DT_DEBUG entries.  */
  for (bufend = buf + dyninfo_sect_size;
       buf < bufend;
       buf += sizeof (Elf32_External_Dyn)) {
    Elf32_External_Dyn *x_dynp = (Elf32_External_Dyn *)buf;
    long dyn_tag;
    PTR dyn_ptr;
    
    dyn_tag = bfd_h_get_32 (abfd, (bfd_byte *) x_dynp->d_tag);
    if (dyn_tag == DT_NULL)
      break;
    else if (dyn_tag == DT_DEBUG)
      {
	dyn_ptr = (void *) bfd_h_get_32 (abfd, (bfd_byte *) x_dynp->d_un.d_ptr);
	return dyn_ptr;
      }
  }
  
  /* DT_DEBUG entry not found.  */
  return 0;
}

static struct r_debug debug_copy;

static struct link_map *
first_link_map_member ()
{
  struct link_map *lm = NULL;

  memcpy ((char *) &debug_copy, debug_base, sizeof (struct r_debug));
  /* FIXME:  Perhaps we should validate the info somehow, perhaps by
     checking r_version for a known version number, or r_state for
     RT_CONSISTENT. */
  lm = debug_copy.r_map;
  return lm;
}

static void
add_to_section_table (bfd * abfd, sec_ptr asect, PTR table_pp_char)
{
  struct section_table **table_pp = (struct section_table **)table_pp_char;
  flagword aflag;

  aflag = bfd_get_section_flags (abfd, asect);
  if (!(aflag & SEC_ALLOC))
    return;
  if (0 == bfd_section_size (abfd, asect))
    return;
  (*table_pp)->abfd = abfd;
  (*table_pp)->the_bfd_section = asect;
  (*table_pp)->addr = (PTR) bfd_section_vma (abfd, asect);
  (*table_pp)->endaddr = (PTR) ((char *) (*table_pp)->addr + bfd_section_size (abfd, asect));
  (*table_pp)++;
}

/* Builds a section table, given args BFD, SECTABLE_PTR, SECEND_PTR.
   Returns 0 if OK, 1 on error.  */

int
build_section_table (bfd * some_bfd,
		     struct section_table ** start,
		     struct section_table ** end)
{
  unsigned count;

  count = bfd_count_sections (some_bfd);
  if (*start)
    free ((PTR)*start);
  *start = (struct section_table *) malloc (count * sizeof (**start));
  *end = *start;
  bfd_map_over_sections (some_bfd, add_to_section_table, (char *)end);
  if (*end > *start + count) {
    fprintf (stderr, "build_section_table() oops\n");
    exit (1);
  }
  /* We could realloc the table, but it probably loses for most files.  */
  return 0;
}

static void
solib_map_sections (struct so_list *so)
{
  struct section_table *p;
  char *filename;
  char *scratch_pathname;
  bfd *abfd;
  
  filename = so -> so_name;
  scratch_pathname = strdup (filename);

  /* Leave scratch_pathname allocated.  abfd->name will point to it.  */

  abfd = bfd_openr (scratch_pathname, NULL);
  if (!abfd)
    {
		
		/* fprintf (stderr, "Could not open `%s' as an executable file: %s",
	       scratch_pathname, bfd_errmsg (bfd_get_error ())); */
      return;
    }
  /* Leave bfd open, core_xfer_memory and "info files" need it.  */
  so -> abfd = abfd;

  strncpy (so->so_name, scratch_pathname, 1024);
  so->so_name[1023] = '\0';

  if (!bfd_check_format (abfd, bfd_object))
    {
      fprintf (stderr, "\"%s\": not in executable format: %s.",
	       scratch_pathname, bfd_errmsg (bfd_get_error ()));
      return;
    }

  if (build_section_table (abfd, &so -> sections, &so -> sections_end))
    {
      fprintf (stderr, "Can't find the file sections in `%s': %s", 
	       bfd_get_filename (abfd), bfd_errmsg (bfd_get_error ()));
      return;
    }

  for (p = so -> sections; p < so -> sections_end; p++)
    {
      /* Relocate the section binding addresses as recorded in the shared
	 object's file by the base address to which the object was actually
	 mapped. */
      p -> addr = (PTR) ((char *) p->addr + (size_t) LM_ADDR (so));
      p -> endaddr = (PTR) ((char *) p->endaddr + (size_t) LM_ADDR (so));
      if (p->endaddr > so->lmend) {
	so->lmend = p->endaddr;
      }
      if (strcmp (p -> the_bfd_section -> name, ".text") == 0)
	{
	  so -> textsection = p;
	}
    }

#if 0
  fprintf (stderr, "loading symbols from `%s' ... ", scratch_pathname);
  fflush  (stderr);
#endif
  so->syms = slurp_symtab (so->abfd);
#if 0
  if (!so->syms) {
    fprintf (stderr, "(no symbols) ... ");
  }
  fprintf (stderr, "done.\n");
#endif
}

static struct so_list *
find_solib (struct so_list *so_list_ptr)
{
  struct so_list *so_list_next = NULL;
  struct link_map *lm = NULL;
  struct so_list *newso;

  if (thebfd == NULL) {
    return NULL;
  }
  
  if (so_list_ptr == NULL)
    {
      /* We are setting up for a new scan through the loaded images. */
      if ((so_list_next = so_list_head) == NULL)
	{
	  /* We have not already read in the dynamic linking structures
	     from the inferior, lookup the address of the base structure. */
	  debug_base = elf_locate_base (thebfd);
	  if (debug_base != 0)
	    {
	      /* Read the base structure in and find the address of the first
		 link map list member. */
	      lm = first_link_map_member ();
	    }
	}
    }
  else
    {
      /* We have been called before, and are in the process of walking
	 the shared library list.  Advance to the next shared object. */
      if ((lm = LM_NEXT (so_list_ptr)) == NULL)
	{
	  /* We have hit the end of the list, so check to see if any were
	     added, but be quiet if we can't read from the target any more. */
	  memcpy ((char *) &(so_list_ptr -> lm),
		  so_list_ptr -> lmaddr,
		  sizeof (struct link_map));
	  lm = LM_NEXT (so_list_ptr);
	}
      so_list_next = so_list_ptr -> next;
    }
  if ((so_list_next == NULL) && (lm != NULL))
    {
      /* Get next link map structure from inferior image and build a local
	 abbreviated load_map structure */
      newso = (struct so_list *) malloc (sizeof (struct so_list));
      memset ((char *) newso, 0, sizeof (struct so_list));
      newso -> lmaddr = lm;
      /* Add the new node as the next node in the list, or as the root
	 node if this is the first one. */
      if (so_list_ptr != NULL)
	{
	  so_list_ptr -> next = newso;
	}
      else
	{
	  so_list_head = newso;
	}      
      so_list_next = newso;
      memcpy ((char *) &(newso -> lm), lm, sizeof (struct link_map));
      /* For SVR4 versions, the first entry in the link map is for the
	 inferior executable, so we must ignore it.  For some versions of
	 SVR4, it has no name.  For others (Solaris 2.3 for example), it
	 does have a name, so we can no longer use a missing name to
	 decide when to ignore it. */
      if (!IGNORE_FIRST_LINK_MAP_ENTRY (newso -> lm))
	{
	  strncpy (newso -> so_name, LM_NAME(newso), 1024 - 1);
	  newso -> so_name[1023] = '\0';
	  solib_map_sections (newso);
	}
    }
  return (so_list_next);
}

static struct so_list *
solib_address (PTR address)
{
  struct so_list *so = 0;   	/* link map state variable */
  
  while ((so = find_solib (so)) != NULL)
    {
      if (so -> so_name[0])
	{
	  if ((address >= (PTR) LM_ADDR (so)) &&
	      (address < (PTR) so -> lmend)) {
	    return so;
	  }
	}
    }
  return NULL;
}

#endif

static int found = 0;
static bfd_vma pc;
static asymbol **cursyms = 0;

static const char* filename = 0;
static const char* functionname = 0;
static unsigned int line = 0;

/* Look for an address in a section.  This is called via
   bfd_map_over_sections.  */

static void find_address_in_section (bfd * abfd, asection * section, PTR data)
{
  bfd_vma vma;

  if (found)
    return;

  if ((bfd_get_section_flags (abfd, section) & SEC_ALLOC) == 0)
    return;

  vma = bfd_get_section_vma (abfd, section);
  if (pc < vma)
    return;

  found = bfd_find_nearest_line (abfd, section, cursyms, pc - vma,
                                 &filename, &functionname, &line);
}

static int find_address (bfd * abfd, void * addr)
{
  /*
   * Search shared libs. Take relocation into account.
   */

#if defined(__linux__) || defined(__sun__)
  struct so_list * soptr = solib_address ((PTR) addr);
#endif

  found = 0;

#if defined(__linux__) || defined(__sun__)
  if (soptr && soptr->syms) {
    pc = (bfd_vma) ((char *) addr - (size_t) LM_ADDR(soptr));
    cursyms = soptr->syms;
    bfd_map_over_sections (soptr->abfd, find_address_in_section, (PTR) NULL);
  }
#endif

  /*
   * Try executable
   */

  if (!found) {
    pc = (bfd_vma) addr;
    cursyms = thesyms;
    bfd_map_over_sections (abfd, find_address_in_section, (PTR) NULL);
  }

  return found;
}

static void i_print_address( bfd* abfd, void* addr, int fullname, FILE* out)
{
	if (!find_address (abfd, addr)) {
		fprintf (out, "[0x%lx]", (unsigned long) addr);
	}
	else {
		if (functionname == NULL || *functionname == '\0') {
			fprintf (out, "[0x%lx]", (unsigned long) addr);
		}
		else {
			fprintf (out, "%-20s", functionname);

			if (!fullname && filename) {
				char *h;

				h = strrchr (filename, '/');
				if (h != NULL)
					filename = h + 1;
			}

			if (filename) {
				fprintf (out, "  (%s:%u)", filename, line);
			}
		}
	}
}

void do_init()
{
    static char exe[4096];
    
    sprintf(exe, "/proc/%d/exe", getpid());

    init_symtab(exe);
}

void print_address(void *addr, int fullname, FILE* out)
{
  if(thebfd == NULL)
  {
      do_init();
  }

  i_print_address( thebfd, addr, fullname, out);
}
