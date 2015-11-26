# If you want C++ functionality, put g++ as LIBCC

LIBCC=gcc
CFLAGS=-Wall -g -D_GNU_SOURCE -fno-omit-frame-pointer -O0 -c

LIBS=-lbfd -liberty
CC=$(LIBCC) $(CFLAGS)

ifeq ($(LIBCC), g++)
MYCPP=g++ $(CFLAGS)
else
MYCPP=
endif

# ----------------------------------
# If we have compiler cache, use it!
# ----------------------------------
ifneq ($(strip $(CCACHE_DIR)),)
CC:=ccache $(CC)
endif

TARGETS=libmmalloc.a generror
ifdef MYCPP
TARGETS+=cpperror
endif

all: $(TARGETS)

objects = mmalloc.o mbacktrace.o msymtab.o

libmmalloc.a: $(objects)
	 ar -r libmmalloc.a $(EXTRALIBS) mmalloc.o mbacktrace.o msymtab.o

generror: libmmalloc.a generror.o
	gcc -o generror generror.o libmmalloc.a $(LIBS)

ifdef MYCPP
cpperror: libmmalloc.a cpperror.o
	gcc -o cpperror libmmalloc.a cpperror.o $(LIBS)

cpperror.o: %.o: %.cpp mmalloc.h mconfig.h msymtab.h mbacktrace.h
	$(MYCPP) $< -o $@
endif

$(objects): %.o: %.c mmalloc.h mconfig.h msymtab.h mbacktrace.h
	$(CC) $< -o $@
clean:
	rm -rf *.o
	rm -f generror
	rm -f cpperror
	rm -f core
	rm -f libmmalloc.a
	rm -f mmalloc.opt
	rm -f mmalloc.ncb
	rm -f mmalloc.plg
	rm -rf Debug
