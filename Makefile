# If you want C++ functionality, put g++ as LIBCC

LIBCC=gcc
#CFLAGS=-Wall -g3 -D_GNU_SOURCE -fno-omit-frame-pointer -O0 -c
CFLAGS=-Wall -Wextra -fsanitize=undefined -fsanitize=address -ggdb -gdwarf-5 -D_GNU_SOURCE -fno-omit-frame-pointer -Og -c
#CFLAGS=-Wall -Wextra -fno-inline -g3 -Werror=return-type -rdynamic -gdwarf-5 -D_GNU_SOURCE -fno-omit-frame-pointer -O0 -c
LIBS=
CC=$(LIBCC) $(CFLAGS)

ifeq ($(LIBCC), g++)
MYCPP=g++ $(CFLAGS)
else
MYCPP=
endif

TARGETS=libmmalloc.a generror
ifdef MYCPP
TARGETS+=cpperror
endif

all: $(TARGETS)

objects = mmalloc.o

libmmalloc.a: $(objects)
	 ar -r libmmalloc.a $(EXTRALIBS) mmalloc.o

generror: libmmalloc.a generror.o
	gcc -o generror generror.o libmmalloc.a $(LIBS) -rdynamic -lasan -lubsan

ifdef MYCPP
cpperror: libmmalloc.a cpperror.o
	gcc -o cpperror libmmalloc.a cpperror.o $(LIBS)

cpperror.o: %.o: %.cpp mmalloc.h mconfig.h
	$(MYCPP) $< -o $@
endif

$(objects): %.o: %.c mmalloc.h mconfig.h
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
