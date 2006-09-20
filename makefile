#
# Murk++ build for cygwin, linux and bsd
#
CPP = g++
CC = gcc
AR = ar

# The suffix appended to executables.  
# This should be set for Cygwin and Windows.
EXE = .exe
#EXE =

# This should be OS_WIN=1 for Cygwin
DEFS = -DOS_UNIX=0 -DOS_WIN=1 -DHAVE_USLEEP=1 -DHAVE_FDATASYNC=1 -DNDEBUG
# For other unixes
#DEFS = -DOS_UNIX=1 -DOS_WIN=0 -DHAVE_USLEEP=1 -DHAVE_FDATASYNC=1 -DNDEBUG
# For FreeBSD
#DEFS = -DOS_UNIX=1 -DOS_WIN=0 -DHAVE_USLEEP=1 -DNDEBUG
 

OPTIM = -O0 -pipe 
WARN = -Wall -Wno-parentheses -Wno-unused 
PROF    = -g

CPPFLAGS = $(OPTIM) $(WARN) -W $(PROF) -fno-default-inline 
CFLAGS = $(OPTIM) $(DEFS) $(WARN) -fno-strict-aliasing
LFLAGS = $(OPTIM) $(PROF) 

INCS = -Isqlite3 
LIBS = -lcrypt 

SQLITE_SRC = sqlite3/alter.c sqlite3/analyze.c sqlite3/attach.c \
	sqlite3/auth.c sqlite3/btree.c sqlite3/build.c sqlite3/callback.c \
	sqlite3/complete.c sqlite3/date.c sqlite3/delete.c sqlite3/expr.c \
	sqlite3/func.c sqlite3/hash.c sqlite3/insert.c sqlite3/legacy.c \
	sqlite3/loadext.c sqlite3/main.c sqlite3/opcodes.c sqlite3/os.c \
	sqlite3/os_unix.c sqlite3/os_win.c sqlite3/pager.c sqlite3/parse.c \
	sqlite3/pragma.c sqlite3/prepare.c sqlite3/printf.c sqlite3/random.c \
	sqlite3/select.c sqlite3/table.c sqlite3/tokenize.c sqlite3/trigger.c \
	sqlite3/update.c sqlite3/utf.c sqlite3/util.c sqlite3/vacuum.c \
	sqlite3/vdbe.c sqlite3/vdbeapi.c sqlite3/vdbeaux.c sqlite3/vdbefifo.c \
	sqlite3/vdbemem.c sqlite3/vtab.c sqlite3/where.c
SQLITE_OBJ = $(SQLITE_SRC:.c=.o)
SQLITE_LIB = sqlite3/libsqlite3.a

SQLITE_PRG_SRC = sqlite3/shell.c 
SQLITE_PRG_OBJ = $(SQLITE_PRG_SRC:.c=.o)
SQLITE_PRG = sqlite3/sqlite3$(EXE) 

SQLITE_XTRA = sqlite3/sqlite3.def sqlite3/btree.h \
	sqlite3/os.h sqlite3/sqlite3.h sqlite3/vdbeInt.h sqlite3/hash.h \
	sqlite3/os_common.h sqlite3/sqlite3ext.h sqlite3/keywordhash.h \
	sqlite3/pager.h sqlite3/sqliteInt.h sqlite3/opcodes.h sqlite3/parse.h \
	sqlite3/vdbe.h

MURK_UTIL_SRC = loadhelps.cpp
MURK_UTIL_OBJ = $(MURK_UTIL_SRC:.cpp=.o)
MURK_SRC = murk.cpp os.cpp descriptor.cpp utils.cpp commands.cpp io.cpp \
	room.cpp object.cpp character.cpp spells.cpp objproto.cpp mobproto.cpp \
	affect.cpp exit.cpp area.cpp reset.cpp extra.cpp shop.cpp pcdata.cpp
MURK_OBJ = $(MURK_SRC:.cpp=.o)
MURK_HDR = os.hpp config.hpp descriptor.hpp character.hpp pcdata.hpp utils.hpp \
	globals.hpp object.hpp note.hpp room.hpp area.hpp mobproto.hpp \
	objproto.hpp affect.hpp exit.hpp extra.hpp ban.hpp shop.hpp reset.hpp \
	io.hpp 

OBJDEPENDS = $(MURK_OBJ) $(MURK_UTIL_OBJ)

# Data files Areas, Mobprogs and Players
DATAFILES = area.lst limbo.are mid_cit.prg midgaard.are school.are help.are \
        vagabond.prg beggar.prg crier.prg drunk.prg gategrd.prg gategrd2.prg \
	janitor.prg One schema item_types socials titles

# Files in the standard distribution
DISTFILES = $(MURK_SRC) $(MURK_UTIL_SRC) $(MURK_HDR) $(DATAFILES) \
	$(SQLITE_SRC) $(SQLITE_PRG_SRC) $(SQLITE_XTRA) \
	makefile makefile.bor makefile.vc makefile.dgm \
	doc.txt startup license.crypt license.diku license.merc license.murk++ 
  
PDIST= $(patsubst %,murk++/%,$(DISTFILES))
RELEASE=dist

TARGETS = $(SQLITE_LIB) $(SQLITE_PRG) murk$(EXE) loadhelps$(EXE)

all: $(TARGETS)

$(SQLITE_LIB): $(SQLITE_OBJ)
	$(AR) rsc $@ $^

$(SQLITE_PRG): $(SQLITE_PRG_OBJ) $(SQLITE_LIB)
	$(CC) $(LFLAGS) -o $@ $^

murk$(EXE): $(MURK_OBJ) $(SQLITE_LIB) 
	$(CPP) $(LFLAGS) -o $@ $^ $(LIBS)

loadhelps$(EXE): loadhelps.o io.o utils.o $(SQLITE_LIB) 
	$(CPP) $(LFLAGS) -o $@ $^ $(LIBS)

database: $(SQLITE_PRG) loadhelps$(EXE)
	@echo "Building database..."
	@-cp murk.db murk.db.bkup
	@-rm murk.db
	@sqlite3/sqlite3 murk.db < schema
	@./loadhelps
	@echo "Done."

clean:
	-rm -f $(TARGETS) $(MURK_OBJ) $(MURK_UTIL_OBJ) $(SQLITE_OBJ) \
	$(SQLITE_PRG_OBJ) $(OBJDEPENDS:.o=.d)

dist:
	ln -s ./ murk++
	tar czvf murk++-$(RELEASE).tar.gz $(PDIST)
	rm murk++
	
# pull in dependency info for *existing* .o files
-include $(OBJDEPENDS:.o=.d)

# compile and generate dependency info;
# more complicated dependency computation, so all prereqs listed
# will also become command-less, prereq-less targets
#   sed:    append directory to object target. (gcc bug?)
#   sed:    strip the target (everything before colon)
#   sed:    remove any continuation backslashes
#   fmt -1: list words one per line
#   sed:    strip leading spaces
#   sed:    add trailing colons
%.o: %.cpp
	$(CPP) -c $(CPPFLAGS) $(INCS) $*.cpp -o $*.o
	@$(CPP) -MM $(CPPFLAGS) $(INCS) $*.cpp > $*.d
	@mv -f $*.d $*.d.tmp
	@sed -e 's|.*:|$*.o:|' < $*.d.tmp > $*.d
	@sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp | fmt -1 | \
	  sed -e 's/^ *//' -e 's/$$/:/' >> $*.d
	@rm -f $*.d.tmp

#.cpp.o: 
#	$(CPP) -c $(CPPFLAGS) $(INCS) $*.cpp -o $*.o 

.c.o: 
	$(CC) -c $(CFLAGS) $(INCS) $*.c -o $*.o 

