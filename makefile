CC      = g++
PROF    = -g
C_FLAGS = -O0 -Wall -W $(PROF) -Wno-unused -fno-default-inline
L_FLAGS = -O0 $(PROF)

O_FILES = murk.o

# Files in the standard distribution
DISTFILES = Makefile Makefile.bor Makefile.vc One area.lst beggar.prg \
  crier.prg doc.txt drunk.prg gategrd.prg gategrd2.prg help.are janitor.prg  \
  license.crypt license.diku license.merc license.murk++ limbo.are \
  mid_cit.prg midgaard.are murk.cpp school.are startup vagabond.prg

PDIST= $(patsubst %,murk++/%,$(DISTFILES))
RELEASE=dist

murk: $(O_FILES)
	$(CC) $(L_FLAGS) -o murk $(O_FILES) -lcrypt

clean:
	-rm -f murk murk.exe murk.o

dist:
	ln -s ./ murk++
	tar czvf murk++-$(RELEASE).tar.gz $(PDIST)
	rm murk++
	
.cpp.o: 
	$(CC) -c $(C_FLAGS) $<
