CXX      = g++ 
# CXX = -O2 -Wall -Wno-sign-compare -std=c++17 -ggdb 

CXXFLAGS=-ggdb3 -m32 -Wall -Wno-sign-compare -std=c++17 -D_GLIBCXX_DEBUG

LEX  = flex
YACC = bison


BIN_DIR := bin
PROCESSORS := 8085

all: sleigh-compile libsla.a $(PROCESSORS:%=%.sla)
	$(CXX) -c $(CXXFLAGS) -I. sleighexample.cc
	$(CXX) $(CXXFLAGS) -o sleighexample sleighexample.o libsla.a

8085.sla: sleigh-compile
	$(BIN_DIR)/$< -a ../processors/8085


SLEIGH_COMPILE_OBJS := \
address \
context \
filemanage \
float \
globalcontext \
opcodes \
pcodecompile \
pcodeparse \
pcoderaw \
semantics \
sleigh \
sleighbase \
slgh_compile \
slghparse \
slghpatexpress \
slghpattern \
slghscan \
slghsymbol \
space \
translate \
xml

sleigh-compile: $(SLEIGH_COMPILE_OBJS:%=%.o)
	$(CXX) $(CXXFLAGS) -I. $^ -o $(BIN_DIR)/$@

$(SLEIGH_COMPILE_OBJS:%=%.o): | $(BIN_DIR)

LIBSLA_OBJS := \
address \
context \
emulate \
filemanage \
float \
globalcontext \
loadimage \
memstate \
opbehavior \
opcodes \
pcodecompile \
pcoderaw \
semantics \
sleighbase \
sleigh \
slghpatexpress \
slghpattern \
slghsymbol \
space \
translate \
xml

libsla.a: $(LIBSLA_OBJS:%=%.o)
	ar -rsv $@ $^

$(LIBSLA_OBJS:%=%.o): | $(BIN_DIR)


$(BIN_DIR):
	mkdir -p $(BIN_DIR)

xml.o: xml.cc xml.hh types.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

xml.cc: xml.y
	$(YACC) -p xml -o $@ $<

slghparse.cc: slghparse.y
	$(YACC) -d -o $@ $<

slghparse.tab.hh: slghparse.cc
	mv slghparse.hh slghparse.tab.hh

pcodeparse.cc: pcodeparse.y
	$(YACC) -p pcode -o $@ $<

slghscan.o: slghscan.cc

slghscan.cc: slghscan.l slghparse.tab.hh
	$(LEX) -o $@ $<

clean:
	rm -f *.o
	rm -f xml.cc
	rm -f slghscan.cc
	rm -f slghparse.cc
	rm -f slghparse.tab.hh
	rm -f pcodeparse.cc
	rm -rf bin
	rm -f libsla.a
	rm -f sleighexample
	rm -f ../processors/8085/8085.sla

# FOR AUTOMATICALLY GENERATING DEPENDENCIES.
SOURCES = $(SLEIGH_COMPILE_OBJS:%=%.cc)
# name of this file
MF = Makefile

depend:
	@echo 'updating the dependencies for:'
	@echo '    ' $(SOURCES)
	@{ \
	< $(MF) sed -n '1,/^###.*SUDDEN DEATH/p'; \
		echo '#' ; \
		echo '# dependencies generated on: ' `date` ; \
		echo '#' ; \
		for i in $(SOURCES); do \
			$(CXX) -MM $(CXXFLAGS) $(DEFINES) $$i ; \
			echo; \
		done \
	} > $(MF).new
	@mv $(MF) $(MF).last
	@mv $(MF).new $(MF)
#
# dependencies generated on:  Wed Jun 17 00:39:33 EDT 2020
#
address.o: address.cc address.hh space.hh error.hh types.h xml.hh \
 translate.hh pcoderaw.hh opbehavior.hh opcodes.hh float.hh

context.o: context.cc context.hh globalcontext.hh pcoderaw.hh address.hh \
 space.hh error.hh types.h xml.hh opbehavior.hh opcodes.hh partmap.hh \
 slghsymbol.hh semantics.hh slghpatexpress.hh slghpattern.hh translate.hh \
 float.hh

filemanage.o: filemanage.cc filemanage.hh

float.o: float.cc float.hh xml.hh types.h address.hh space.hh error.hh

globalcontext.o: globalcontext.cc globalcontext.hh pcoderaw.hh address.hh \
 space.hh error.hh types.h xml.hh opbehavior.hh opcodes.hh partmap.hh

opcodes.o: opcodes.cc opcodes.hh types.h

pcodecompile.o: pcodecompile.cc pcodecompile.hh slghsymbol.hh \
 semantics.hh context.hh globalcontext.hh pcoderaw.hh address.hh space.hh \
 error.hh types.h xml.hh opbehavior.hh opcodes.hh partmap.hh \
 slghpatexpress.hh slghpattern.hh


pcoderaw.o: pcoderaw.cc pcoderaw.hh address.hh space.hh error.hh types.h \
 xml.hh opbehavior.hh opcodes.hh translate.hh float.hh

semantics.o: semantics.cc semantics.hh context.hh globalcontext.hh \
 pcoderaw.hh address.hh space.hh error.hh types.h xml.hh opbehavior.hh \
 opcodes.hh partmap.hh translate.hh float.hh

sleigh.o: sleigh.cc sleigh.hh sleighbase.hh translate.hh pcoderaw.hh \
 address.hh space.hh error.hh types.h xml.hh opbehavior.hh opcodes.hh \
 float.hh slghsymbol.hh semantics.hh context.hh globalcontext.hh \
 partmap.hh slghpatexpress.hh slghpattern.hh loadimage.hh

sleighbase.o: sleighbase.cc sleighbase.hh translate.hh pcoderaw.hh \
 address.hh space.hh error.hh types.h xml.hh opbehavior.hh opcodes.hh \
 float.hh slghsymbol.hh semantics.hh context.hh globalcontext.hh \
 partmap.hh slghpatexpress.hh slghpattern.hh

slgh_compile.o: slgh_compile.cc slgh_compile.hh sleighbase.hh \
 translate.hh pcoderaw.hh address.hh space.hh error.hh types.h xml.hh \
 opbehavior.hh opcodes.hh float.hh slghsymbol.hh semantics.hh context.hh \
 globalcontext.hh partmap.hh slghpatexpress.hh slghpattern.hh \
 pcodecompile.hh filemanage.hh

slghpatexpress.o: slghpatexpress.cc slghpatexpress.hh slghpattern.hh \
 context.hh globalcontext.hh pcoderaw.hh address.hh space.hh error.hh \
 types.h xml.hh opbehavior.hh opcodes.hh partmap.hh sleighbase.hh \
 translate.hh float.hh slghsymbol.hh semantics.hh

slghpattern.o: slghpattern.cc slghpattern.hh context.hh globalcontext.hh \
 pcoderaw.hh address.hh space.hh error.hh types.h xml.hh opbehavior.hh \
 opcodes.hh partmap.hh

slghsymbol.o: slghsymbol.cc slghsymbol.hh semantics.hh context.hh \
 globalcontext.hh pcoderaw.hh address.hh space.hh error.hh types.h xml.hh \
 opbehavior.hh opcodes.hh partmap.hh slghpatexpress.hh slghpattern.hh \
 sleighbase.hh translate.hh float.hh


space.o: space.cc space.hh error.hh types.h xml.hh translate.hh \
 pcoderaw.hh address.hh opbehavior.hh opcodes.hh float.hh

translate.o: translate.cc translate.hh pcoderaw.hh address.hh space.hh \
 error.hh types.h xml.hh opbehavior.hh opcodes.hh float.hh


