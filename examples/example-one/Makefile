# The C compiler
CC=gcc
CXX=g++

# Debug flags
DBG_CXXFLAGS=-g -Wall -Wno-sign-compare

# Optimization flags
OPT_CXXFLAGS=-O2 -Wall -Wno-sign-compare

# libraries
INCLUDES=-I../../include -I../../src

LNK=../../lib/libsla.a

example-one.o:	example-one.cpp
	$(CXX) -c $(DBG_CXXFLAGS) $(INCLUDES) $< -o $@

example-one:	example-one.o
	$(CXX) $(DBG_CXXFLAGS) -o example-one example-one.o $(LNK)

clean:
	rm -rf *.o example-one

