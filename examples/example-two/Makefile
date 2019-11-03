# The C compiler
CC=gcc
CXX=g++

# Debug flags
DBG_CXXFLAGS=-g -Wall -Wno-sign-compare

# Optimization flags
OPT_CXXFLAGS=-O2 -Wall -Wno-sign-compare

# libraries
INCLUDES=-I../../include
#-I../../src

LNK=../../lib/libsla.a

example-two:	example-two.o
	$(CXX) $(DBG_CXXFLAGS) -o example-two example-two.o $(LNK)

example-two.o:	example-two.cpp
	$(CXX) -c $(DBG_CXXFLAGS) $(INCLUDES) $< -o $@

clean:
	rm -rf *.o example-two

