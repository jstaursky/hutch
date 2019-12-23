# The C compiler
CC=gcc
CXX=g++

# Debug flags
DBG_CXXFLAGS=-g3 -Wall -Wno-sign-compare

# Optimization flags
OPT_CXXFLAGS=-std=c++17 -O1 -Wall -Wno-sign-compare

# libraries
INCLUDES=-I../../include
#-I../../src

LNK=../../lib/libsla.a

example-three:	example-three.o
	$(CXX) $(DBG_CXXFLAGS) -o example-three example-three.o $(LNK)

example-three.o:	example-three.cpp
	$(CXX) -c $(DBG_CXXFLAGS) $(INCLUDES) $< -o $@

clean:
	rm -rf *.o example-three

