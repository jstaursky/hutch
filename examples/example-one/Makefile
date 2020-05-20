CC=gcc -ggdb 
CXX=g++ -ggdb 

CXXFLAGS=-g3 -Wall -Wno-sign-compare -std=c++17

INCLUDES=-I../../include -I../../src/Sleigh/include

LNK=../../lib/libsla.a

example-one: example-one.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $< $(LNK) -o $@
