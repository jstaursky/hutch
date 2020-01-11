CC=gcc
CXX=g++

CXXFLAGS=-g3 -Wall -Wno-sign-compare -std=c++17

INCLUDES=-I../../include

LNK=../../lib/libsla.a

example-two: example-two.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $< $(LNK) -o $@
