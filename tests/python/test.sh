#!/bin/bash
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../../lib
python3 ./tester.py "$@"
