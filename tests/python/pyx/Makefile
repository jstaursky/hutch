LIB_DIR = ../../../lib

default: cypy_test

cypy_test: setup.py cypy_test.pyx $(LIB_DIR)/libsla.a
	python3 setup.py build_ext --inplace && rm -f cypy_test.cpp && rm -Rf build

$(LIB_DIR)/libsla.a:
	make -C $(LIB_DIR) libsla.a

clean:
	rm *.so
