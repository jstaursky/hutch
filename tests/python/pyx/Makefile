default: cypy_test

cypy_test: setup.py cypy_test.pyx
	python3 setup.py build_ext --inplace && rm -f cypy_test.cpp && rm -Rf build

clean:
	rm *.so
