import sys
from distutils.core import setup, Extension
from Cython.Build import cythonize

compile_args = ['-g', '-std=c++11', '-static-libstdc++', '-L../../../lib']

examples_extension = Extension(
    name="cypy_test",
    sources=["cypy_test.pyx"],
    extra_compile_args=compile_args,
    language='c++',
    libraries=["sla"],
    library_dirs=["../../../lib"],
    include_dirs=["../../../include"]
)
setup(
    name="cypy_test",
    ext_modules=cythonize([examples_extension]),
    gdb_debug=True
)
