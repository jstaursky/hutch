from cython.operator cimport dereference as deref
from libcpp.memory cimport unique_ptr
from libcpp.string cimport string


cdef extern from "hutch.hpp":
    cdef cppclass hutch:
        hutch()
        void configure (const string cpu)
        void options (const unsigned char opts);
        void disasm (const unsigned char * buf, unsigned long bufsize, unsigned long start);


cdef class pyhutch:
    cdef hutch hutch_h

    def __init__(self):
        self.hutch_h = hutch()

    def configure(self, _cpu):
        self.hutch_h.configure(_cpu)

    def options(self, _opts):
        self.hutch_h.options(_opts)

    def disasm(self, _buf, _bufsize, _start):
        self.hutch_h.disasm(_buf, _bufsize, _start)
