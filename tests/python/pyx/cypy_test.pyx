from cython.operator cimport dereference as deref
from libcpp.memory cimport unique_ptr
from libcpp.string cimport string


cdef extern from "hutch-disasm.hpp":
    cdef cppclass hutch_Disasm:
        hutch_Disasm()
        void configure (const string cpu)
        void options (const unsigned char opts);
        void disasm (const unsigned char * buf, unsigned long bufsize, unsigned long start);


cdef class pyhutch_Disasm:
    cdef unique_ptr[hutch_Disasm] thisptr

    def __init__(self):
        self.thisptr.reset(new hutch_Disasm())

    def configure(self, _cpu):
        deref(self.thisptr).configure(_cpu)

    def options(self, _opts):
        deref(self.thisptr).options(_opts)

    def disasm(self, _buf, _bufsize, _start):
        deref(self.thisptr).disasm(_buf, _bufsize, _start)
