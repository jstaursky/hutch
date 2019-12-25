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
    cdef hutch_Disasm hutch_h

    def __init__(self):
        self.hutch_h = hutch_Disasm()

    def configure(self, _cpu):
        self.hutch_h.configure(_cpu)

    def options(self, _opts):
        self.hutch_h.options(_opts)

    def disasm(self, _buf, _bufsize, _start):
        self.hutch_h.disasm(_buf, _bufsize, _start)
