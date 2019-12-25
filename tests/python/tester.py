import pyx.cypy_test as hutch

CODE = b"\x55\x89\xe5\xb8\x78\x56\x34\x12"

hutch_h = hutch.pyhutch_Disasm()

hutch_h.configure(b'../../processors/x86/languages/x86.sla')

hutch_h.disasm(CODE, len(CODE), 0x1000)

