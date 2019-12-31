import pyx.cypy_test as hutch

# Need to run make in pyx directory to create shared lib first.

OPT_IN_DISP_ADDR = 1
OPT_IN_PCODE = 2
OPT_IN_ASM = 4

CODE = b"\x55\x89\xe5\xb8\x78\x56\x34\x12"

hutch_h = hutch.pyhutch()

hutch_h.configure(b'../../processors/x86/languages/x86.sla')

hutch_h.options(OPT_IN_DISP_ADDR | OPT_IN_PCODE | OPT_IN_ASM)

hutch_h.disasm(CODE, len(CODE), 0x1000)

