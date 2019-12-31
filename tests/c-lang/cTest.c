#include <stdio.h>

// Compile against shared object lib.
// gcc -o cTest cTest.c -L../../lib -lsla (or alt.)
// gcc -o cTest cTest.c -L../../lib -l:../../libsla.so
extern struct hutch* hutch_new();
extern void hutch_configure(struct hutch*, char const*);
extern void hutch_options(struct hutch*, unsigned char);
extern void hutch_disasm(struct hutch*, unsigned char const*, unsigned long);
extern unsigned char const OPT_IN_DISP_ADDR, OPT_IN_PCODE, OPT_IN_ASM;

static unsigned char code[] = { 0x55, 0x89, 0xe5, 0xb8, 0x78, 0x56, 0x34, 0x12 };

int main(int argc, char *argv[])
{
    struct hutch* handle = hutch_new();
    hutch_configure(handle, "../../processors/x86/languages/x86.sla");
    hutch_options(handle, OPT_IN_ASM | OPT_IN_PCODE | OPT_IN_DISP_ADDR);
    hutch_disasm(handle, code, sizeof(code));

    return 0;
}
