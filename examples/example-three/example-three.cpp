// Root include for parsing using SLEIGH
#include "loadimage.hh"
#include "sleighbase.hh"
#include "sleigh.hh"
#include "emulate.hh"
#include <iostream>
#include <string>

#include "hutch-disasm.hpp"

// x86 insns
//
// push ebp            \x55
// move ebp, esp       \x89\xe5
// mov eax, 0x12345678 \xb8\x78\x56\x34\x12
//
static uint1 code[] = { 0x55, 0x89, 0xe5, 0xb8, 0x78, 0x56, 0x34, 0x12 };

int main(int argc, char *argv[])
{
    hutch_Disasm handle;

    handle.configure("../../processors/x86/languages/x86.sla");
    handle.options (OPT_IN_DISP_ADDR | OPT_IN_PCODE | OPT_IN_ASM);
    handle.disasm (code, sizeof (code));

    return 0;
}
