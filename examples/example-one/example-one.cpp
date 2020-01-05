#include "loadimage.hh"
#include "sleigh.hh"
#include "emulate.hh"
#include "memstate.hh"
#include "hutch.hpp"
#include <iostream>
#include <filesystem>

// x86 insns
//
// push ebp            \x55
// move ebp, esp       \x89\xe5
// mov eax, 0x12345678 \xb8\x78\x56\x34\x12
//
static uint1 code[] = { 0x55, 0x89, 0xe5, 0xb8, 0x78, 0x56, 0x34, 0x12 };


int main(int argc, char *argv[])
{
    size_t fsize;
    uint1* fbytes = nullptr;

    if (argc == 2) {
        fsize = filesystem::file_size (argv[1]);
        fbytes = new uint1[fsize];
        ifstream file (argv[1], ios::in | ios::binary);
        file.read ((char*)fbytes, fsize);
    }

    hutch hutch_h;

    hutch_h.preconfigure ("../../processors/x86/languages/x86.sla", IA32);
    hutch_h.options(OPT_IN_DISP_ADDR | OPT_IN_PCODE | OPT_IN_ASM);

    auto img = (argc == 2) ? fbytes : code;
    uintb imgsize = (argc == 2) ? fsize : sizeof(code);

    hutch_h.initialize(img,imgsize,0x12345680);

    hutch_h.disasm(UNIT_BYTE, 0, imgsize);

    return 0;
}
