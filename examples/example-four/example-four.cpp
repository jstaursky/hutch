#include "loadimage.hh"
#include "sleigh.hh"
#include "emulate.hh"
#include "memstate.hh"
#include "hutch.hpp"
#include <iostream>
#include <filesystem>

int main(int argc, char *argv[])
{
    auto     fsize (filesystem::file_size (argv[1]));
    uint1*   fbytes (new uint1[fsize]);
    ifstream file (argv[1], ios::in | ios::binary);
    file.read ((char*)fbytes, fsize);

    hutch hutch_h;
    hutch_transcribe scribe;

    hutch_h.configure ("../../processors/x86/languages/x86.sla", IA32);
    scribe.transpose(&hutch_h, fbytes, fsize, 0x12345680);

    hutch_h.disasm(&scribe, UNIT_BYTE, 2, 3);

    return 0;
}
