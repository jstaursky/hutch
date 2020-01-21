#include <iostream>
#include <string>
#include <filesystem>
#include "hutch.hpp"

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

    Hutch hutch_h;
    Hutch_Insn insn;

    hutch_h.preconfigure ("../../processors/x86/languages/x86.sla", IA32);

    auto img = (argc == 2) ? fbytes : code;
    auto imgsize = (argc == 2) ? fsize : sizeof (code);

    // Need to translate the buffer into internal representation prior to use.
    // Loaded image is persistent.
    hutch_h.initialize (img, imgsize, 0x12345680);

    // insn.clearInstructions ();
    for (auto [i, len, idx] = tuple{ 0, 0, 0 };
         len = hutch_h.disassemble_iter (i, imgsize, &insn); i += len, ++idx)
    {
        cout << "0x" << hex << insn(idx).address << endl;
        cout << insn(idx).assembly << endl;
        for (auto p : insn(idx).pcode)
            printPcode(p);

        cout << endl << "NEXT INSTRUCTION" << endl;
    }
    cout << "FINISHED\n";

    return 0;
}
