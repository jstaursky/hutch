#include <iostream>
#include <string>
#include <filesystem>
#include <algorithm>
#include "hutch.hpp"
#include <unistd.h>
#include <cstring>

// x86 insns
//
// push ebp            \x55
// move ebp, esp       \x89\xe5
// mov eax, 0x12345678 \xb8\x78\x56\x34\x12
//
static uint1 code[] = { 0x55, 0x89, 0xe5, 0xb8, 0x78, 0x56, 0x34, 0x12, 0xc3 };

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
    Hutch_Instructions insn;

    hutch_h.preconfigure (IA32);

    auto img = (argc == 2) ? fbytes : code;
    auto imgsize = (argc == 2) ? fsize : sizeof (code);

    // Need to translate the buffer into internal representation prior to use.
    // Loaded image is persistent.
    hutch_h.initialize (img, imgsize, 0x00000000);

    auto [len, offset] = pair{ 0, 0 };
    while (offset += len, len = hutch_h.disassemble_iter(offset, &insn)) {
        cout << "@address: " << insn.current()->address << endl
             << "Has bytes: ";
        hutch_h.printInstructionBytes(insn.current());
        cout << insn.current()->assembly << endl
             << "semantics" << endl;
        for (auto p : insn.current()->pcode)
            printPcode(p);
        cout << endl;
    }

    cout << "\n\n\n";
    cout << "will now output the raw binary valus for each insn" << endl;



    auto [length, mover] = pair{ 0, 0 };
    while (mover += length, length = hutch_h.disassemble_iter(mover, &insn)) {
        cout << insn.current()->rawBytes () << endl;

        int tmp = strlen((char*)insn.current()->rawBytes ()) + 1 + strlen ("echo -n ") + strlen (" | xxd");
        unsigned char* result = (unsigned char*)calloc(40, sizeof(unsigned char));

        char* s = (char*)calloc(tmp, sizeof (char));
        strcat(s, "echo -n ");
        strcat(s, (char*)insn.current()->rawBytes());
        strcat(s, " | xxd");

        FILE *fp = popen (s, "r");
        fgets ((char*)result, 40, fp);
        puts ((char*)result);
        printf ("\n");

    }



    return 0;
}
