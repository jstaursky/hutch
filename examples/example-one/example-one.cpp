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

    // Can display Address info, pcode, assembly alone or in combination with
    // each other. Omission of hutch_h.options() will display a default of asm +
    // address info.
    hutch_h.options (OPT_IN_DISP_ADDR | OPT_IN_PCODE | OPT_IN_ASM);

    auto img = (argc == 2) ? fbytes : code;
    auto imgsize = (argc == 2) ? fsize : sizeof (code);

    // Need to translate the buffer into internal representation prior to use.
    // Loaded image is persistent.
    hutch_h.initialize (img, imgsize, 0x12345680);

    // Able to disassemble at specific offset + length.
    // The offset + length can be specified in terms bytes or instructions.
    hutch_h.disassemble (UNIT_BYTE, 0, imgsize);

    cout << "\nFOCUSING NOW ON PCODE" << endl;
    // liftInstruction will update the offset according to the insn bytelength
    // when passed as a pointer value.
    uintb offset = 0;
    while (auto pcodes =
               insn.liftInstruction (&hutch_h, &offset, img, imgsize)) {
        for (auto p : *pcodes) {
            printPcode (p);
        }
        cout << "\nWill now dissassemble to pcode starting at byte " << offset
             << endl;
    }
    cout << "Nothing left to dissassemble, onto next showcase!" << endl << endl;

    // liftInstruction will also accept a simple int or uintb if you want to
    // manage which offsets to disassemble into pcode by yourself.
    for (auto [i, pcodes, buf] = tuple{ 0, (optional<vector<PcodeData>>)nullopt, img };
         i < imgsize; i += 1, buf = nullptr)
    {
        auto k = i;
        cout << "i is " << i << endl;

        pcodes = insn.liftInstruction (&hutch_h, k, buf, imgsize);
        if (pcodes == nullopt)
            continue;

        cout << "insn bytes @" << k << ": ";
        // Also able to print the raw bytes which are being disassembled.
        insn.printInstructionBytes (&hutch_h, i);
        for (auto p : *pcodes) {
            printPcode (p);
        }
    }

    return 0;
}
