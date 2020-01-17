# hutch (a sleigh library derivative)
Separate the sleigh compiler from Ghidra, a rewritten Makefile.

I had trouble with the existing Makefile in the Ghidra repository and so after
some trial and error to get a successful build, I decided to rewrite it. So I
rewrote the Makefile, and built (IMO) a better folder structure for using sleigh
as a library.

The intent is not to be in 1-1 sync with the sleigh code-base found in ghidra, I
will be making my own modifications and eventually the two codebases will be
incompatible--Hence the change in name (as well as to avoid potiential trademark
issues). That said, until I start implementing my own changes, this repo will
try and stay up to date. I am still analyzing the codebase.

# WINDOWS BUILDING
Assuming your running under an mingw-w64-x86_64 style environment, after
installing `bison` and `flex` (and `g++` + `binutils` + etc.), execute `make
CXX='g++ -D_WINDOWS '`.


# BUILDING

Type `make` in `hutch` main directory.

Can now build as a static library or a shared library (e.g., for use from
python, example TBD).

You will want to install `g++-9` for easier time compiling the example in the
examples directory. Heavily using features from c++17/

# EXAMPLE
```c++
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
    for (auto i = 0;
         auto pcodes = insn.liftInstruction (&hutch_h, i, img, imgsize);
         i += hutch_h.instructionLength (i))
    {
        cout << "insn bytes: ";
        // Also able to print the raw bytes which are being disassembled.
        insn.printInstructionBytes (&hutch_h, i);
        for (auto p : *pcodes) {
            printPcode (p);
        }
    }

    return 0;
}
```

# MISC
Expect bindings found in `test` to be broken fairly often until a stable version number is released.

[Ghidra Language Specification](https://ghidra.re/courses/languages/index.html)

[Sleigh Decompiler Docs](https://ghidra-decompiler-docs.netlify.com/)
