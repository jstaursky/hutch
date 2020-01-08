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
python, example coming soon).

You will want to install `g++-9` for easier time compiling the example in the
examples directory.

# EXAMPLE
```c++
#include <iostream>
#include <string>

#include "hutch.hpp"

// x86 insns
//
// push ebp            \x55
// move ebp, esp       \x89\xe5
// mov eax, 0x12345678 \xb8\x78\x56\x34\x12
//
static uint1 code[] = { 0x55, 0x89, 0xe5, 0xb8, 0x78, 0x56, 0x34, 0x12 };

int main (int argc, char* argv[])
{
    Hutch hutch_h;
    Hutch_Insn insn;

    hutch_h.preconfigure ("../../processors/x86/languages/x86.sla", IA32);

    // Can display Address info, pcode, assembly alone or in combination with
    // each other. Omission of hutch_h.options() will display a default of asm +
    // address info.
    hutch_h.options (OPT_IN_DISP_ADDR | OPT_IN_PCODE | OPT_IN_ASM);

    // Need to translate the buffer into internal representation prior to use.
    // Loaded image is persistent.
    hutch_h.initialize (code, sizeof (code), 0x12345680);

    // Able to disassemble at specific offset + length.
    // The offset + length can be specified in terms bytes or instructions.
    hutch_h.disasm (UNIT_BYTE, 0, sizeof (code));

    // The above is useful for handling a single persistent image. If you have
    // snippets you want to pass and convert to pcode, you only need to run the
    // hutch_h.preconfigure step before continuing to the below.
    cout << "\n* Convert insn by insn to raw pcode\n";

    // Convert insn by insn to pcode and print.
    for (auto [buf, asm_pcode] = pair{ img, (optional<Hutch_Data>)nullopt };
         asm_pcode = insn.expand_insn(&hutch_h, buf, imgsize);
         buf = nullptr)
    {
        cout << asm_pcode->asm_stmt <<endl;
        for (auto pc : asm_pcode->pcodes)
            hutch_print_pcodedata(cout, pc);
    }

    return 0;
}
```
Example can be found in `examples/example-three`.

# MISC
Expect bindings found in `test` to be broken fairly often until a stable version number is released.
[Ghidra Language Specification](https://ghidra.re/courses/languages/index.html)
