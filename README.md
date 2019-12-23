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

# EXAMPLE
```c++
#include "loadimage.hh"
#include "sleigh.hh"
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
    hutch_Disasm hutch_h;
    // x86 only atm, but this should be easy enough to change. Will update for
    // other arches eventually.
    hutch_h.configure("../../processors/x86/languages/x86.sla");

    // Can display Address info, pcode, assembly alone or in combination with
    // each other. Omission of hutch_h.options() will display a default of asm +
    // address info.
    hutch_h.options (OPT_IN_DISP_ADDR | OPT_IN_PCODE | OPT_IN_ASM);

    // Below relies on default args, full prototype of hutch_h.disasm is;
    // void hutch_Disasm::disasm (uint1 const* buf, uintb bufsize, uintb start,
    //                            ssize_t ninsn)

    hutch_h.disasm (code, sizeof (code));

    return 0;
}
```
Example can be found in `examples/example-three`.

# BUILDING

Type `make` in `hutch` main directory.

# WINDOWS BUILDING
Assuming your running under an mingw-w64-x86_64 style environment, after
installing `bison` and `flex` (and `g++` + `binutils` + etc.), execute `make
CXX='g++ -D_WINDOWS '`.


# MISC
[Ghidra Language Specification](https://ghidra.re/courses/languages/index.html)
