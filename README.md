# UPATE
All work has been moved to https://github.com/jstaursky/coronium. There the usage + install of the library have been greatly simplified.

# UPDATE 4/22/21
Currently in works of big update. Working on a deep yet discoverable API. 

# UPDATE 7/4/20
atm the makefile has an edge case that may prevent you from running `make -j$(nproc)` -- which means building in parallel may not work. In this case just run `make` to run make in a single thread.

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
    Hutch_Instructions insn;

    hutch_h.preconfigure ("../../processors/x86/languages/x86.sla", IA32);

    auto img = (argc == 2) ? fbytes : code;
    auto imgsize = (argc == 2) ? fsize : sizeof (code);

    // Need to translate the buffer into internal representation prior to use.
    // Loaded image is persistent.
    hutch_h.initialize (img, imgsize, 0x12345680);


    for (auto [i, len, idx] = tuple{ 0, 0, 0 };
         len = hutch_h.disassemble_iter (i, imgsize, &insn); i += len, ++idx)
    {
        cout << "0x" << hex << insn(idx).address << endl;
        cout << "number of bytes in insn = " << insn(idx).bytelength << endl;
        hutch_h.printInstructionBytes(insn(idx));
        cout << insn(idx).assembly << endl;
        for (auto p : insn(idx).pcode)
            printPcode(p);

        cout << endl << "NEXT INSTRUCTION" << endl;
    }
    cout << "FINISHED\n";

    return 0;
}
```
outputs

```
0x12345680
number of bytes in insn = 1
0x55 
PUSH EBP
(unique,0x1b50,4) =  COPY (register,EBP,4)
(register,ESP,4) =  INT_SUB (register,ESP,4) (const,0x4,4)
STORE (const,0x559cf7bd76e0,8) (register,ESP,4) (unique,0x1b50,4)

NEXT INSTRUCTION
0x12345681
number of bytes in insn = 2
0x89 0xe5 
MOV EBP,ESP
(register,EBP,4) =  COPY (register,ESP,4)

NEXT INSTRUCTION
0x12345683
number of bytes in insn = 5
0xb8 0x78 0x56 0x34 0x12 
MOV EAX,0x12345678
(register,EAX,4) =  COPY (const,0x12345678,4)

NEXT INSTRUCTION
exceeded last available address
FINISHED
```
# MISC
Expect bindings found in `test` to be broken fairly often until a stable version number is released.

[Ghidra Language Specification](https://ghidra.re/courses/languages/index.html)

[Sleigh Decompiler Docs](https://ghidra-decompiler-docs.netlify.com/)
