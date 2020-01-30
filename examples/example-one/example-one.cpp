#include <iostream>
#include <string>
#include <filesystem>
#include <algorithm>
#include "hutch.hpp"

// x86 insns
//
// push ebp            \x55
// move ebp, esp       \x89\xe5
// mov eax, 0x12345678 \xb8\x78\x56\x34\x12
//
static uint1 code[] = { 0xff, 0xff, 0xff, 0x58, 0x5a, 0xc9, 0xc3 };

// { 0x55, 0x89, 0xe5, 0xb8, 0x78, 0x56, 0x34, 0x12, 0xc3, 0x55, 0xc3 };


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

    vector<vector<Instruction>> gadget;

    for (auto [retpos, buf] = pair{ 0, img }; retpos = bytePosition("\xc3", buf, imgsize); buf = nullptr ) {

        // Find instructions that could be prepend the ret insn to begin forming
        // a ROP gadget.
        vector<Instruction> pinsn = hutch_h.inspectPreviousInstruction (
            retpos, 15, insn, [](PcodeData pcode) -> bool {
                return ((pcode.opc == CPUI_STORE) || (pcode.opc == CPUI_LOAD) ||
                        (pcode.opc == CPUI_COPY));
            });

        if (pinsn.empty())
            continue;
        // Will reverse this later to put in proper order. Just under time
        // crunch atm.
        gadget.push_back(pinsn);
    }

    for (auto candidates : gadget) {
        for (auto i : candidates) {
            cout << "@0x" << hex << i.address << endl;
            hutch_h.printInstructionBytes (i);
            cout << i.assembly << endl;
            cout << "insn semantics" << endl;
            for (auto p : i.pcode) {
                printPcode (p);
            }
            cout << endl;
        }
    }

    // // Analyze each potiential instruction to determine whether suitable for ROP
    // // chain. Analysis is performed backwards from the instruction closest to
    // // the ret(c3) instruction to the farthest away.
    // for (auto g = 0; g != gadgets.size (); ++g) {
    //     // Remove uneligable instruction canidates.
    //     remove_if (gadgets[g].begin (), gadgets[g].end (), [](auto i) {
    //         // By default assume the insn is not applicable.
    //         auto notApplicable = true;
    //         for (auto p : i.pcode) {
    //             if ((p.opc == CPUI_STORE) || ((p.opc == CPUI_LOAD)))
    //                 notApplicable = false; // Keep Instructions relating to
    //                                        // storing and loading.
    //         }
    //         return (notApplicable ? true : false);
    //     });
    // }

    // cout << "**********************************" << endl;
    // for (auto i : gadgets) {
    //     for (auto j : i) {
    //         cout << "@0x" << j.address << endl
    //              << j.assembly << endl;
    //         for (auto k : j.pcode) {
    //             printPcode(k);
    //         }
    //         cout << endl;
    //     }
    // }
    // cout << "**********************************" << endl;

    return 0;
}
