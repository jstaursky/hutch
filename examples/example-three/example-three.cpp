/*
 * Copyright 2019 Joe Staursky
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iostream>
#include <string>

#include <sys/stat.h>           // for struct stat status.st_size

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
    hutch hutch_h;
    hutch_insn insn;            // Needed to keep Sleigh translating object in
                                // scope for accessing pcode IR.

    // x86 only atm, but this should be easy enough to change. Will update for
    // other arches eventually.
    hutch_h.configure("../../processors/x86/languages/x86.sla");

    // Can display address info, pcode, assembly alone or in combination with
    // each other. Omission of hutch_h.options() will display a default of asm +
    // address info.
    hutch_h.options (OPT_IN_DISP_ADDR | OPT_IN_PCODE | OPT_IN_ASM);

    if (argc == 2) {
        // For experimenting w/ ./program =(echo -n $'\x55') and the like..
        struct stat filestatus;
        stat (argv[1], &filestatus);

        ifstream file (argv[1], ios::in | ios::binary);
        uint1* data = new uint1[filestatus.st_size];
        file.read((char*)data, filestatus.st_size);

        hutch_h.disasm (&insn, data, filestatus.st_size);

    } else {
        // Below relies on default args, full prototype of hutch_h.disasm is;
        // void hutch::disasm (uint1 const* buf, uintb bufsize, uintb start,
        //                            ssize_t ninsn)
        hutch_h.disasm (&insn, code, sizeof (code));

        cout << "\n* ACCESS TO PCODE IR! \n";

        // TODO cleanup IR access methodology, shouldnt need to use this much heap space.
        vector<struct Pcode*>* ir = hutch_h.lift(&insn, code, sizeof (code));

        for (auto pcode : *ir) {
            // Print all pcode statments corresponding to the ith asm insn.
            for (auto i = 0; i < pcode->ninsns; ++i) {
                print_vardata(cout, pcode->insns[i].outvar); // print output varnode.
                if (pcode->insns[i].outvar != (VarnodeData*)0) {
                    cout << " = ";
                }

                cout << get_opname(pcode->insns[i].opc);
                // Print out all varnode inputs to this operation.
                for (auto k = 0; k < pcode->insns[i].isize; ++k) {
                    print_vardata (cout, &pcode->insns[i].invar[k]);
                    cout << " ";
                }
                cout << endl;
            }
            cout << endl;
        }
    }

    return 0;
}
