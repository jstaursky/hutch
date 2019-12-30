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

#include "hutch-disasm.hpp"

// *****************************************************************************
// Initial implementation of FFI
extern "C" {
    const uint1 OPT_IN_DISP_ADDR = (1<<0);
    const uint1 OPT_IN_PCODE     = (1<<1);
    const uint1 OPT_IN_ASM       = (1<<2);

    const uint1 OPT_OUT_DISP_ADDR = 0, OPT_OUT_PCODE = 0, OPT_OUT_ASM = 0;


    hutch_Disasm* hutch_Disasm_new (int4 cpu)
    {
        return new hutch_Disasm (cpu);
    }
    void hutch_configure (hutch_Disasm* hutch_h, char const* cpu)
    {
        hutch_h->configure (cpu);
    }
    void hutch_options (hutch_Disasm* hutch_h, unsigned char const opt)
    {
        hutch_h->options (opt);
    }
    void hutch_disasm (hutch_Disasm* hutch_h, unsigned char const* buf,
                       unsigned long bufsize)
    {
        hutch_h->disasm (buf, bufsize);
    }

} // end extern "C"
// *****************************************************************************



void hutch_Disasm::configure (string const cpu)
{
    Element* ast_root = docstorage.openDocument (cpu)->getRoot ();
    docstorage.registerTag (ast_root);
}

Sleigh hutch_Disasm::initializeImageAlloc (uint1 const* buf, uintb bufsize,
                                           uintb baseaddr)
{
    this->image = new DefaultLoadImage (baseaddr, buf, bufsize);
    Sleigh trans (image, &context);
    trans.initialize (docstorage);
    // cpu_context set by hutch_Disasm ctor.
    for (auto i : this->cpu_context)
        // first = option, second = setting.
        this->context.setVariableDefault (i.first, i.second);

    return trans;
}

void hutch_Disasm::releaseImage ()
{
    delete this->image;
}

void hutch_Disasm::disasm (uint1 const* buf, uintb bufsize, uintb baseaddr,
                           ssize_t ninsn)
// NOTE baseaddr = 0x1000 , ninsn = -1 is default
{
    Sleigh trans = initializeImageAlloc(buf, bufsize, baseaddr);
    PcodeRawOut pcodeemit;
    AssemblyRaw asmemit;
    int4 len;

    Address addr (trans.getDefaultSpace (), baseaddr);
    Address lastaddr (trans.getDefaultSpace (), baseaddr + bufsize);

    // Set up default options if user has not;
    optionlist = (optionlist == -1) ? OPT_IN_ASM | OPT_IN_DISP_ADDR : optionlist;
    // Set up default number of insns to count if user has not.
    ninsn = (ninsn == -1) ? bufsize : ninsn;
    // Assume ninsn was given the default -1 value. The above reassigns it to
    // the size of the buffer, consequently since the smallest insn len is 1,
    // The addr < lastaddr condition will trigger before the i < ninsn
    // condition. Conversly, if ninsn != -1 then the 1 < ninsn will trigger
    // before the addr < lastaddr condition (if used correctly) because we are
    // counting less instructions than the total that make up the buffer.
    // If ninsn is defined by user to be greator than the number of insns in
    // buffer, then addr < lastaddr will trigger first.
    for (auto i = 0; i < ninsn && addr < lastaddr; ++i, addr = addr + len) {
        // Print hex Address?
        if (optionlist & OPT_IN_DISP_ADDR) {
            cout << "--- ";
            addr.printRaw(cout);
            cout << ":";
        }
        // Print assembly?
        if (optionlist & OPT_IN_ASM) {
            len = trans.printAssembly (asmemit, addr);
        }
        // Print ir?
        if (optionlist & OPT_IN_PCODE) {
            len = trans.oneInstruction (pcodeemit, addr);
        }

    }
    releaseImage();
}

struct Pcode hutch_Disasm::lift (uint1 const* buf, uintb bufsize,
                                 uintb baseaddr, ssize_t ninsn)
{
    Sleigh trans = initializeImageAlloc(buf, bufsize, baseaddr);
    struct Pcode pcode;

    Address addr (trans.getDefaultSpace (), baseaddr);
    Address lastaddr (trans.getDefaultSpace (), baseaddr + bufsize);

    // Set up default number of insns to count if user has not.
    ninsn = (ninsn == -1) ? bufsize : ninsn;

    // Go through all pcode statements for each asm insn.
    for (auto i = 0, len = 0; i < ninsn && addr < lastaddr;
         ++i, addr = addr + len) {
        pair<vector<struct PcodeData>, int4> tmp = trans.hutch_liftInstruction (addr);
        pcode.insns = tmp.first.data ();
        pcode.ninsns = tmp.first.size ();
        len = pcode.bytelen = tmp.second;

        // Print all pcode statements corresponding to the i'th asm insn.
        for (auto n = 0; n < pcode.ninsns; ++n) {
            // If there is an output varnode, print it.
            print_vardata (cout, pcode.insns[n].outvar);
            if (pcode.insns[n].outvar != (VarnodeData*)0) {
                cout << " = ";
            }

            cout << get_opname (pcode.insns[n].opc);
            // Print out all varnode inputs to this operation.
            for (auto k = 0; k < pcode.insns[n].isize; ++k) {
                print_vardata (cout, &pcode.insns[n].invar[k]);
            }
            cout << endl;
        }
        cout << endl;
    }
    releaseImage();
    return pcode;
}

// Constructor kept separate so the list of cpu context variables can be large
// and not obstruct viewing the definition of hutch_Disasm.
hutch_Disasm::hutch_Disasm(int4 cpu) {
    switch (cpu) {
    case IA32:
        cpu_context = { {"addrsize",1},
                        {"opsize",1} };
        break;
    default:
        break;
    }
}

