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


    hutch_Disasm* hutch_Disasm_new ()
    {
        return new hutch_Disasm ();
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

void hutch_Disasm::disasm (uint1 const* buf, uintb bufsize, uintb baseaddr,
                           ssize_t ninsn)
// NOTE baseaddr = 0x1000 , ninsn = -1 is default
{
    DefaultLoadImage loader (baseaddr, buf, bufsize);

    Sleigh trans (&loader, &context);
    trans.initialize (docstorage);
    // TODO some cpu's do not have setup beyond ContextInternal (e.g., 8085) so
    // this needs be optional / have ability to be passed specific options.
    context.setVariableDefault ("addrsize", 1);
    context.setVariableDefault ("opsize", 1);

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
        // Print pcode?
        if (optionlist & OPT_IN_PCODE) {
            len = trans.oneInstruction (pcodeemit, addr);
        }

    }
}
