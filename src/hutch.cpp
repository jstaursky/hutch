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

#include "hutch.hpp"

// TODO FIX C FFI.
// *****************************************************************************
// Initial implementation of FFI
// extern "C" {
    const uint1 OPT_IN_DISP_ADDR = (1<<0);
    const uint1 OPT_IN_PCODE     = (1<<1);
    const uint1 OPT_IN_ASM       = (1<<2);

    const uint1 OPT_OUT_DISP_ADDR = 0, OPT_OUT_PCODE = 0, OPT_OUT_ASM = 0;


//     hutch* hutch_new (int4 cpu)
//     {
//         return new hutch (cpu);
//     }
//     void hutch_configure (hutch* hutch_h, char const* cpu)
//     {
//         hutch_h->configure (cpu);
//     }
//     void hutch_options (hutch* hutch_h, unsigned char const opt)
//     {
//         hutch_h->options (opt);
//     }
//     void hutch_disasm (hutch* hutch_h, unsigned char const* buf,
//                        unsigned long bufsize)
//     {
//         hutch_h->disasm (buf, bufsize);
//     }

// } // end extern "C"
// *****************************************************************************



void hutch::configure (string const cpu)
{
    Element* ast_root = docstorage.openDocument (cpu)->getRoot ();
    docstorage.registerTag (ast_root);
}

void hutch::initHutchResources (class hutch_transcribe* insn, uint1 const* buf, uintb bufsize,
                                uintb baseaddr)
{
    if (insn->isInitialized) {
        delete insn->image;
        delete insn->trans;
    }
    // Start fresh.
    insn->image = new DefaultLoadImage (baseaddr, buf, bufsize);
    insn->trans = new Sleigh(insn->image, &context);
    insn->trans->initialize (docstorage);
    // cpu_context set by hutch ctor.
    for (auto i : this->cpu_context)
        // first = option, second = setting.
        this->context.setVariableDefault (i.first, i.second);

    insn->isInitialized = true;
}

void hutch::disasm (class hutch_transcribe* insn, uint1 const* buf, uintb bufsize, uintb baseaddr,
                    ssize_t ninsn)
// NOTE baseaddr = 0x1000 , ninsn = -1 is default
{
    initHutchResources(insn, buf, bufsize, baseaddr);
    PcodeRawOut pcodeemit;
    AssemblyRaw asmemit;

    Address addr (insn->trans->getDefaultSpace (), baseaddr);
    Address lastaddr (insn->trans->getDefaultSpace (), baseaddr + bufsize);

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
    for (auto i = 0, len = 0; i < ninsn && addr < lastaddr; ++i, addr = addr + len) {
        // Print hex Address?
        if (optionlist & OPT_IN_DISP_ADDR) {
            cout << "--- ";
            addr.printRaw(cout);
            cout << ":";
        }
        // Print assembly?
        if (optionlist & OPT_IN_ASM) {
            len = insn->trans->printAssembly (asmemit, addr);
        }
        // Print ir?
        if (optionlist & OPT_IN_PCODE) {
            len = insn->trans->oneInstruction (pcodeemit, addr);
        }

    }
}




vector<struct Pcode*>* hutch::lift (class hutch_transcribe* insn, uint1 const* buf, uintb bufsize,
                                    uintb baseaddr, ssize_t ninsn)
{
    initHutchResources(insn, buf, bufsize, baseaddr);
    vector<struct Pcode*> *pcode = new vector<struct Pcode*>;

    Address addr (insn->trans->getDefaultSpace (), baseaddr);
    Address lastaddr (insn->trans->getDefaultSpace (), baseaddr + bufsize);

    // Set up default number of insns to count if user has not.
    ninsn = (ninsn == -1) ? bufsize : ninsn;

    // Go through all pcode statements for each asm insn.
    for (auto i = 0, len = 0; i < ninsn && addr < lastaddr;
         ++i, addr = addr + len) {
        pair<vector<struct PcodeData>, int4> tmp = insn->trans->hutch_liftInstruction (addr);
        struct Pcode* instructions = new struct Pcode(tmp.first.data(), tmp.first.size(), tmp.second);
        pcode->push_back(instructions);
        len = tmp.second;

    }

    return pcode;
}

// Constructor kept separate so the list of cpu context variables can be large
// and not obstruct viewing the definition of hutch.
hutch::hutch(int4 cpu) {
    switch (cpu) {
    case IA32:
        cpu_context = { {"addrsize",1},
                        {"opsize",1} };
        break;
    default:                    // ctor given IA32 as default so this case is
                                // never triggered.
        break;
    }
}

