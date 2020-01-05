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

void hutch_transcribe::transpose(class hutch *handle, const uint1 *buf, uintb bufsize, uintb begaddr)
{
    if (this->isInitialized) {
        delete this->image;
        delete this->trans;
    }
    this->image = new DefaultLoadImage (begaddr, buf, bufsize);
    this->trans = new Sleigh(this->image, &handle->context);
    this->trans->initialize (handle->docstorage);

    for (auto [option, setting] : handle->cpu_context)
        handle->context.setVariableDefault (option, setting);

    this->isInitialized = true;
}

void hutch::configure (string const cpu, int4 arch)
{
    Element* ast_root = docstorage.openDocument (cpu)->getRoot ();
    docstorage.registerTag (ast_root);

    setArchInfo(arch);
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
    for (auto [option, setting] : this->cpu_context)
        this->context.setVariableDefault (option, setting);

    insn->isInitialized = true;
}

void hutch::disasm (class hutch_transcribe* scribe, disasmUnit unit,
                    uintb offset, uintb amount)

// NOTE baseaddr = 0x1000 , ninsn = -1 is default
{
    PcodeRawOut pcodeemit;
    AssemblyRaw asmemit;

    uintb baseaddr = scribe->image->getBaseAddr ();

    Address addr (scribe->trans->getDefaultSpace (), baseaddr);
    Address lastaddr (scribe->trans->getDefaultSpace (),
                      baseaddr + scribe->image->getImageSize ());

    // Is offset in instruction units?
    if (unit == UNIT_INSN) {
        // If so we want to move addr forward by offset amount of instructions.
        for (auto moveaddr = 0, insnlen = 0;
             moveaddr < offset && addr < lastaddr; addr = addr + insnlen) {
            moveaddr += insnlen = scribe->trans->instructionLength (addr);
        }
    } else {
        // Offset unit must be in bytes.
        addr = addr + offset;
    }

    // Set up default options if user has not;
    optionlist =
        (optionlist == -1) ? OPT_IN_ASM | OPT_IN_DISP_ADDR : optionlist;

    for (auto i = 0, len = 0; i < amount && addr < lastaddr;
         i += (unit == UNIT_BYTE) ? len : 1, addr = addr + len) {
        // Print hex Address?
        if (optionlist & OPT_IN_DISP_ADDR) {
            cout << "--- ";
            addr.printRaw (cout);
            cout << ":";
        }
        // Print assembly?
        if (optionlist & OPT_IN_ASM) {
            len = scribe->trans->printAssembly (asmemit, addr);
        }
        // Print ir?
        if (optionlist & OPT_IN_PCODE) {
            len = scribe->trans->oneInstruction (pcodeemit, addr);
        }
    }
}

vector<struct Pcode*>* hutch::lift (class hutch_transcribe* insn,
                                    uint1 const* buf, uintb bufsize,
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

void hutch::setArchInfo (int4 cpu) {
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

