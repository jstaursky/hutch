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
#include "xml.hh"
#include <iostream>

//*****************************************************************************/
// * Functions
//
void printVarnodeData (ostream& s, VarnodeData* data)
{
    if (data == nullptr)
        return;

    s << '(' << data->space->getName () << ',';

    const Translate* trans = data->space->getTrans ();

    if (data->space->getName () == "register") {
        s << trans->getRegisterName (data->space, data->offset, data->size);
    } else {
        data->space->printOffset (s, data->offset);
    }
    s << ',' << dec << data->size << ')';
    return;
}

void printPcode (PcodeData pcode)
{
    if (pcode.outvar) {
        printVarnodeData(cout, pcode.outvar);
        cout << " =  ";
    }
    cout << get_opname(pcode.opc);
    for (auto i = 0; i < pcode.isize; ++i) {
        cout << ' ';
        printVarnodeData(cout, &pcode.invar[i]);
    }
    cout << endl;
}

static Element* findTag (string tag, Element* root) {

    Element *el = root;
    while (el->getName() != tag) {
        for (auto e : el->getChildren()) {
            if (e->getName() == tag)
                return e;
            else
                return findTag(tag, e);
        }
    }
    cout << "could not find tag" << endl;
    return nullptr;
}

//*****************************************************************************/
// * DefaultLoadImage
//
void DefaultLoadImage::loadFill (uint1* ptr, int4 size,
                                 const Address& addr)
{
    auto start = addr.getOffset ();
    auto max = baseaddr + (bufsize - 1);
    for (auto i = 0; i < size; ++i) { // For every byte request
        auto curoff = start + i;      // Calculate offset of byte.
        if ((curoff < this->baseaddr) ||
            (curoff > max)) { // if byte does not fall in window,
            ptr[i] = 0;       // return 0
            continue;
        }
        // Otherwise return data from our window.
        auto diff = curoff - baseaddr;
        ptr[i] = this->buf[(int4)diff];
    }
}

void DefaultLoadImage::adjustVma (long adjust)
{
    // TODO
}

//*****************************************************************************/
// * Hutch
//
void Hutch::initialize (const uint1* buf, uintb bufsize, uintb begaddr)
{
    this->loader = make_unique<DefaultLoadImage>(begaddr, buf, bufsize);
    this->trans = make_unique<Sleigh>(this->loader.get(), &this->context);
    this->trans->initialize (this->docstorage);

    for (auto [option, setting] : this->cpucontext)
        this->context.setVariableDefault (option, setting);
}

int4 Hutch::instructionLength (const uintb addr)
{
    return trans->instructionLength(Address (trans->getDefaultSpace(),
                                             this->loader->getBaseAddr() + addr));
}

void Hutch::disassemble(DisassemblyUnit unit, uintb offset, uintb amount)
{
    Hutch_PcodeEmit emitPcode;
    Hutch_AssemblyEmit emitAsm;

    uintb baseaddr = this->loader->getBaseAddr ();

    Address addr (this->trans->getDefaultSpace (), baseaddr);
    Address lastaddr (this->trans->getDefaultSpace (),
                      baseaddr + this->loader->getImageSize ());

    // Is offset in instruction units?
    if (unit == UNIT_INSN) {
        // If so we want to move addr forward by offset amount of instructions.
        for (auto moveaddr = 0, insnlen = 0;
             moveaddr < offset && addr < lastaddr; addr = addr + insnlen) {
            moveaddr += insnlen = this->trans->instructionLength (addr);
        }
    } else {
        // Offset unit must be in bytes.
        addr = addr + offset;
    }

    // Set up default options if user has not;
    optionslist =
        (optionslist == -1) ? OPT_IN_ASM | OPT_IN_DISP_ADDR : optionslist;

    for (auto i = 0, len = 0; i < amount && addr < lastaddr;
         i += (unit == UNIT_BYTE) ? len : 1, addr = addr + len) {
        // Print hex Address?
        if (optionslist & OPT_IN_DISP_ADDR) {
            cout << "--- ";
            addr.printRaw (cout);
            cout << ":";
        }
        // Print assembly?
        if (optionslist & OPT_IN_ASM) {
            len = this->trans->printAssembly (emitAsm, addr);
        }
        // Print ir?
        if (optionslist & OPT_IN_PCODE) {
            len = this->trans->oneInstruction (emitPcode, addr);
        }
    }
}

void Hutch::preconfigure (string const sla_file, int4 cpu_arch)
{
    this->docname = sla_file;
    Element* ast_root = docstorage.openDocument (this->docname)->getRoot ();
    docstorage.registerTag (ast_root);

    switch (cpu_arch) {
    case IA32:
        cpucontext = { { "addrsize", 1 }, { "opsize", 1 } };

        break;
    default:
        // IA32 is default.
        cpucontext = { { "addrsize", 1 }, { "opsize", 1 } };
        break;
    }

}

//*****************************************************************************/
// * Hutch_PcodeEmit
//
void Hutch_PcodeEmit::dumpPcode (Address const& addr, OpCode opc,
                                 VarnodeData* outvar, VarnodeData* vars,
                                 int4 isize)
{
    if (outvar != (VarnodeData*)0) {
        printVarnodeData (cout, outvar);
        cout << " = ";
    }
    cout << get_opname (opc);
    // Possibly check for a code reference or a space reference.
    for (int4 i = 0; i < isize; ++i) {
        cout << ' ';
        printVarnodeData (cout, &vars[i]);
    }
    cout << endl;
}

//*****************************************************************************/
// * Hutch_AssemblyEmit
//
void Hutch_AssemblyEmit::dumpAsm (const Address& addr, const string& mnem,
                        const string& body)
{
    cout << mnem << ' ' << body << endl;
}

//*****************************************************************************/
// * Hutch_Insn
//
Hutch_Insn::~Hutch_Insn (void)
{
    for (auto [ addr, pcodes ] : pcode_insns) {
        if (pcodes.outvar != nullptr)
            delete pcodes.outvar;
        delete[] pcodes.invar;
    }
}

void Hutch_Insn::dumpPcode (Address const& addr, OpCode opc,
                            VarnodeData* outvar, VarnodeData* vars,
                            int4 isize)
{
    if (!pcode_insns.empty()) {
        auto [start, finish] = this->pcode_insns.equal_range (addr);
        if (start != finish) {
            PcodeData tmp (opc, outvar, vars, isize);
            do {
                auto [address, pcode] = pair{ start->first, start->second };
                if (pcode == tmp) {
                    return;
                }
            } while (++start != finish);
        }
    }
    PcodeData pcode;
    pcode.opc = opc;
    pcode.isize = isize;

    if (outvar != nullptr) {
        pcode.outvar = new VarnodeData;
        *pcode.outvar = *outvar;
    }
    else {
        pcode.outvar = nullptr;
    }
    pcode.invar = new VarnodeData[isize];
    for (auto i = 0; i != isize; ++i)
        pcode.invar[i] = vars[i];

    this->pcode_insns.insert({ addr, pcode });
}

void Hutch_Insn::dumpAsm (const Address& addr, const string& mnem,
                          const string& body)
{
    this->asm_insns.insert({ addr, string (mnem + ' ' + body) });
}

optional<vector<PcodeData>> Hutch_Insn::liftInstruction (Hutch* handle, any offset,
                                                         uint1* code, uintb bufsize)
{
    // The remaining buffer size.
    static uintb rbuffersize = (code == nullptr) ? rbuffersize : bufsize;
    ssize_t off_set = (offset.type() == typeid(uintb)) ? any_cast<uintb>(offset)
        : (offset.type() == typeid(int)) ? any_cast<int>(offset)
        : (offset.type() == typeid(uintb*)) ? *any_cast<uintb*>(offset)
        : -1;

    if (off_set <= -1) {
        cout << "invalid offset type";
        return nullopt;
    }

    if (off_set > rbuffersize)
        return nullopt;
    else
        rbuffersize -= off_set;

    Address mover (handle->trans->getDefaultSpace (),
                   handle->loader->getBaseAddr () + off_set);

    off_set += handle->trans->oneInstruction (*this, mover);

    vector<PcodeData> result;
    auto [start, finish] = this->pcode_insns.equal_range (mover);

    do {
        auto [addr, pcode] = pair{ start->first, start->second };
        result.push_back (pcode);
    } while (++start != finish);

    if (offset.type() == typeid(uintb))
        return result;
    if (offset.type() == typeid(uintb*)) {
        uintb* p = any_cast<uintb*>(offset);
        *p = off_set;
    }

    return result;
}

void Hutch_Insn::printInstructionBytes (Hutch* handle, uintb offset)
{
    uintm res = handle->trans->getInstructionBytes (
        Address (handle->trans->getDefaultSpace (),
                 handle->loader->getBaseAddr () + offset));

    cout << hex << res << endl;
}
