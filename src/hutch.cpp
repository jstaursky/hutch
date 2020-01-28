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
#include "types.h"
#include <algorithm>
/*****************************************************************************/
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

/*****************************************************************************/
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

/*****************************************************************************/
// * Hutch
//
Hutch::Hutch (string sladoc, int4 arch, const uint1* buf, uintb bufsize) : docname(sladoc)
{
    this->preconfigure(docname, arch);
    this->initialize (buf, bufsize, 0x00000000);
}

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

void Hutch::printInstructionBytes (const Hutch_Instructions::Instruction& insn)
{
    trans->printInstructionBytes( Address (trans->getDefaultSpace(), insn.address) );
    return;
}

ssize_t Hutch::disassemble(DisassemblyUnit unit, uintb offset, uintb amount, Hutch_Emit* emitter)
{
    Hutch_Emit emitdefault;
    Hutch_Emit* emit = (emitter) ? emitter : &emitdefault;

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
    auto i = 0;
    for (auto len = 0; i < amount && addr < lastaddr;
         i += (unit == UNIT_BYTE) ? len : 1, addr = addr + len) {
        if (auto e = dynamic_cast<Hutch_Instructions*>(emit)) {
            len = this->trans->printAssembly(*e, addr);
            this->trans->oneInstruction(*e, addr);
        }
        else {
            cout << "--- ";
            addr.printRaw (cout);
            cout << ":";
            len = this->trans->printAssembly (*emit, addr);
            this->trans->oneInstruction (*emit, addr);
        }
    }
    return i;                   // Return the number of instructions disassembled.
}

uint Hutch::disassemble_iter(uintb offset, uintb bufsize, Hutch_Emit* emitter)
{
    static uintb bufcheck = 0;
    static uintb ninsnbytes = 0;
    ninsnbytes = (bufcheck == bufsize)
        ? ninsnbytes : 0;
    bufcheck = (bufcheck == 0)
        ? bufsize : (bufcheck == bufsize) ? bufcheck : bufsize;

    if (ninsnbytes > bufsize)
        return 0;

    Hutch_Emit emitdefault;
    Hutch_Emit* emit = (emitter) ? emitter : &emitdefault;

    uintb baseaddr = this->loader->getBaseAddr ();

    Address addr (this->trans->getDefaultSpace (), baseaddr);
    Address lastaddr (this->trans->getDefaultSpace (),
                      baseaddr + this->loader->getImageSize ());

    addr = addr + offset;

    if (lastaddr <= addr) {
        cout << "exceeded last available address\n";
        return 0;
    }

    auto len = 0;
    if (auto e = dynamic_cast<Hutch_Instructions*>(emit)) {
        len = this->trans->printAssembly(*e, addr);
        this->trans->oneInstruction(*e, addr);
    }
    else {
        cout << "--- ";
        addr.printRaw (cout);
        cout << ":";
        len = this->trans->printAssembly (*emit, addr);
        this->trans->oneInstruction (*emit, addr);
    }

    if ((ninsnbytes += len) > bufsize) {
        cout << "exceeded buffer len\n";
        return 0;
    }
    return len;
}



void Hutch::preconfigure (string const sla_file, int4 cpu_arch)
{
    this->docname = sla_file;
    Element* ast_root = docstorage.openDocument (this->docname)->getRoot ();
    docstorage.registerTag (ast_root);

    this->arch = cpu_arch;
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

/*****************************************************************************/
// * Hutch_PcodeEmit
//
void Hutch_Emit::dumpPcode (Address const& addr, OpCode opc,
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

/*****************************************************************************/
// * Hutch_AssemblyEmit
//
void Hutch_Emit::dumpAsm (const Address& addr, const string& mnem,
                          const string& body)
{
    cout << mnem << ' ' << body << endl;
}

/*****************************************************************************/
// * Hutch_Instructions
//
void Hutch_Instructions::dumpPcode (Address const& addr, OpCode opc,
                                    VarnodeData* outvar, VarnodeData* vars,
                                    int4 isize)
{
    PcodeData pcode (opc, outvar, vars, isize);
    pcode.store(outvar, vars);
    storeInstruction(addr, pcode);
}

void Hutch_Instructions::dumpAsm (const Address& addr, const string& mnem,
                          const string& body)
{
    string assembly(mnem + " " + body);
    storeInstruction(addr, assembly);
}

Hutch_Instructions::Instruction Hutch_Instructions::operator()(uintb i)
{
    return instructions[i];
}

void Hutch_Instructions::storeInstruction (Address const& addr, any insn)
{
    auto len = addr.getSpace()->getTrans()->instructionLength(addr);

    if (instructions.empty ()) {
        Instruction instr;
        instr.bytelength = len;
        instr.address = addr.getOffset ();
        if (insn.type () == typeid (string)) {
            instr.assembly = any_cast<string> (insn);
        }
        if (insn.type () == typeid (PcodeData)) {
            instr.pcode.push_back (any_cast<PcodeData> (insn));
        }
        instructions.push_back (instr);
        this->current.instruction = &instructions.back();
        this->current.index = instructions.size() - 1;
        return;
    } else if ((insn.type () == typeid (PcodeData)) and
               (instructions.front ().pcode.empty ())) {
        instructions.front ().pcode.push_back (any_cast<PcodeData> (insn));
        instructions.front ().bytelength = len;
        this->current.instruction = &instructions.front();
        this->current.index = 0;
        return;
    }

    for (auto i = 0; i != instructions.size (); ++i) {
        if ((instructions[i].address == addr.getOffset ()) and
            (insn.type () == typeid (string))) {
            if (instructions[i].assembly == any_cast<string> (insn)) {
                this->current.instruction = &instructions[i];
                this->current.index = i;
                return;
            }
            if (instructions[i].assembly == "") {
                instructions[i].assembly = any_cast<string> (insn);
                instructions[i].bytelength = len;
                this->current.instruction = &instructions[i];
                this->current.index = i;
                return;
            }
        }
        if ((instructions[i].address == addr.getOffset ()) and
            (insn.type () == typeid (PcodeData))) {
            auto pcode = any_cast<PcodeData> (insn);
            if (find (instructions[i].pcode.begin (),
                      instructions[i].pcode.end (),
                      pcode) != instructions[i].pcode.end ()) {
                pcode.release ();
                this->current.instruction = &instructions.data()[i];
                this->current.index = i;
                return;
            } else {
                instructions[i].pcode.push_back (any_cast<PcodeData> (insn));
                instructions[i].bytelength = len;
                this->current.instruction = &instructions.data()[i];
                this->current.index = i;
                return;
            }
        }
    }

    Instruction instr;

    instr.address = addr.getOffset ();
    instr.bytelength = len;

    if (insn.type () == typeid (string))
        instr.assembly = any_cast<string> (insn);
    if (insn.type () == typeid (PcodeData))
        instr.pcode.push_back (any_cast<PcodeData> (insn));

    auto index = distance (
        instructions.begin (),
        lower_bound (instructions.begin (), instructions.end (),
                     addr.getOffset (),
                     [](const Instruction& lhs, const uintb& rhs) -> bool {
                         return lhs.address < rhs;
                     }));

    if (instructions[index].address != addr.getOffset ()) {
        instructions.insert (instructions.begin () + index, instr);
        this->current.instruction = &instructions.data()[index - 1];
        this->current.index = index - 1;
        return;
    }
    this->current.instruction = &instructions.data()[index];
    this->current.index = index;

}
