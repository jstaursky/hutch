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
        if (auto e = dynamic_cast<Hutch_Insn*>(emit)) {
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
    if (auto e = dynamic_cast<Hutch_Insn*>(emit)) {
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

//*****************************************************************************/
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

//*****************************************************************************/
// * Hutch_AssemblyEmit
//
void Hutch_Emit::dumpAsm (const Address& addr, const string& mnem,
                          const string& body)
{
    cout << mnem << ' ' << body << endl;
}

//*****************************************************************************/
// * Hutch_Insn
//
void Hutch_Insn::dumpPcode (Address const& addr, OpCode opc,
                            VarnodeData* outvar, VarnodeData* vars,
                            int4 isize)
{
    // Need to ensure that no duplicates can be inserted for a given address.
    if (!pcodes.empty()) {
        auto [start, finish] = this->pcodes.equal_range (addr.getOffset());
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

    this->pcodes.insert({ addr.getOffset(), pcode });
}

void Hutch_Insn::dumpAsm (const Address& addr, const string& mnem,
                          const string& body)
{
    this->assembly.insert({ addr.getOffset(), string (mnem + ' ' + body) });
}

void Hutch_Insn::clearInstructions ()
{
    assembly.clear();
    for (auto [ addr, pcode ] : pcodes) {
        if (pcode.outvar != nullptr)
            delete pcode.outvar;
        delete[] pcode.invar;
    }
}


optional<vector<PcodeData>> Hutch_Insn::liftInstruction (Hutch* handle, any offset,
                                                         uint1* code, uintb bufsize)
{
    // TODO
    // unique_ptr<Hutch> handle = make_unique<Hutch>(handle->docname, handle->arch, code, bufsize);

    uintb* lenptr = nullptr;
    if (offset.type() == typeid(uintb*))
        lenptr = any_cast<uintb*>(offset);

    ssize_t offsbegin = (offset.type() == typeid(uintb*)) ? *lenptr
        : (offset.type() == typeid(uintb)) ? any_cast<uintb>(offset)
        : (offset.type() == typeid(int)) ? any_cast<int>(offset)
        : -1;

    if (offsbegin == -1) {
        cout << "invalid offset type";
        return nullopt;
    }
    // Need to setup prior to insn being expanded and stored.
    Address mover (handle->trans->getDefaultSpace (),
                   handle->loader->getBaseAddr () + offsbegin);

    // Test whether or not the insn would be a valid insn.
    auto len = handle->instructionLength(offsbegin);

    if (offset.type() == typeid(uintb*)) {
        *lenptr += len;
    }

    offsbegin += len;
    if (offsbegin > bufsize) {
        cout << "exceeded buffer size";
        return nullopt;
    }
    // OK to expand and store the insn.
    handle->trans->oneInstruction (*this, mover);

    vector<PcodeData> result;
    auto [start, finish] = this->pcodes.equal_range (mover.getOffset());
    do {
        auto [addr, pcode] = pair{ start->first, start->second };
        result.push_back (pcode);
    } while (++start != finish);

    return result;
}

void Hutch_Insn::printInstructionBytes (Hutch* handle, uintb offset)
{
    uintm res = handle->trans->getInstructionBytes (
        Address (handle->trans->getDefaultSpace (),
                 handle->loader->getBaseAddr () + offset));

    cout << "0x" << hex << res << endl;
}

void Hutch_Insn::printPcodeInstructions ()
{
    for (auto [addr, pcode] : pcodes) {
        // addr.printRaw(cout);
        cout << "0x" << hex << addr << endl;
        cout << " ";
        printPcode(pcode);
    }
}

void Hutch_Insn::printAssemblyInstructions ()
{
    for (auto [addr, insn] : assembly) {
        // addr.printRaw(cout);
        cout << "0x" << hex << addr << endl;
        cout << " " + insn << endl;
    }
}

Hutch_Insn::~Hutch_Insn (void)
{
    this->clearInstructions();
}

