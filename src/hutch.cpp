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
    // if (!insns.pcodes.empty()) {
    //     auto [start, finish] = this->insns.pcodes.equal_range (addr.getOffset());
    //     if (start != finish) {
    //         PcodeData tmp (opc, outvar, vars, isize);
    //         do {
    //             auto [address, pcode] = pair{ start->first, start->second };
    //             if (pcode == tmp) {
    //                 return;
    //             }
    //         } while (++start != finish);
    //     }
    // }
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

    insns.insertInstruction(addr.getOffset(), pcode);
}

void Hutch_Insn::dumpAsm (const Address& addr, const string& mnem,
                          const string& body)
{
    insns.insertInstruction(addr.getOffset(), string (mnem + ' ' + body));
}

// void Hutch_Insn::clearInstructions ()
// {
//     insns.assembly.clear();
//     for (auto [ addr, pcode ] : insns.pcodes) {
//         if (pcode.outvar != nullptr)
//             delete pcode.outvar;
//         delete[] pcode.invar;
//     }
// }

// void Hutch_Insn::printInstructionBytes (Hutch* handle, uintb offset)
// {
//     uintm res = handle->trans->getInstructionBytes (
//         Address (handle->trans->getDefaultSpace (),
//                  handle->loader->getBaseAddr () + offset));

//     cout << "0x" << hex << res << endl;
// }

// Hutch_Insn::~Hutch_Insn (void)
// {
//     this->clearInstructions();
// }

Hutch_Insn::Insn Hutch_Insn::operator()(uintb i)
{
    return insns.getInstruction(i);
}

void Hutch_Insn::Hidden::insertInstruction (uintb addr, any insn)
{
    if (addrss_.size() == 0) { addrss_.push_back(addr); }
    if (addrss_.size() == 1) {
        if (addrss_[0] == addr) {
        } else if (addrss_[0] > addr) {
            addrss_.insert(addrss_.begin(), addr);
        } else {
            addrss_.insert(addrss_.begin() + 1, addr);
        }
    }

    auto index = distance(addrss_.begin(), lower_bound(addrss_.begin(), addrss_.end(), addr));
    if (addrss_[index] == addr) {
        if (insn.type() == typeid(PcodeData)) {
            auto pc = any_cast<PcodeData>(insn);
            for (auto [adr, pcode] : pcodes_) {
                if (pc == pcode) {
                    if (pcode.outvar != nullptr)
                        delete pcode.outvar;
                    delete[] pcode.invar;
                }
            }
        }
    } else
        addrss_.insert(addrss_.begin() + index, addr);

    if (insn.type() ==  typeid(PcodeData))
        pcodes_.insert({ addr, any_cast<PcodeData>(insn) });

    if (insn.type() == typeid(string))
        assembly_.insert(make_pair(addr, any_cast<string>(insn)));
}

Hutch_Insn::Insn Hutch_Insn::Hidden::getInstruction(int idx)
{
    Hutch_Insn::Insn insn;

    insn.address = addrss_[idx];
    insn.assembly = assembly_[addrss_[idx]];
    for (auto iter = pcodes_.find(addrss_[idx]); iter != pcodes_.end(); iter++)
        insn.pcode.push_back(iter->second);

    return insn;
}
