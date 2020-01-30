/*
 * Copyright 2020 Joe Staursky
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
#include <iterator>
#include <cstring>
/*****************************************************************************/
// * Functions
//










// Returns to position of "byte" inside buffer "buf" of size "sz".
// ex.
//     for (auto [pos, buf] = pair{ 0, img };
//     pos = bytePosition ("\xc3", buf, imgsize); buf = nullptr)
uintmax_t bytePosition (char const* byte, uint1* buf, size_t sz)
{
    static uint1* sbufp = nullptr;
    static uintmax_t spos = 0;  // i.e., s(aved)pos(ition)

    sbufp = (buf != nullptr) ? buf : sbufp;
    spos = (buf != nullptr) ? 0 : spos;

    for (; spos <= sz; ++spos) {
        if (0 == memcmp((uint1*)byte, &sbufp[spos], sizeof(uint1))) {
            return spos++;      // Post increment side effect is important here.
        }
    }

    return 0;
}



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
Hutch::Hutch (int4 arch, const uint1* buf, uintb bufsize)
{
    this->preconfigure(arch);
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

void Hutch::storeRawInstructionBytes (const Instruction& insn)
{
    trans->getInstructionBytes( Address (trans->getDefaultSpace(), insn.address), insn.raw);
    return;
}

void Hutch::printInstructionBytes (const Instruction& insn)
{
    for (auto i = 0; i < insn.bytelength; ++i) {
        cout << "0x" << hex << (int)insn.raw[i] << " ";
    }
    cout << endl;
    return;
}

//pDisassemble at offset "offset" the buffer passed to Hutch::initialize.
uint Hutch::disassemble_iter(uintb offset, Hutch_Emit* emitter)
{
    uintb baseaddr = this->loader->getBaseAddr ();

    Address addr (this->trans->getDefaultSpace (), baseaddr);
    Address lastaddr (this->trans->getDefaultSpace (),
                      baseaddr + this->loader->getBufferSize ());

    addr = addr + offset;

    if (lastaddr <= addr) {
        cout << "exceeded last available address\n";
        return 0;
    }
    auto len = 0;

    try {
        len = this->trans->printAssembly(*emitter, addr);
        this->trans->oneInstruction(*emitter, addr);
    } catch (const BadDataError&) {
        len = 0;
        emitter->removeBadInstruction ();
    }

    if (auto e = dynamic_cast<Hutch_Instructions*>(emitter))
        storeRawInstructionBytes(*e->currentinsn);

    return len;
}

vector<Instruction>
Hutch::inspectPreviousInstruction (uintb offset, uintb limit,
                                   Hutch_Instructions& insn,
                                   bool (*select) (PcodeData))
{
    vector<Instruction> res;

    resetMark (offset, insn);
    if (insn.getMark()->address - 1 == 0)
        return {};

    for (auto r = 1; (r != limit) && ((offset - r ) > 0) && disassemble_iter (offset - r, &insn); ++r)
        ;
    for (auto rinsn = insn.getMark () - 1; rinsn != insn.current (); --rinsn) {
        if (select == nullptr) {
            if ((rinsn->address + rinsn->bytelength) == insn.getMark ()->address)
                res.push_back (*rinsn);
            continue;
        }
        if (bool isSelected = false; (rinsn->address + rinsn->bytelength) == insn.getMark ()->address) {
            for (auto p : rinsn->pcode) {
                isSelected = select (p);
                if (isSelected) {
                    res.push_back (*rinsn);
                    break; }
            }
        }
    }
    return res;
}

void Hutch::preconfigure (int4 cpu_arch)
{
    this->arch = cpu_arch;
    switch (cpu_arch) {
    case IA32:
        docname    = "../../processors/x86/languages/x86.sla";
        cpucontext = { { "addrsize", 1 }, { "opsize", 1 } };

        break;
    default:
        // IA32 is default.
        cpucontext = { { "addrsize", 1 }, { "opsize", 1 } };
        break;
    }

    Element* ast_root = docstorage.openDocument (this->docname)->getRoot ();
    docstorage.registerTag (ast_root);
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

auto Hutch_Instructions::current () -> vector<Instruction>::iterator
{
    return instructions.begin() + distance(instructions.data(), currentinsn);
}

Instruction Hutch_Instructions::operator()(int i)
{
    return instructions[i];
}

void Hutch_Instructions::storeInstruction (Address const& addr, any insn)
{
    auto len = addr.getSpace ()->getTrans ()->instructionLength (addr);

    // Keep track of vector relocations for Hutch_Instructions::mark.
    auto ofront = (!instructions.empty ()) ? instructions.data () : 0;
    auto oback = (!instructions.empty ()) ?
                     instructions.data () + instructions.size () - 1 :
                     0;
    size_t fdiff, bdiff;

    // Do not need to track very initial run (when instructions.empty ())
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
        this->currentinsn = &instructions.back ();
        return;
    } else if ((insn.type () == typeid (PcodeData)) and
               (instructions.front ().pcode.empty ())) {
        instructions.front ().pcode.push_back (any_cast<PcodeData> (insn));
        instructions.front ().bytelength = len;
        this->currentinsn = &instructions.front ();

        // Move mark if vector instructions has moved.
        fdiff = instructions.data () - ofront;
        bdiff = (instructions.data () + instructions.size () - 1) - oback;
        mark = (mark != nullptr) ?
                     (fdiff != 0) || (bdiff != 0) ?
                     (fdiff > bdiff) ? mark + fdiff : mark + bdiff :
                     mark :
                     nullptr;
        return;
    }

    for (auto i = 0; i != instructions.size (); ++i) {
        if ((instructions[i].address == addr.getOffset ()) and
            (insn.type () == typeid (string))) {
            if (instructions[i].assembly == any_cast<string> (insn)) {
                this->currentinsn = &instructions[i];
                return;
            }
            if (instructions[i].assembly == "") {
                instructions[i].assembly = any_cast<string> (insn);
                instructions[i].bytelength = len;
                this->currentinsn = &instructions[i];
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
                this->currentinsn = &instructions[i];
                return;
            } else {
                instructions[i].pcode.push_back (any_cast<PcodeData> (insn));
                instructions[i].bytelength = len;
                this->currentinsn = &instructions[i];
                // Move mark if vector instructions has moved.
                fdiff = instructions.data () - ofront;
                bdiff =
                    (instructions.data () + instructions.size () - 1) - oback;
                mark = (mark != nullptr) ?
                             (fdiff != 0) || (bdiff != 0) ?
                             (fdiff > bdiff) ? mark + fdiff : mark + bdiff :
                             mark :
                             nullptr;
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
        if (index > 0)
            this->currentinsn = &instructions[index - 1];
        else
            this->currentinsn = &instructions[index];
        // Move mark if vector instructions has moved.
        fdiff = instructions.data () - ofront;
        bdiff = (instructions.data () + instructions.size () - 1) - oback;
        mark = (mark != nullptr) ?
                     (fdiff != 0) || (bdiff != 0) ?
                     (fdiff > bdiff) ? mark + fdiff : mark + bdiff :
                     mark :
                     nullptr;
        return;
    }
    this->currentinsn = &instructions[index];
}

void Hutch_Instructions::removeBadInstruction ()
{
    auto after = instructions.erase(current());
    auto index = distance(instructions.begin(), after);
    if (after == instructions.end()) {
        currentinsn = instructions.data() + index - 1;
    } else {
        currentinsn = instructions.data() + index;
    }
}
