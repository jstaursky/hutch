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

#ifndef __HUTCH__
#define __HUTCH__

#include "loadimage.hh"
#include "sleigh.hh"

#include <optional>
#include <any>
#include <memory>

enum { IA32, AMD64 };
enum DisassemblyUnit { UNIT_BYTE, UNIT_INSN };

const uint1 OPT_IN_DISP_ADDR = (1 << 0);
const uint1 OPT_IN_PCODE     = (1 << 1);
const uint1 OPT_IN_ASM       = (1 << 2);

const uint1 OPT_OUT_DISP_ADDR = 0, OPT_OUT_PCODE = 0, OPT_OUT_ASM = 0;

//*****************************************************************************/
// * Function Declarations.
//
void printVarnodeData (ostream& s, VarnodeData* data);
void printPcode (PcodeData pcode);

//*****************************************************************************/
// * DefaultLoadImage
//
class DefaultLoadImage : public LoadImage {
    uintb baseaddr = 0;
    uint1 const* buf = nullptr;
    uintb bufsize = 0;
public:
    DefaultLoadImage (uintb baseaddr, uint1 const* buf, uintb bufsize) :
        LoadImage ("nofile"), baseaddr (baseaddr), buf (buf), bufsize (bufsize)
    {
    }
    inline uintb getImageSize () { return bufsize; }
    inline uintb getBaseAddr () { return baseaddr; }

    virtual void loadFill (uint1* ptr, int4 size, const Address& addr) override;
    virtual string getArchType (void) const override { return "Default"; };
    virtual void adjustVma (long adjust) override; // TODO
};

//*****************************************************************************/
// * Hutch
//
class Hutch {
    friend class Hutch_Insn;
    string docname;
    DocumentStorage docstorage;
    ContextInternal context;
    // Stores the executable buffer passed to initialize();
    unique_ptr<DefaultLoadImage> loader;
    // The sleigh translator.
    unique_ptr<Sleigh> trans;
    // Stores the options set.
    vector<pair<string, int4>> cpucontext;
    // Disassembler options, e.g., OPT_IN_DISP_ADDR, OPT_IN_PCODE, ...
    ssize_t optionslist = -1;

public:
    Hutch () = default;
    ~Hutch () = default; // TODO
    // Sets up docstorage.
    void preconfigure (string const sla_file, int4 cpu_arch);
    // Gets passed an bitwise OR to decide disassemble display options.
    void options (const uint1 options) { optionslist = options; }
    // Creates image of executable.
    void initialize (uint1 const* buf, uintb bufsize, uintb baseaddr);

    int4 instructionLength (const uintb baseaddr);

    void disassemble (DisassemblyUnit unit, uintb offset, uintb amount);
};
// *****************************************************************************

// THE FOLLOWING HACK ENABLES MULTIPLE INHERITANCE THROUGH AssemblyEmit + PcodeEmit.

//*****************************************************************************/
// * Hutch_PcodeEmit
//     Hack to enable multiple inheritance (PcodeEmit + AssemblyEmit both have
//     dump() that needs to be override'd).
class Hutch_PcodeEmit : public PcodeEmit {
public:
    virtual void dumpPcode (Address const& addr, OpCode opc, VarnodeData* outvar,
                            VarnodeData* vars, int4 isize);

    // Gets called multiple times through PcodeCacher::emit called by
    // trans.oneInstruction(pcodeemit, addr) -- which is called through
    // Hutch::disassemble(). -- see sleigh.cc for more info on call process.
    void dump (Address const& addr, OpCode opc, VarnodeData* outvar,
               VarnodeData* vars, int4 isize) final override
    // Note that overriding dumpPcode() effectively overrides this.
    {
        dumpPcode (addr, opc, outvar, vars, isize);
    }
};

//*****************************************************************************/
// * Hutch_AssemblyEmit
//     Hack to enable multiple inheritance (PcodeEmit + AssemblyEmit both have
//     dump() that needs to be override'd).
class Hutch_AssemblyEmit : public AssemblyEmit {
public:
    virtual void dumpAsm (const Address& addr, const string& mnem,
                          const string& body);

    // Gets called through trans.printAssembly(asmemit, addr).
    void dump (const Address& addr, const string& mnem,
               const string& body) final override // But overriding dumpAsm()
                                                  // effectively overrides this.
    {
        dumpAsm (addr, mnem, body);
    }

};

// BEGIN MULTIPLE INHERITANCE DEFINITION
// * Usage w/ trans.oneInstruction() + trans.printAssembly():
//     Hutch_PcodeEmit *pcode_emit = new Hutch_Insn;
//     trans.oneInstruction (*pcode_emit, someaddr);
//
//     auto *asm_emit = dynamic_cast<Hutch_AssemblyEmit*>(pcode_emit);
//     trans.printAssembly (*asm_emit, someaddr);
//
//   Alternatively,
//     Hutch_Insn emit;
//     trans.oneInstruction (emit, someaddr);
//     trans.printAssembly (emit, some addr);
//*****************************************************************************/
// * Hutch_Insn
//
class Hutch_Insn : public Hutch_PcodeEmit, public Hutch_AssemblyEmit {
    map<Address, string> asm_insns;
    multimap<Address, PcodeData> pcode_insns;
public:
    Hutch_Insn() = default;
    ~Hutch_Insn(void);
    // Also overrides Hutch_PcodeEmit::dump()
    virtual void dumpPcode (Address const& addr, OpCode opc, VarnodeData* outvar,
                            VarnodeData* vars, int4 isize) override;
    // Also overrides Hutch_AssemblyEmit::dump()
    virtual void dumpAsm (const Address& addr, const string& mnem,
                          const string& body) override;

    optional<vector<PcodeData>> liftInstruction (Hutch* handle, any offset, uint1* code, uintb bufsize);

    void printInstructionBytes (Hutch* handle, uintb offset);
};


#endif
