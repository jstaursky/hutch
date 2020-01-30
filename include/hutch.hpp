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

#include <vector>
#include <cstring>
#include <optional>
#include <any>
#include <memory>

// Forward Declaration(s)
class Hutch_Emit;
/*****************************************************************************/
enum { IA32, AMD64 };
enum DisassemblyUnit { UNIT_BYTE, UNIT_INSN };

const uint1 OPT_IN_DISP_ADDR = (1 << 0);
const uint1 OPT_IN_PCODE     = (1 << 1);
const uint1 OPT_IN_ASM       = (1 << 2);

const uint1 OPT_OUT_DISP_ADDR = 0, OPT_OUT_PCODE = 0, OPT_OUT_ASM = 0;

/*****************************************************************************/
// * Function Declarations.
//
void printVarnodeData (ostream& s, VarnodeData* data);
void printPcode (PcodeData pcode);
uintmax_t bytePosition (string byte, uint1* buf, size_t sz);

/*****************************************************************************/
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
    inline uintb getBufferSize () { return bufsize; }
    inline uintb getBaseAddr () { return baseaddr; }

    virtual void loadFill (uint1* ptr, int4 size, const Address& addr) override;
    virtual string getArchType (void) const override { return "Default"; };
    virtual void adjustVma (long adjust) override; // TODO
};

/*****************************************************************************/
// THE FOLLOWING HACK ENABLES MULTIPLE INHERITANCE THROUGH AssemblyEmit + PcodeEmit.

/*****************************************************************************/
// * Hutch_PcodeEmit
//     Hack to enable multiple inheritance (PcodeEmit + AssemblyEmit both have
//     dump() that needs to be override-n).
class Hutch_PcodeEmit : public PcodeEmit {
public:
    virtual void dumpPcode (Address const& addr, OpCode opc, VarnodeData* outvar,
                            VarnodeData* vars, int4 isize) = 0;

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

/*****************************************************************************/
// * Hutch_AssemblyEmit
//     Hack to enable multiple inheritance (PcodeEmit + AssemblyEmit both have
//     dump() that needs to be override-n).
class Hutch_AssemblyEmit : public AssemblyEmit {
public:
    virtual void dumpAsm (const Address& addr, const string& mnem,
                          const string& body) = 0;

    // Gets called through trans.printAssembly(asmemit, addr).
    void dump (const Address& addr, const string& mnem,
               const string& body) final override // But overriding dumpAsm()
                                                  // effectively overrides this.
    {
        dumpAsm (addr, mnem, body);
    }

};
struct Instruction;
class Hutch_Emit : public Hutch_PcodeEmit, public Hutch_AssemblyEmit {
    friend class Hutch;
    // vector<Instruction> instructions;

    // // For tracking the most recent disassembled instruction.
    // // Gets set in disassemble_iter.
    // Instruction* currentinsn = nullptr;

    // virtual void storeInstruction (Address const&, any) = 0;

    virtual void removeBadInstruction () = 0;

public:
    virtual void dumpPcode (Address const& addr, OpCode opc, VarnodeData* outvar,
                            VarnodeData* vars, int4 isize) override;
    virtual void dumpAsm (const Address& addr, const string& mnem,
                          const string& body) override;

};

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
/*****************************************************************************/

struct Instruction {
    // Really 15 but include room for byte '\0' for easy printing.
    enum {
        MAX_INSN_LEN = 16
    };

    uintb address;
    size_t bytelength = 0;
    string assembly = "";
    vector<PcodeData> pcode;

    // - Aggregate initialization ensures "raw" is initialized with all
    //   zeros.
    // - Sleigh::getInstructionBytes() const forces this to be mutable, but
    //   not sure whether I like it. Might instead remove const from
    //   Sleigh::getInstructionBytes()
    mutable uint1 raw[MAX_INSN_LEN] = {};

    Instruction () = default;
    Instruction (const Instruction& other) :
        address (other.address), bytelength (other.bytelength),
        assembly (other.assembly)
    {
        for (auto i : other.pcode)
            pcode.push_back (PcodeData (i));
        for (auto i = 0; i < MAX_INSN_LEN; ++i)
            raw[i] = other.raw[i];
    }

    ~Instruction (void)
    {
        for (auto p : pcode) {
            p.release ();
        }
    }
};

class Hutch;
// * Hutch_Instructions
//
class Hutch_Instructions : public Hutch_Emit {
    friend class Hutch;

    vector<Instruction> instructions;

    // For tracking the most recent disassembled instruction.
    // Gets set in disassemble_iter.
    Instruction* currentinsn = nullptr;

    void storeInstruction (Address const&, any);

    void removeBadInstruction () override;

    // Logic is present to track when/if vector "instructions" relocates.
    Instruction* mark = nullptr;

    // fills in Instruction::pcode via trans.oneInstruction()
    virtual void dumpPcode (Address const& addr, OpCode opc,
                            VarnodeData* outvar, VarnodeData* vars,
                            int4 isize) override;
    // fills in Instruction::assembly via trans.printAssembly()
    virtual void dumpAsm (const Address& addr, const string& mnem,
                          const string& body) override;

public:
    Hutch_Instructions () = default;
    // TODO
    // ~Hutch_Insn() = default;
    // - Hutch_Instructions::Instruction.pcode needs to be released
    //   (cannot write a destructor for PcodeData, need to manage it manually)

    // This can only tell you about the insns processed so far, so for example,
    // if you have disassembled some offset into the buffer skipping the
    // beginning, then isns(0) != instruction at the beginning of the buffer.
    Instruction operator() (int);

    uint4 count () { return instructions.size (); }

    vector<Instruction>::iterator current ();

    // setMark + resetMark are apart of class Hutch
    auto getMark () -> vector<Instruction>::iterator
    { return instructions.begin() + distance (instructions.data(), mark); }
    auto begin () { return instructions.begin (); }
    auto end () { return instructions.end (); }
    auto rbegin () { return instructions.rbegin (); }
    auto rend () { return instructions.rend (); }
};

/*****************************************************************************/
// * Hutch
//
class Hutch {
    friend class Hutch_Instructions;
    string docname;
    int4 arch;
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

    void storeRawInstructionBytes (const Instruction& insn);

public:
    Hutch () = default;
    Hutch (int4 arch, const uint1* buf, uintb bufsize);
    ~Hutch () = default; // TODO
    // Sets up docstorage.
    void preconfigure (int4 cpu_arch);
    // Gets passed an bitwise OR to decide disassemble display options.
    void options (const uint1 options) { optionslist = options; }
    // Creates image of executable.
    void initialize (uint1 const* buf, uintb bufsize, uintb baseaddr);

    uintb getBufferSize () { return loader->getBufferSize(); }

    int4 instructionLength (const uintb baseaddr);

    uint disassemble_iter(uintb offset, Hutch_Emit* emitter);

    vector<Instruction>
    inspectPreviousInstruction (uintb offset, uintb limit,
                                 Hutch_Instructions& insn,
                                 bool (*select) (PcodeData));

    void printInstructionBytes (const Instruction& insn);

    void setMark (uintb position,
                  Hutch_Instructions& insn)
    {
        this->disassemble_iter(position, &insn);
        insn.mark = insn.instructions.data()
                     + distance(insn.instructions.data(), insn.currentinsn);
    }

    void resetMark (uintb position,
                    Hutch_Instructions& insn)
    {
        this->disassemble_iter(position, &insn);
        insn.mark = insn.instructions.data()
                     + distance(insn.instructions.data(), insn.currentinsn);
    }

};

#endif
