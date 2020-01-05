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
#ifndef __HUTCH__
#define __HUTCH__

#include "loadimage.hh"
#include "sleigh.hh"

#include <fstream>
#include <iostream>

class hutch; // Forward Declaration for C ffi.
// Necessary for C ffi, see more in hutch.cpp
extern "C" {
    enum { IA32 };
    enum DisasmUnit { UNIT_BYTE, UNIT_INSN };
    extern const uint1 OPT_IN_DISP_ADDR;
    extern const uint1 OPT_IN_PCODE;
    extern const uint1 OPT_IN_ASM;
    extern const uint1 OPT_OUT_DISP_ADDR, OPT_OUT_PCODE, OPT_OUT_ASM;

    extern hutch* hutch_new (int4 cpu);
    extern void hutch_configure (hutch* hutch_h, char const* cpu);
    extern void hutch_options (hutch* hutch_h, unsigned char const opt);
    extern void hutch_disasm (hutch* hutch_h, unsigned char const* buf,
                              unsigned long bufsize);
}
//
// * DefaultLoadImage
//
class DefaultLoadImage : public LoadImage {
    uintb baseaddr = 0;
    uint1 const* buf = NULL;
    uintb bufsize = 0;
public:
    DefaultLoadImage (uintb baseaddr, uint1 const* buf, uintb bufsize) :
        LoadImage ("nofile"), baseaddr (baseaddr), buf (buf), bufsize (bufsize)
    {
    }
    inline uintb getImageSize () { return bufsize; }
    inline uintb getBaseAddr () { return baseaddr; }

    virtual void loadFill (uint1* ptr, int4 size, const Address& addr) override;
    virtual string getArchType (void) const override;
    virtual void adjustVma (long adjust) override;
};
//
// * PcodeRawOut
//
class PcodeRawOut : public PcodeEmit {
public:
    // Gets called multiple times through PcodeCacher::emit called by
    // trans.oneInstruction(pcodeemit, addr) -- which is called through
    // hutch::disasm(). -- see sleigh.cc for more info on call process.
    virtual void dump (Address const& addr, OpCode opc, VarnodeData* outvar,
                       VarnodeData* vars, int4 isize) override;
};
//
// * AssemblyRaw
//
class AssemblyRaw : public AssemblyEmit {
public:
    // Gets called through trans.printAssembly(asmemit, addr).
    virtual void dump (const Address& addr, const string& mnem,
                       const string& body) override;
};
//
// * hutch
//
class hutch {
    DocumentStorage docstorage;
    ContextInternal context;
    // Stores the executable buffer passed to initialize();
    DefaultLoadImage* image;
    // The sleigh translator.
    Sleigh* trans;
    // Check whether initialize() has already been called.
    bool isInitialized = false;
    // Disassembler options, e.g., OPT_IN_DISP_ADDR, OPT_IN_PCODE, ...
    ssize_t optionlist = -1;
    // Set the options to be used for context.setVariableDefault(...)
    void setArchContextInfo (int4 cpu);
    // Stores the options set.
    vector<pair<string, int4>> cpu_context;

public:
    hutch() = default;
    ~hutch() = default;                   // TODO
    // Sets up docstorage.
    void configure (string const cpu, int4 arch);
    // Gets passed an bitwise OR to decide disasm display options.
    void options (const uint1 opts);
    // Creates image of executable.
    void initialize(uint1 const* buf, uintb bufsize, uintb baseaddr);
    // * Disassembler notes
    // disasm() allows you to specify the offset + length with which you wish
    // begin disassembling. Additionally, this offset & length may be specified
    // in bytes or insns. That is, by specifying:
    //   disasm(UNIT_BYTE, 1, 3);
    //   - disassembling will begin 1 byte into the executable image.
    //   - continues for ~3 bytes (~ meaning approximately as
    //     disassembler appears to try and complete any incomplete or invalid
    //     insns--triggering errors will be looked into TODO).
    // Now if instead you specified,
    //   disasm(UNIT_INSN, 1, 3);
    //   - disassembling will begin 1 instruction past the begining of the
    //     image.
    //   - continues for 3 instructions.
    // In the case of simply disassembling the entire buffer, either
    // disasm(UNIT_BYTE, 0, <buffer-size>) or
    // disasm(UNIT_INSN, 0, <buffer-size>) will suffice.
    // * Caveats
    // - It should also be noted that I have not as of yet bothered will
    //   implementing error detection (TODO), so if you put garbage in you will
    //   get garbage out.
    // - options such as whether or not to display the baseaddress + rawpcode
    //   must be previously set by the options() method.
    void disasm (DisasmUnit unit, uintb offset, uintb amount);

};

#endif
