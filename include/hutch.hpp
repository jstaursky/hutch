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
#include "xml.hh"
#include "emulate.hh"
#include <initializer_list>
#include <any>
#include <memory>
#include <optional>
#include <fstream>
#include <iostream>

using AssemblyString = string;
// Forward Declarations.
class Hutch;
class Hutch_Insn;

struct Hutch_Data {
    string asm_stmt;
    vector<PcodeData> pcodes;
};
// This will generate warnings about expand_insn being declared but undefined. A
// necessary evil to have this compile correctly. The function was meant to be
// file local in Hutch.cpp and have other functions defined as instances of
// expand_insn with varying argument configurations--(*manip)() being the
// primary method to accomplish this--but since it needs access to class
// variables it needed to be declared as a friend function. Unfortunately this
// prevented compilation as _expand_insn() was appearing as extern in Hutch.hpp
// and static in Hutch.cpp. Thus forcing the below forward declaration to solve
// this.
// ! It is important to note that functions defined in terms of _expand_insn
// ! should not be used together. Reason being that they will either share or
// ! override each others buffer inside _expand_insn(). _expand_insn is
// ! basically a temporary hack to accelerate the defining of new functions
// ! while I figure out what is and is not useful.
static optional<Hutch_Data>
_expand_insn (Hutch* handle, Hutch_Insn* emit, uint1* code, uintb bufsize,
             bool (*manip) (PcodeData&, AssemblyString));


extern "C" {
    enum { IA32 };
    enum DisasmUnit { UNIT_BYTE, UNIT_INSN };
    extern const uint1 OPT_IN_DISP_ADDR;
    extern const uint1 OPT_IN_PCODE;
    extern const uint1 OPT_IN_ASM;
    extern const uint1 OPT_OUT_DISP_ADDR, OPT_OUT_PCODE, OPT_OUT_ASM;

    extern Hutch* hutch_new (int4 cpu);
    extern void hutch_configure (Hutch* hutch_h, char const* cpu);
    extern void hutch_options (Hutch* hutch_h, unsigned char const opt);
    extern void hutch_disasm (Hutch* hutch_h, unsigned char const* buf,
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
// * AssemblyRaw
//
class AssemblyRaw : public AssemblyEmit {
public:
    // Gets called through trans.printAssembly(asmemit, addr).
    virtual void dump (const Address& addr, const string& mnem,
                       const string& body) override;
};
//
// * hutch_asm
//
class Hutch_Asm : public AssemblyEmit {
    friend optional<Hutch_Data>
    _expand_insn (Hutch* handle, Hutch_Insn* emit, uint1* code, uintb bufsize,
                 bool (*manip) (PcodeData&,AssemblyString));

    AssemblyString asm_stmt;
public:
    virtual void dump (const Address& addr, const string& mnem,
                       const string& body) override
    {
        this->asm_stmt = mnem + ' ' + body;
    }
};
//
// * PcodeRawOut
//
class PcodeRawOut : public PcodeEmit {
    friend class Hutch_Insn;
public:
    // Gets called multiple times through PcodeCacher::emit called by
    // trans.oneInstruction(pcodeemit, addr) -- which is called through
    // Hutch::disasm(). -- see sleigh.cc for more info on call process.
    virtual void dump (Address const& addr, OpCode opc, VarnodeData* outvar,
                       VarnodeData* vars, int4 isize) override;
};
//
// * Hutch_Insn
//
class Hutch_Insn : public PcodeEmit {
    // Read comment in forward declaration at top of this file.
    friend optional<Hutch_Data>
    _expand_insn (Hutch* handle, Hutch_Insn* emit, uint1* code, uintb bufsize,
                 bool (*manip) (PcodeData&,AssemblyString));

    DocumentStorage   insn_docstorage;
    ContextInternal   insn_context;
    DefaultLoadImage* loader    = nullptr;
    Sleigh*           translate = nullptr;

    // Multimap because asm -> pcode is typically a 1 to many mapping.
    multimap<Address, PcodeData> rpcodes;

public:
    Hutch_Insn() = default;
    ~Hutch_Insn (void);
    // Populates rpcodes.
    virtual void dump (Address const& addr, OpCode opc, VarnodeData* outvar,
                       VarnodeData* vars, int4 isize) override;

    optional<Hutch_Data>
    expand_insn (Hutch* handle, uint1* code, uintb bufsize = 0);

};
//
// * Hutch_Emulate
//
class _Hutch_Emulate;           // Hidden class defined only in hutch.cpp

class Hutch_Emulate {
    Hutch* hutch_ptr = nullptr;

    MemoryState* memstate = nullptr;

    vector<any> memvalues;

    BreakTableCallBack* breaktable = nullptr;

    _Hutch_Emulate* emulater = nullptr;

    uintb execute_address = 0;

    multimap<uintb, BreakCallBack*> callbacks;

    int findCpuWordSize (Hutch* handle);

    void apply_settings ();
public:
    Hutch_Emulate() = default;
    ~Hutch_Emulate(void);

    void preconfigure (Hutch* handle);

    void add_address_callback (uintb addr, BreakCallBack* callback)
    {
        callbacks.insert(pair{addr,callback});
    }

    void set_execution_address (uintb off)
    {
        this->execute_address = off;
    }

    void set_emulater_value (const string& nm, uintb cval)
    {
        // Use verbose tuple<> here to ensure const string& is passed.
        memvalues.push_back(tuple<const string&, uintb>{nm, cval});
    }

    void set_emulater_value (AddrSpace *spc,uintb off,int4 size,uintb cval)
    {
        memvalues.push_back(tuple{spc, off, size, cval});
    }

    void set_emulater_value (const VarnodeData *vn, uintb cval)
    {
        memvalues.push_back(tuple{vn, cval});
    }

    // Needed for emulation.
    void emulate(int4 pagesize = 4096, int4 hashsize = 4096);

};
//
// * Hutch
//
class Hutch {
    friend class Hutch_Insn;    // Needs access to docname + cpu_context.
    friend class Hutch_Emulate;
    // Read comment in forward declaration at top of this file.
    friend optional<Hutch_Data>
    _expand_insn (Hutch* handle, Hutch_Insn* emit, uint1* code, uintb bufsize,
                  bool (*manip) (PcodeData&,AssemblyString));

    string          docname;
    DocumentStorage docstorage;
    ContextInternal context;
    // The sleigh translator.
    Sleigh* trans;
    // Stores the executable buffer passed to initialize();
    DefaultLoadImage* loader;
    // Check whether initialize() has already been called.
    bool isInitialized = false;
    // Disassembler options, e.g., OPT_IN_DISP_ADDR, OPT_IN_PCODE, ...
    ssize_t optionlist = -1;
    // Set the options to be used for context.setVariableDefault(...)
    void setArchContextInfo (int4 cpu);
    // Stores the options set.
    vector<pair<string, int4>> cpu_context;
public:
    Hutch () = default;
    ~Hutch () = default; // TODO
    // Sets up docstorage.
    void preconfigure (string const cpu, int4 arch);
    // Gets passed an bitwise OR to decide disasm display options.
    void options (const uint1 opts);
    // Creates image of executable.
    void initialize (uint1 const* buf, uintb bufsize, uintb baseaddr);
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
//
// * Function prototypes.
//
void hutch_print_pcodedata (ostream& s, PcodeData data);


#endif
