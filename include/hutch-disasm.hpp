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
#ifndef __HUTCH_DISASM__
#define __HUTCH_DISASM__


#include "loadimage.hh"
#include "sleigh.hh"

#include <fstream>
#include <iostream>

class hutch_Disasm;             // Forward Declaration.

// Necessary for C ffi, see more in hutch-disasm.cpp
extern "C" {
    extern const uint1 OPT_IN_DISP_ADDR;
    extern const uint1 OPT_IN_PCODE;
    extern const uint1 OPT_IN_ASM;
    extern const uint1 OPT_OUT_DISP_ADDR, OPT_OUT_PCODE, OPT_OUT_ASM;

    extern hutch_Disasm* hutch_Disasm_new ();
    extern void hutch_configure (hutch_Disasm* hutch_h, char const* cpu);
    extern void hutch_options (hutch_Disasm* hutch_h, unsigned char const opt);
    extern void hutch_disasm (hutch_Disasm* hutch_h, unsigned char const* buf,
                              unsigned long bufsize);
}

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

    virtual void loadFill (uint1* ptr, int4 size, const Address& addr) override
    {
        auto start = addr.getOffset ();
        auto max = baseaddr + (bufsize - 1);
        for (auto i = 0; i < size; ++i) { // For every byte request
            auto curoff = start + i;      // Calculate offset of byte.
            if ((curoff < baseaddr) ||
                (curoff > max)) { // if byte does not fall in window,
                ptr[i] = 0;       // return 0
                continue;
            }
            auto diff = curoff - baseaddr;
            ptr[i] =
                this->buf[(int4)diff]; // Otherwise return data from our window.
        }
    }

    virtual string getArchType (void) const override
    {
        return "DefaultLoadImage";
    }
    virtual void adjustVma (long adjust) override {} // TODO
};


class PcodeRawOut : public PcodeEmit {
public:
    // Called via PcodeRawOut::dump
    void print_vardata (ostream& s, VarnodeData& data)
    {
        const Translate* trans = data.space->getTrans ();

        s << '(' << data.space->getName () << ',';
        if (data.space->getName () == "register") {
            s << trans->getRegisterName (data.space, data.offset, data.size);
        } else {
            data.space->printOffset (s, data.offset);
        }
        s << ',' << dec << data.size << ')';
    }
    // Gets called multiple times through PcodeCacher::emit called by
    // trans.oneInstruction(pcodeemit, addr) -- which is called through
    // hutch_Disasm::disasm(). -- see sleigh.cc for more info on call process.
    virtual void dump (Address const& addr, OpCode opc, VarnodeData* outvar,
                       VarnodeData* vars, int4 isize) override
    {
        if (outvar != (VarnodeData*)0) {
            print_vardata (cout, *outvar);
            cout << " = ";
        }
        cout << get_opname (opc);
        // Possibly check for a code reference or a space reference.
        for (int4 i = 0; i < isize; ++i) {
            cout << ' ';
            print_vardata (cout, vars[i]);
        }
        cout << endl;
    }
};


class AssemblyRaw : public AssemblyEmit {
public:
    // Gets called through trans.printAssembly(asmemit, addr).
    virtual void dump (const Address& addr, const string& mnem,
                       const string& body) override
    {
        cout << mnem << ' ' << body << endl;
    }
};


class hutch_Disasm {
    DocumentStorage docstorage;
    ContextInternal context;
    ssize_t optionlist = -1;

public:
    hutch_Disasm () = default;

    void configure (string const cpu);
    void options (const uint1 opts) { optionlist = opts; }
    void disasm (uint1 const* buf, uintb bufsize, uintb baseaddr = 0x00000000,
                 ssize_t ninsn = -1);
};

#endif
