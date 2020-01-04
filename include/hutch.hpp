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

class hutch; // Forward Declaration for C ffi.
// Necessary for C ffi, see more in hutch.cpp
extern "C" {
enum { IA32 };
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

static void print_vardata (ostream& s, VarnodeData* data)
{
    if (data == (VarnodeData*)0)
        return;

    const Translate* trans = data->space->getTrans ();

    s << '(' << data->space->getName () << ',';
    if (data->space->getName () == "register") {
        s << trans->getRegisterName (data->space, data->offset, data->size);
    } else {
        data->space->printOffset (s, data->offset);
    }

    s << ',' << dec << data->size << ')';
}

struct [[depreciated("Should use PcodeOpRaw instead")]] Pcode {
    struct PcodeData* insns;
    uintb ninsns;
    int4 bytelen;
    Pcode () = default;
    // TODO not sure whether Deep copy ctor necessary.
    Pcode (struct PcodeData* data, uintb insn_cnt, int4 bytelen) :
    ninsns (insn_cnt), bytelen (bytelen)
    {
        insns = new struct PcodeData[insn_cnt];

        for (auto i = 0; i < insn_cnt; ++i) {
            insns[i].opc = data[i].opc;
            insns[i].isize = data[i].isize;
            insns[i].invar = new VarnodeData[data[i].isize];

            if (data[i].outvar != (VarnodeData*)0) {
                insns[i].outvar = new VarnodeData;
                *insns[i].outvar = *data[i].outvar;
            } else {
                insns[i].outvar = (VarnodeData*)0;
            }

            for (auto j = 0; j < data[i].isize; ++j) {
                insns[i].invar[j] = data[i].invar[j];
            }
        }
    }
};

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
            if ((curoff < this->baseaddr) ||
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
    // Gets called multiple times through PcodeCacher::emit called by
    // trans.oneInstruction(pcodeemit, addr) -- which is called through
    // hutch::disasm(). -- see sleigh.cc for more info on call process.
    virtual void dump (Address const& addr, OpCode opc, VarnodeData* outvar,
                       VarnodeData* vars, int4 isize) override
    {
        if (outvar != (VarnodeData*)0) {
            print_vardata (cout, outvar);
            cout << " = ";
        }
        cout << get_opname (opc);
        // Possibly check for a code reference or a space reference.
        for (int4 i = 0; i < isize; ++i) {
            cout << ' ';
            print_vardata (cout, &vars[i]);
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

class hutch {
    DocumentStorage docstorage;
    ContextInternal context;
    ssize_t optionlist = -1;

    vector<pair<string, int4>> cpu_context;

    void initHutchResources (class hutch_transcribe* insn, uint1 const* buf,
                             uintb bufsize, uintb baseaddr);

public:
    hutch (int4 cpu = IA32);    // See ctor at end of hutch.cpp for
                                // viewing the different cpu context
                                // variables that are set.
    // Sets up docstorage.
    void configure (string const cpu);
    // Gets passed an bitwise OR to decide disasm display options.
    void options (const uint1 opts) { optionlist = opts; }
    void disasm (class hutch_transcribe* insn, uint1 const* buf, uintb bufsize,
                 uintb baseaddr = 0x00000000, ssize_t ninsn = -1);
    // TODO Learn how to use procedures in emulate.hh + pcoderaw.hh
    [[depreciated("Should use PcodeOpRaw")]]
    vector<struct Pcode*>* lift (class hutch_transcribe* insn, uint1 const* buf,
                                 uintb bufsize, uintb baseaddr = 0x00000000,
                                 ssize_t ninsn = -1);
};

class hutch_transcribe {
    friend class hutch;
    DefaultLoadImage* image;
    Sleigh* trans;
    bool isInitialized = false;
};

#endif
