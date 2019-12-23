#include "loadimage.hh"
#include "sleigh.hh"

#include <fstream>
#include <iostream>

constexpr uint1 OPT_IN_DISP_ADDR = (1<<0);
constexpr uint1 OPT_IN_PCODE     = (1<<1);
constexpr uint1 OPT_IN_ASM       = (1<<2);

constexpr uint1 OPT_OUT_DISP_ADDR = 0, OPT_OUT_PCODE = 0, OPT_OUT_ASM = 0;

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

    virtual void dump (Address const& addr, OpCode opc, VarnodeData* outvar,
                       VarnodeData* vars, int4 isize) override
    {
        if (outvar != (VarnodeData*)0) {
            print_vardata (cout, *outvar);
            cout << " = ";
        }
        cout << get_opname (opc);
        // Possibly check for a code reference or a space reference
        for (int4 i = 0; i < isize; ++i) {
            cout << ' ';
            print_vardata (cout, vars[i]);
        }
        cout << endl;
    }
};

class hutch_Disasm;
class AssemblyRaw : public AssemblyEmit {
public:
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
    void disasm (uint1 const* buf, uintb bufsize, uintb start = 0x00000000,
                 ssize_t ninsn = -1);
    void options (const uint1 opts) { optionlist = opts; }
};
