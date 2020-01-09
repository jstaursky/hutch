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

// TODO FIX C FFI.
// *****************************************************************************
// Initial implementation of FFI
// extern "C" {
const uint1 OPT_IN_DISP_ADDR = (1 << 0);
const uint1 OPT_IN_PCODE = (1 << 1);
const uint1 OPT_IN_ASM = (1 << 2);

const uint1 OPT_OUT_DISP_ADDR = 0, OPT_OUT_PCODE = 0, OPT_OUT_ASM = 0;

//     hutch* hutch_new (int4 cpu)
//     {
//         return new hutch (cpu);
//     }
//     void hutch_configure (hutch* hutch_h, char const* cpu)
//     {
//         hutch_h->configure (cpu);
//     }
//     void hutch_options (hutch* hutch_h, unsigned char const opt)
//     {
//         hutch_h->options (opt);
//     }
//     void hutch_disasm (hutch* hutch_h, unsigned char const* buf,
//                        unsigned long bufsize)
//     {
//         hutch_h->disasm (buf, bufsize);
//     }
// } // end extern "C"

// *****************************************************************************
//
// * file local convienience function(s).
//
static bool print_vardata (ostream& s, VarnodeData* data)
{
    if (data == (VarnodeData*)0)
        return false;

    const Translate* trans = data->space->getTrans ();

    s << '(' << data->space->getName () << ',';
    if (data->space->getName () == "register") {
        s << trans->getRegisterName (data->space, data->offset, data->size);
    } else {
        data->space->printOffset (s, data->offset);
    }

    s << ',' << dec << data->size << ')';

    return true;
}

static optional<Hutch_Data>
_expand_insn (Hutch* handle, Hutch_Insn* emit, uint1* code, uintb bufsize,
             bool (*manip) (PcodeData&, AssemblyString))
{
    // Remaining buffer size.
    static uintb rsize = (code == nullptr) ? rsize : bufsize;

    if (rsize == 0)
        return nullopt;         // Have gone through the whole buffer.

    if (code != nullptr) {
        // Need to test whether rpcodes has already been populated.
        if (!emit->rpcodes.empty()) {
            for (auto [addr, pcode] : emit->rpcodes) {
                if (pcode.outvar != nullptr)
                    delete pcode.outvar;
                if (pcode.invar != nullptr)
                    delete[] pcode.invar;
            }
            emit->rpcodes.clear ();
        }

        if (emit->loader != nullptr)
            delete emit->loader;
        if (emit->translate != nullptr)
            delete emit->translate;

        // Start Fresh.
        emit->insn_docstorage.registerTag (
            emit->insn_docstorage.openDocument (handle->docname)->getRoot ());
        emit->loader = new DefaultLoadImage ((uintb)0x00, code, bufsize);
        emit->translate = new Sleigh (emit->loader, &emit->insn_context);

        emit->translate->initialize (emit->insn_docstorage);

        for (auto [opt, setting] : handle->cpu_context)
            emit->insn_context.setVariableDefault (opt, setting);

    }
    Address offset (emit->translate->getDefaultSpace (), (uintb)(bufsize - rsize));
    // Setup complete.

    Hutch_Data result;


    // Begin translating (populate emit->rpcodes via
    // hutch_insn::dump()).
    auto len = emit->translate->oneInstruction (*emit, offset);
    // Get the asm statement as well;
    hutch_asm assem;
    emit->translate->printAssembly(assem, offset);

    vector<PcodeData> pcodes;
    for (auto [addr, pc] : emit->rpcodes) {
        // Only interested in the pcodes relevant to the insn found at current
        // offset.
        if (addr < offset)
            continue;
        // Option to manip results before returning. Convention is that the
        // function passed to manip returns true when it is desirable to pass
        // whatever manipulations that took place inside *manip onto result; and
        // return false when we would like to prevent pc from being passed onto
        // result. Thus you can define a function in terms of _expand_insn()
        // that has complete control over the number of pcode insns returned per
        // asm instruction as well as control over each pcode instructions
        // opcode, output varnode, and input varnodes.
        if ((*manip)(pc, assem.asm_stmt))
            pcodes.push_back (pc);
    }

    result.asm_stmt = assem.asm_stmt;
    result.pcodes = pcodes;

    rsize -= len;

    return result;
}
//
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

string DefaultLoadImage::getArchType (void) const
{
    return "DefaultLoadImage";
}

void DefaultLoadImage::adjustVma (long adjust)
{
    // TODO
}
//
// * PcodeRawOut
//
void PcodeRawOut::dump (Address const& addr, OpCode opc,
                                VarnodeData* outvar, VarnodeData* vars,
                                int4 isize)
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
//
// * AssemblyRaw
//
void AssemblyRaw::dump (const Address& addr, const string& mnem,
                                const string& body)
{
    cout << mnem << ' ' << body << endl;
}
//
// * hutch
//
void Hutch::preconfigure (string const cpu, int4 arch)
{
    this->docname = cpu;
    Element* ast_root = docstorage.openDocument (this->docname)->getRoot ();
    docstorage.registerTag (ast_root);

    setArchContextInfo (arch);
}

void Hutch::setArchContextInfo (int4 cpu)
{
    switch (cpu) {
    case IA32:
        cpu_context = { { "addrsize", 1 }, { "opsize", 1 } };
        break;
    default:
        // IA32 is default.
        cpu_context = { { "addrsize", 1 }, { "opsize", 1 } };
        break;
    }
}

void Hutch::options (const uint1 opts)
{
    optionlist = opts;
}

void Hutch::initialize (const uint1* buf, uintb bufsize, uintb begaddr)
{
    if (this->isInitialized) {
        delete this->image;
        delete this->trans;
    }
    this->image = new DefaultLoadImage (begaddr, buf, bufsize);
    this->trans = new Sleigh (this->image, &this->context);
    this->trans->initialize (this->docstorage);

    for (auto [option, setting] : this->cpu_context)
        this->context.setVariableDefault (option, setting);

    this->isInitialized = true;
}

void Hutch::disasm (DisasmUnit unit, uintb offset, uintb amount)
{
    PcodeRawOut pcodeemit;
    AssemblyRaw asmemit;

    uintb baseaddr = this->image->getBaseAddr ();

    Address addr (this->trans->getDefaultSpace (), baseaddr);
    Address lastaddr (this->trans->getDefaultSpace (),
                      baseaddr + this->image->getImageSize ());

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

    // Set up default options if user has not;
    optionlist =
        (optionlist == -1) ? OPT_IN_ASM | OPT_IN_DISP_ADDR : optionlist;

    for (auto i = 0, len = 0; i < amount && addr < lastaddr;
         i += (unit == UNIT_BYTE) ? len : 1, addr = addr + len) {
        // Print hex Address?
        if (optionlist & OPT_IN_DISP_ADDR) {
            cout << "--- ";
            addr.printRaw (cout);
            cout << ":";
        }
        // Print assembly?
        if (optionlist & OPT_IN_ASM) {
            len = this->trans->printAssembly (asmemit, addr);
        }
        // Print ir?
        if (optionlist & OPT_IN_PCODE) {
            len = this->trans->oneInstruction (pcodeemit, addr);
        }
    }
}
//
// * hutch_insn
//
Hutch_Insn::~Hutch_Insn (void)
{
    for (auto [addr, pdata] : rpcodes) {
        if (pdata.outvar != nullptr)
            delete pdata.outvar;
        if (pdata.invar != nullptr)
            delete[] pdata.invar;
    }
}

void Hutch_Insn::dump (Address const& addr, OpCode opc, VarnodeData* outvar,
                       VarnodeData* vars, int4 isize)
{
    PcodeData node;
    node.opc = opc;
    node.outvar = new VarnodeData;

    if (outvar != (VarnodeData*)0) {
        *node.outvar = *outvar;
    } else {
        node.outvar = (VarnodeData*)0;
    }
    node.isize = isize;
    node.invar = new VarnodeData[isize];
    for (auto i = 0; i != isize; ++i) {
        node.invar[i] = vars[i];
    }
    rpcodes.insert ({ addr, node });
}

optional<Hutch_Data>
Hutch_Insn::expand_insn (Hutch* handle, uint1* code, uintb bufsize)
{
    return _expand_insn(handle, this, code, bufsize, [](PcodeData&, AssemblyString) { return true; });
}

// optional<vector<PcodeData>>
// hutch_insn::expand_to_pcode (hutch* handle, uint1* code, uintb bufsize)
// {
//     auto result = _expand_insnn (handle, this, code, bufsize,
//                             [](PcodeData&, AssemblyString) { return true; });

//     if (result)
//         return result->second;
//     else
//         return nullopt;
// }

// optional<AssemblyString>
// hutch_insn::disasm (hutch* handle, uint1* code, uintb bufsize)
// {
//     auto result = expand_insn (handle, this, code, bufsize,
//                                [](PcodeData&, AssemblyString) { return false; });
//     if (result)
//         return result->first;
//     else
//         return nullopt;
// }

//
// * regular functions.
//
void hutch_print_pcodedata (ostream& s, PcodeData data)
{

    if (print_vardata(s, data.outvar)) {
        s << " = ";
    }
    s << get_opname(data.opc);
    for (auto i = 0; i < data.isize; ++i) {
        s << " ";
        print_vardata(s, &data.invar[i]);
    }
    s << endl;
}

