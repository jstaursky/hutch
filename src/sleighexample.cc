/* ###
 * IP: GHIDRA
 * NOTE: mentions GNU libbfd, the hard-coded binary is a toy function that generates primes
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Dump the raw pcode instructions

// Root include for parsing using SLEIGH
#include "loadimage.hh"
#include "sleigh.hh"
#include "emulate.hh"
#include <iostream>

// These are the bytes for an example 8085 binary
// These bytes are loaded at address 0x0000

static uint1 myprog[] = { 0xC3, 0x03, 0x00, 0x00, 0x3E, 0x42, 0x4F, 0x3E, 0x19, 0x47, 0x76 };
// Size of 9 bytes

// This is the example program.
//   - Moves 0x42 into register A
//   - Moves contents of register A into register C
//   - Moves 0x19 into register A
//   - Moves contents of register A into register B
// ADDR                                 Hex
// 0x0000           JMP START           0xC3
// 0x0001                               0x03
// 0x0002                               0x00
// 0x0003    START: NOP                 0x00
// 0x0004           MVI A, 0X42         0x3E
// 0x0005                               0x42
// 0x0006           MOV C,A             0x4F
// 0x0007           MVI A, 0X19         0x3E
// 0x0008                               0x19
// 0x0009           MOV B,A             0x47
// 0x000A           HLT                 0x76

// *not that for GNUSim8085 hex numbers must be entered as 42h and 19h.

// This is a tiny LoadImage class which feeds the executable bytes to the translator
class MyLoadImage : public LoadImage
{
    uintb baseaddr;
    int4 length;
    uint1* data;
public:
    MyLoadImage (uintb ad, uint1* ptr, int4 sz) : LoadImage ("nofile") { baseaddr = ad; data = ptr; length = sz; }
    virtual void loadFill (uint1* ptr, int4 size, const Address& addr);
    virtual string getArchType (void) const { return "myload"; }
    virtual void adjustVma (long adjust) { }
};

// This is the only important method for the LoadImage. It returns bytes from the static array
// depending on the address range requested
void MyLoadImage::loadFill (uint1* ptr, int4 size, const Address& addr)

{
    uintb start = addr.getOffset();
    uintb max = baseaddr + (length - 1);
    for (int4 i = 0; i < size; ++i) {                // For every byte requestes
        uintb curoff = start + i;                    // Calculate offset of byte
        if ((curoff < baseaddr) || (curoff > max)) { // If byte does not fall in window
            ptr[i] = 0;		// return 0
            continue;
        }
        uintb diff = curoff - baseaddr;
        ptr[i] = data[ (int4)diff];	// Otherwise return data from our window
    }
}

// -------------------------------
//
// These are the classes/routines relevant to doing disassembly

// Here is a simple class for emitting assembly.  In this case, we send the strings straight
// to standard out.
class AssemblyRaw : public AssemblyEmit
{
public:
    virtual void dump (const Address& addr, const string& mnem, const string& body)
    {
        addr.printRaw (cout);
        cout << ": " << mnem << ' ' << body << endl;
    }
};

static void dumpAssembly (Translate& trans)

{
    // Print disassembly of binary code
    AssemblyRaw assememit;	// Set up the disassembly dumper
    int4 length;			// Number of bytes of each machine instruction

    Address addr (trans.getDefaultCodeSpace(), 0x0000);     // First disassembly address
    Address lastaddr (trans.getDefaultCodeSpace(), 0x000A); // Last disassembly address

    while (addr < lastaddr) {
        length = trans.printAssembly (assememit, addr);
        addr = addr + length;
    }
}

// -------------------------------
//
// These are the classes/routines relevant to printing a pcode translation

// Here is a simple class for emitting pcode. We simply dump an appropriate string representation
// straight to standard out.
class PcodeRawOut : public PcodeEmit
{
public:
    virtual void dump (const Address& addr, OpCode opc, VarnodeData* outvar, VarnodeData* vars, int4 isize);
};

static void print_vardata (ostream& s, VarnodeData& data)

{
    s << '(' << data.space->getName() << ',';

    const Translate* trans = data.space->getTrans ();

    if (data.space->getName () == "register") {
        s << trans->getRegisterName (data.space, data.offset, data.size);
    } else {
        data.space->printOffset (s, data.offset);
    }
    s << ',' << dec << data.size << ')';
}

void PcodeRawOut::dump (const Address& addr, OpCode opc, VarnodeData* outvar, VarnodeData* vars, int4 isize)

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

static void dumpPcode (Translate& trans)

{
    // Dump pcode translation of machine instructions
    PcodeRawOut emit;		// Set up the pcode dumper
    AssemblyRaw assememit;	// Set up the disassembly dumper
    int4 length;			// Number of bytes of each machine instruction

    Address addr (trans.getDefaultCodeSpace(), 0x0000); // First address to translate
    Address lastaddr (trans.getDefaultCodeSpace(), 0x000A); // Last address

    while (addr < lastaddr) {
        cout << "--- ";
        trans.printAssembly (assememit, addr);
        length = trans.oneInstruction (emit, addr); // Translate instruction
        addr = addr + length;		// Advance to next instruction
    }
}

int main (int argc, char** argv)

{
    if (argc != 2) {
        cerr << "USAGE:  " << argv[0] << " disassemble" << endl;
        cerr << "        " << argv[0] << " pcode" << endl;
        return 2;
    }
    string action (argv[1]);

    // Set up the loadimage
    MyLoadImage loader (0x0000, myprog, 9);

    // Set up the context object
    ContextInternal context;

    // Set up the assembler/pcode-translator
    string sleighfilename = "../processors/8085/8085.sla";
    Sleigh trans (&loader, &context);

    // Read sleigh file into DOM
    DocumentStorage docstorage;
    Element* sleighroot = docstorage.openDocument (sleighfilename)->getRoot();
    docstorage.registerTag (sleighroot);
    trans.initialize (docstorage); // Initialize the translator

    // Now context symbol names are loaded by the translator

    if (action == "disassemble")
        dumpAssembly (trans);
    else if (action == "pcode")
        dumpPcode (trans);
    else
        cerr << "Unknown action: " + action << endl;
}

// This is the example program as written in GNUSim8085
//
// ;<example>
// jmp start

// start: nop
// mvi a,42h
//     mov c,a
//     mvi a,19h
//     mov b,a

//     hlt
