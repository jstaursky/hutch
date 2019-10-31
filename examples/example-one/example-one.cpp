
/* ###
 * IP: GHIDRA
 * NOTE: mentions GNU libbfd, the hard-coded binary is a toy function that generates primes
 *
 * Modifications:
 * copyright (C) 2019 Joe Staursky, no rights reserved (edits are public domain).
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

// Root include for parsing using SLEIGH
#include "loadimage.hh"
#include "sleigh.hh"
#include "emulate.hh"
#include <iostream>
#include <string>
#include <cstdio>
#include <cstdlib>

size_t getfilesize (FILE* fp)
{
    size_t fsize;
    fseek (fp, 0L, SEEK_END);
    fsize = ftell (fp);
    fseek (fp, 0L, SEEK_SET);
    return fsize;
}

// This is a tiny LoadImage class which feeds the executable bytes to the translator
class MyLoadImage : public LoadImage {
    uintb baseaddr = 0;
    size_t image_size = 0;
    uint8_t* data = NULL;

public:
    MyLoadImage (char const* fname) : LoadImage (fname)
    {
        FILE* file;
        if (!(file = fopen (fname, "rb")))
            puts ("Error in opening file.");
        image_size = getfilesize (file);

        data = new uint8_t[image_size];
        // Fill buf with bytes from file.
        fread (data, sizeof (uint8_t), image_size, file);
        fclose (file);
    }
    inline size_t getImageSize () { return image_size; }

    virtual void loadFill (uint1* ptr, int4 size, const Address& addr);
    virtual string getArchType (void) const { return "myload"; }
    virtual void adjustVma (long adjust) {}
};

// This is the only important method for the LoadImage. It returns bytes from
// the static array depending on the address range requested
void MyLoadImage::loadFill (uint1* ptr, int4 size, const Address& addr)
{
    uintb start = addr.getOffset ();
    uintb max = baseaddr + (image_size - 1);
    for (int4 i = 0; i < size; ++i) { // For every byte requestes
        uintb curoff = start + i; // Calculate offset of byte
        if ((curoff < baseaddr) ||
            (curoff > max)) { // If byte does not fall in window
            ptr[i] = 0; // return 0
            continue;
        }
        uintb diff = curoff - baseaddr;
        ptr[i] = data[(int4)diff]; // Otherwise return data from our window
    }
}



// -------------------------------
//
// These are the classes/routines relevant to doing disassembly

// Here is a simple class for emitting assembly.  In this case, we send the strings straight
// to standard out.
class AssemblyRaw : public AssemblyEmit {
public:
    virtual void dump (const Address& addr, const string& mnem,
                       const string& body)
    {
        addr.printRaw (cout);
        cout << ": " << mnem << ' ' << body << endl;
    }
};

static void dumpAssembly (Translate& trans, uintb start, uintb end)
{ // Print disassembly of binary code
    AssemblyRaw assememit; // Set up the disassembly dumper
    int4 length; // Number of bytes of each machine instruction

    Address addr (trans.getDefaultSpace (),
                  start); // First disassembly address
    Address lastaddr (trans.getDefaultSpace (),
                      end); // Last disassembly address

    while (addr < lastaddr) {
        length = trans.printAssembly (assememit, addr);
        addr = addr + length;
    }
}

// -------------------------------
//
// These are the classes/routines relevant to printing a pcode translation

// Here is a simple class for emitting pcode. We simply dump an appropriate
// string representation straight to standard out.
class PcodeRawOut : public PcodeEmit {
public:
    virtual void dump (const Address& addr, OpCode opc, VarnodeData* outvar,
                       VarnodeData* vars, int4 isize);
};

static void print_vardata (ostream& s, VarnodeData& data)
{
    s << '(' << data.space->getName () << ',';
    data.space->printOffset (s, data.offset);
    s << ',' << dec << data.size << ')';
}

void PcodeRawOut::dump (const Address& addr, OpCode opc, VarnodeData* outvar,
                        VarnodeData* vars, int4 isize)
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

// Dump pcode translation of machine instructions
static void dumpPcode (Translate& trans, uintb start, uintb end)
{
    PcodeRawOut emit; // Set up the pcode dumper
    AssemblyRaw assememit; // Set up the disassembly dumper
    int4 length; // Number of bytes of each machine instruction

    // First address to translate
    Address addr (trans.getDefaultSpace (), start);
    Address lastaddr (trans.getDefaultSpace (), end); // Last address

    while (addr < lastaddr) {
        cout << "--- ";
        trans.printAssembly (assememit, addr);
        length = trans.oneInstruction (emit, addr); // Translate instruction
        addr = addr + length; // Advance to next instruction
    }
}

int main (int argc, char* argv[])
{
    if (argc != 3) {
        cerr << "USAGE:  " << argv[0] << " <file> disassemble" << endl;
        cerr << "USAGE:  " << argv[0] << " <file> pcode" << endl;
        return 2;
    }
    char const* fname (argv[1]);
    string action (argv[2]);

    // Set up the loadimage
    MyLoadImage loader (fname);

    // Set up the context object
    ContextInternal context;

    // Set up the assembler/pcode-translator
    string sleighfilename = "../../processors/x86/languages/x86.sla";
    Sleigh trans (&loader, &context);

    // Read sleigh file into DOM
    DocumentStorage docstorage;
    Element* sleighroot = docstorage.openDocument (sleighfilename)->getRoot ();
    docstorage.registerTag (sleighroot);
    trans.initialize (docstorage); // Initialize the translator

    // Now that context symbol names are loaded by the translator
    // we can set the default context

    context.setVariableDefault ("addrsize", 1); // Address size is 32-bit
    context.setVariableDefault ("opsize", 1); // Operand size is 32-bit

    if (action == "disassemble")
        dumpAssembly (trans, 0, loader.getImageSize());
    else if (action == "pcode")
        dumpPcode(trans, 0, loader.getImageSize());
    else
        cerr << "Unknown action: " + action << endl;
}
