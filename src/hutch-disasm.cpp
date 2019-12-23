#include "hutch-disasm.hpp"

void hutch_Disasm::configure (string const cpu)
{
    Element* ast_root = docstorage.openDocument (cpu)->getRoot ();
    docstorage.registerTag (ast_root);
}

void hutch_Disasm::disasm (uint1 const* buf, uintb bufsize, uintb start,
                           ssize_t ninsn)
{
    // NOTE start = 0x1000 , ninsn = -1 is default
    DefaultLoadImage loader (start, buf, bufsize);

    Sleigh trans (&loader, &context);
    trans.initialize (docstorage);
    // TODO some cpu's do not have setup beyond ContextInternal (e.g., 8085) so
    // this needs be optional / have ability to be passed specific options.
    context.setVariableDefault ("addrsize", 1);
    context.setVariableDefault ("opsize", 1);

    PcodeRawOut pcodeemit;
    AssemblyRaw asmemit;
    int4 len;

    Address addr (trans.getDefaultSpace (), start);
    Address lastaddr (trans.getDefaultSpace (), start + bufsize);

    // Set up default options if user has not;
    optionlist = (optionlist == -1) ? OPT_IN_ASM | OPT_IN_DISP_ADDR : optionlist;
    // Set up default number of insns to count if user has not.
    ninsn = (ninsn == -1) ? bufsize : ninsn;

    // Assume ninsn was given the default -1 value. The above reassigns it to
    // the size of the buffer, consequently since the smallest insn len is 1,
    // The addr < lastaddr condition will trigger before the i < ninsn
    // condition. Conversly, if ninsn != -1 then the 1 < ninsn will trigger
    // before the addr < lastaddr condition (if used correctly) because we are
    // counting less instructions than the total that make up the buffer.
    // If ninsn is defined by user to be greator than the number of insns in
    // buffer, then addr < lastaddr will trigger first.
    for (auto i = 0; i < ninsn && addr < lastaddr; ++i, addr = addr + len) {
        // Print hex Address?
        if (optionlist & OPT_IN_DISP_ADDR) {
            cout << "--- ";
            addr.printRaw(cout);
            cout << ":";
        }
        // Print assembly?
        if (optionlist & OPT_IN_ASM) {
            len = trans.printAssembly (asmemit, addr);
        }
        // Print pcode?
        if (optionlist & OPT_IN_PCODE) {
            len = trans.oneInstruction (pcodeemit, addr);
        }

    }
}
