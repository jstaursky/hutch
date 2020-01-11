#include <iostream>
#include "hutch.hpp"

uint1 code[] = { 0xeb, 0x14, 0x59, 0x31, 0xc0, 0x31, 0xdb, 0x31, 0xd2, 0xb0,
                 0x04, 0xb3, 0x01, 0xb2, 0x0c, 0xcd, 0x80, 0x31, 0xc0, 0x40,
                 0xcd, 0x80, 0xe8, 0xe7, 0xff, 0xff, 0xff, 0x0a, 0x48, 0x65,
                 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64 };
// 39 bytes.

class sys_write_callback : public BreakCallBack {
public:
    virtual bool addressCallback(const Address &addr);
};

bool sys_write_callback::addressCallback(const Address &addr)

{
    cout << "running sys write\n";
    MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();

    uint4 eax = mem->getValue("EAX");
    uint4 ebx = mem->getValue("EBX");
    uint4 ecx = mem->getValue("ECX");
    uint4 edx = mem->getValue("EDX");

    cout << hex << eax << "\t <- eax" << endl;
    cout << hex << ebx << "\t <- ebx" << endl;
    cout << hex << ecx << "\t <- ecx" << endl;
    cout << hex << edx << "\t <- edx" << endl;

    AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");

    if (eax != 0x04)
        return false;

    uint1* buf = new uint1[edx + 1];

    mem->getChunk(buf, ram, ecx, edx);
    buf[edx] = '\0';

    cout << buf << endl;

    delete[] buf;

    uintb eip = emulate->getExecuteAddress().getOffset();
    // INSN "int 0x80" = cd80 (i.e., 2 bytes long).
    uint4 returnaddr = eip + 2;
    emulate->setExecuteAddress(Address(ram,returnaddr));

    return true;			// This replaces the indicated instruction
}

// A callback that terminates the emulation
class sys_exit_callback: public BreakCallBack {
public:
    virtual bool addressCallback(const Address &addr);
};

bool sys_exit_callback::addressCallback(const Address &addr)

{
    // Kinda cheat on this one but I already know it calls sys_exit correctly.
    emulate->setHalt(true);
    return true;
}

int main(int argc, char *argv[])
{
    Hutch hutch_h;
    Hutch_Emulate hutch_emu;

    uintb entrypoint = 0x1000;
    hutch_h.preconfigure("../../processors/x86/languages/x86.sla", IA32);
    hutch_h.initialize(code, sizeof (code), entrypoint);

    hutch_emu.preconfigure(&hutch_h);
    hutch_emu.set_execution_address(entrypoint);
    hutch_emu.set_emulater_value("ESP", 0x7fffffff);

    sys_write_callback systemwritecallback;
    sys_exit_callback systemexitcallback;

    hutch_emu.add_address_callback(0x100f, &systemwritecallback);
    hutch_emu.add_address_callback(0x1014, &systemexitcallback);

    hutch_emu.emulate();

    return 0;
}
