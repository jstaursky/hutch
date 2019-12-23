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

#include "loadimage.hh"
#include "sleigh.hh"
#include <iostream>
#include <string>

#include "hutch-disasm.hpp"

// x86 insns
//
// push ebp            \x55
// move ebp, esp       \x89\xe5
// mov eax, 0x12345678 \xb8\x78\x56\x34\x12
//
static uint1 code[] = { 0x55, 0x89, 0xe5, 0xb8, 0x78, 0x56, 0x34, 0x12 };

int main(int argc, char *argv[])
{
    hutch_Disasm hutch_h;
    // x86 only atm, but this should be easy enough to change. Will update for
    // other arches eventually.
    hutch_h.configure("../../processors/x86/languages/x86.sla");

    // Can display address info, pcode, assembly alone or in combination with
    // each other. Omission of hutch_h.options() will display a default of asm +
    // address info.
    hutch_h.options (OPT_IN_DISP_ADDR | OPT_IN_PCODE | OPT_IN_ASM);

    // Below relies on default args, full prototype of hutch_h.disasm is;
    // void hutch_Disasm::disasm (uint1 const* buf, uintb bufsize, uintb start,
    //                            ssize_t ninsn)

    hutch_h.disasm (code, sizeof (code));

    return 0;
}
