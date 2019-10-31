# byte-slide
Separate the sleigh compiler from Ghidra, rewritten Makefile.

I had trouble with the existing Makefile in the repository and after debugging
it, decided there are probably others like myself. So I cleaned(i.e., rewrote) it, and built
(IMO) a better folder structure for use as a library. This is a work in progress.

# WINDOWS BUILDING
Assuming your running under an mingw-w64-x86_64 style environment, after installing `bison` and `flex` (and `g++` + `binutils` + etc.), 
execute `make sleigh-compile`, 

This will get you 95% of the way but then gets trapped in an infinite loop.
Hit Ctrl+C to interupt the loop and finish the build with

`g++ -D__linux__ -D__x86_64__ -Wno-sign-compare -Isrc -Iinclude src/build/*.cc -o sleigh-compile`

(this forces `types.h` file in `src` directory to recognize your system as a linux system and define types such as `uintb`, `uint4`, etc. needed by the build).

This should result in the executable `sleigh-compile`, which you can then run `./sleigh-compile.exe -a processors/x86/` to generate the `x86.sla` file needed in order to use the rest of the sleigh library (TBD when I will be able to do more on this).
