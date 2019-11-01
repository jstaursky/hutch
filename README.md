# hutch (a sleigh library derivative)
Separate the sleigh compiler from Ghidra, a rewritten Makefile.

I had trouble with the existing Makefile in the Ghidra repository and so after some trial and error to get a successful build, I decided to rewrite it. So I rewrote the Makefile, and built (IMO) a better folder structure for using sleigh as a library.

The intent is not to be in 1-1 sync with the sleigh code-base found in ghidra, I will be making my own modifications and eventually the two codebases will be incompatible--Hence the change in name (as well as to avoid potiential trademark issues). That said, until I start implementing my own changes, this repo will try and stay up to date. I am still analyzing the codebase.

# BUILDING
To build the sleigh compiler type: `make sleigh-compile`
Follow this up with:

`./bin/sleigh-compile -a processors/x86/languages`

which compiles `x86.sla`.

Next type: `make libsla.a` to build the library.

To see a complete example of what you can do with this library, enter `examples/example-one` directory.

# WINDOWS BUILDING
Assuming your running under an mingw-w64-x86_64 style environment, after installing `bison` and `flex` (and `g++` + `binutils` + etc.), 
execute `make sleigh-compile CXX='g++ -D_WINDOWS '`, 

the rest of the instructions are same as above but always append the `make` commands with `CXX='g++ -D_WINDOWS '` otherwise you will run into errors.
