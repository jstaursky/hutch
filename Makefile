CC       = gcc
CXX      = g++
CXXFLAGS = -O2  -Wall  -Wno-sign-compare

PARSER_TOOLS	        = parser-tools
BUILD_DIR		= src/build
PUB_INCLUDE_DIR = include
SRC_DIR			= src
BIN_DIR			= bin

VPATH = parser-tools include src src/build

# Core source files used in all projects
CORE := address  float  globalcontext  opcodes  pcoderaw  space  translate  xml

# Files used for any project that use the sleigh decoder
SLEIGH := context  filemanage  pcodecompile    pcodeparse   semantics   \
          sleigh   sleighbase  slghpatexpress  slghpattern  slghsymbol

# Files specific to the sleigh compiler
SLEIGH_CMPLR := slgh_compile  slghparse  slghscan


# Parsing + Lexing
LEX  = flex
YACC = bison

PARSING_FILES = xml  slghparse  pcodeparse  slghscan

# PARSING ######################################################################
xml.cc:  xml.y
	$(YACC) -p xml -o $(SRC_DIR)/build/$@ $<

slghparse.cc: slghparse.y
	$(YACC) -d -o $(SRC_DIR)/build/$@ $<
	mv $(SRC_DIR)/build/slghparse.hh $(SRC_DIR)/build/slghparse.tab.hh

pcodeparse.cc: pcodeparse.y
	$(YACC) -p pcode -o $(SRC_DIR)/build/$@ $<

# LEXING #######################################################################
slghscan.cc:  slghscan.l
	$(LEX) -o $(SRC_DIR)/build/$@ $<

# BUILDING SLEIGH COMPILER #####################################################

# Collect all the requisite .cc files, less the parsing ones as those are
# handled separately.
SLGH_COMP_COLLATE := $(addsuffix .cc,        \
	$(addprefix $(BUILD_DIR)/,   			 \
	$(filter-out $(PARSING_FILES), $(CORE) $(SLEIGH) $(SLEIGH_CMPLR))))

$(SLGH_COMP_COLLATE): | $(BUILD_DIR) $(addsuffix .cc, $(PARSING_FILES))
# Do not add actions to $(SLGH_COMP_COLLATE) targer. 
# Not even a printf--messes up build.

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Begin collating the relevant .cc files into the build directory.
$(BUILD_DIR)/%.cc: %.cc
	cp $< $@


sleigh-compile: $(SLGH_COMP_COLLATE)
	$(CXX) $(CXXFLAGS) -I$(PUB_INCLUDE_DIR)/ -I$(SRC_DIR)/ \
	$(BUILD_DIR)/*.cc -o $(BIN_DIR)/$@

