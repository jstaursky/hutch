VPATH = parser-tools include src src/build processors/x86/languages processors/8085/languages

CC       = gcc
CXX      = g++
CXXFLAGS = -O2  -Wall  -Wno-sign-compare

PARSER_TOOLS	 = parser-tools
BUILD_DIR	 = src/build
PUB_INCLUDE_DIR = include # Plan to eventually separate headers into public and
				  		  # private headers. Where private headers reside in src
SRC_DIR		 = src
LIB_DIR		 = lib
BIN_DIR		 = bin


# Core source files used in all projects
CORE := address  float  globalcontext  opcodes  pcoderaw  space  translate  xml

# Files used for any project that use the sleigh decoder
SLEIGH := context  filemanage  pcodecompile    pcodeparse   semantics   \
          sleigh   sleighbase  slghpatexpress  slghpattern  slghsymbol


# BUILD EVERYTHING #############################################################
all: sleigh-compile x86.sla 8085.sla libsla.a
	$(MAKE) -C examples/example-one
	$(MAKE) -C examples/example-two


x86.sla: x86.slaspec
	./bin/sleigh-compile -a processors/x86/languages

8085.sla: 8085.slaspec
	./bin/sleigh-compile -a processors/8085/languages

# Parsing + Lexing #############################################################
LEX  = flex
YACC = bison

PARSING_FILES = xml  slghparse  pcodeparse  slghscan

# PARSING ######################################################################
xml.o: xml.cc
	$(CXX) $(CXXFLAGS) -I$(PUB_INCLUDE_DIR) -c $(BUILD_DIR)/$< -o $(BUILD_DIR)/$@
xml.cc: xml.y
	$(YACC) -p xml -o $(BUILD_DIR)/$@ $<

slghparse.o: slghparse.cc
	$(CXX) $(CXXFLAGS) -I$(PUB_INCLUDE_DIR) -c $(BUILD_DIR)/$< -o $(BUILD_DIR)/$@
slghparse.cc: slghparse.y
	$(YACC) -d -o $(BUILD_DIR)/$@ $<
	mv $(BUILD_DIR)/slghparse.hh $(BUILD_DIR)/slghparse.tab.hh

pcodeparse.o: pcodeparse.cc
	$(CXX) $(CXXFLAGS) -I$(PUB_INCLUDE_DIR) -c $(BUILD_DIR)/$< -o $(BUILD_DIR)/$@
pcodeparse.cc: pcodeparse.y
	$(YACC) -p pcode -o $(BUILD_DIR)/$@ $<


# LEXING #######################################################################
slghscan.o: slghscan.cc
	$(CXX) $(CXXFLAGS) -I$(PUB_INCLUDE_DIR) -c $(BUILD_DIR)/$< -o $(BUILD_DIR)/$@
slghscan.cc: slghscan.l
	$(LEX) -o $(BUILD_DIR)/$@ $<


# RECIPE SHARED ACROSS TARGETS #################################################
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: %.cc
	$(CXX) $(CXXFLAGS) -I$(PUB_INCLUDE_DIR) -I$(SRC_DIR) -c $< -o $@


# BUILD SLEIGH COMPILER RECIPE #################################################
# Files specific to the sleigh compiler
SLEIGH_COMP := slgh_compile  slghparse  slghscan

# Collect all the requisite .o files, less the parsing ones. Those are handled
# separately.
SLEIGH_COMP_OBJS := $(addsuffix .o, $(addprefix $(BUILD_DIR)/,       \
	$(filter-out $(PARSING_FILES), $(CORE) $(SLEIGH) $(SLEIGH_COMP))))

$(SLEIGH_COMP_OBJS): | $(BUILD_DIR) $(addsuffix .o, $(PARSING_FILES))
# No actions. Messes up build process.


sleigh-compile: $(SLEIGH_COMP_OBJS)
	$(CXX) $(CXXFLAGS) -I$(BUILD_DIR) $(BUILD_DIR)/*.o -o $(BIN_DIR)/$@


# BUILD LIBSLA.A RECIPE ########################################################

LIBSLA := loadimage emulate  memstate  opbehavior  slghparse  slghscan

LIBSLA_OBJS := $(addsuffix .o, $(addprefix $(BUILD_DIR)/,       \
	$(filter-out $(PARSING_FILES), $(CORE) $(SLEIGH) $(LIBSLA))))

$(LIBSLA_OBJS): | $(BUILD_DIR) $(addsuffix .o, $(PARSING_FILES))
# No actions


# Create static library.
libsla.a: $(LIBSLA_OBJS)
	rm -rf $(LIB_DIR)/$@
	ar rcs $(LIB_DIR)/$@ $^ $(addprefix $(BUILD_DIR)/, xml.o pcodeparse.o)


# CLEANUP ######################################################################
clean:
	rm -rf src/build
	rm -f bin/sleigh-compile
	rm -f lib/libsla.a
	rm -f processors/x86/languages/x86.sla
	rm -f processors/8085/languages/8085.sla
	rm -f examples/example-one/example-one
	rm -f examples/example-one/*.o
	rm -f examples/example-two/example-two
	rm -f examples/example-two/*.o


# Useful for debugging. To find out value of variable, type 'make
# print-VARIABLE'
print-%  : ; @echo $* = $($*)


