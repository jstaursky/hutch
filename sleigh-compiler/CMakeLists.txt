cmake_minimum_required(VERSION 3.13)

project(pcodecodeparse CXX)

find_package(BISON REQUIRED)

# configure build for generating pcodeparse.cc
BISON_TARGET(gen_pcodecodeparse
  pcodeparse.y
  pcodeparse.cc
  COMPILE_FLAGS "-p pcode -o ${BISON_gen_pcodecodeparse_OUTPUT_SOURCE}"
  )

# MIGHT BE NEEDED LATER
#set_source_files_properties(${BISON_parser_OUTPUT_SOURCE} PROPERTIES GENERATED TRUE)


add_custom_target(
  pcodecodeparse
  ALL echo "generate stuff"
  DEPENDS ${BISON_generate_pcodecodeparse_OUTPUT_SOURCE}
  )


