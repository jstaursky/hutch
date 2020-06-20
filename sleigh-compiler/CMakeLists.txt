cmake_minimum_required(VERSION 3.10)

project(sleigh_compile CXX)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(BISON REQUIRED)
find_package(FLEX REQUIRED)

# Create target for pcodeparse
ADD_CUSTOM_TARGET(  pcodeparse  echo "Creating pcodeparse.cc" DEPENDS pcodeparse.cc)
ADD_CUSTOM_COMMAND(             OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/pcodeparse.cc
                                COMMAND ${BISON_EXECUTABLE}
                                ARGS -y ${CMAKE_CURRENT_SOURCE_DIR}/../parser-tools/pcodeparse.y -p pcode -o ${CMAKE_CURRENT_BINARY_DIR}/pcodeparse.cc
  )

# Create target for xml
ADD_CUSTOM_TARGET(  xml  echo "Creating xml.cc" DEPENDS xml.cc)
ADD_CUSTOM_COMMAND(      OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/xml.cc
                         COMMAND ${BISON_EXECUTABLE}
                         ARGS -y ${CMAKE_CURRENT_SOURCE_DIR}/../parser-tools/xml.y -p xml -o ${CMAKE_CURRENT_BINARY_DIR}/xml.cc
  )

# configure build for generating slghparse.cc
BISON_TARGET( slghparse  ${CMAKE_CURRENT_SOURCE_DIR}/../parser-tools/slghparse.y ${CMAKE_CURRENT_BINARY_DIR}/slghparse.cc
                         DEFINES_FILE ${CMAKE_CURRENT_BINARY_DIR}/slghparse.tab.hh
  )

FLEX_TARGET( slghscan  ${CMAKE_CURRENT_SOURCE_DIR}/../parser-tools/slghscan.l
                       ${CMAKE_CURRENT_BINARY_DIR}/slghscan.cc
  )

ADD_FLEX_BISON_DEPENDENCY(slghscan slghparse)


file(GLOB SOURCES "*.cc")
file(GLOB HEADERS "*.hh")


add_executable (sleighcompiler
  ${SOURCES}
  pcodeparse.cc
  slghscan.cc
  slghparse.cc
  xml.cc
  ${HEADERS}
  )

add_dependencies(sleighcompiler pcodeparse xml)
# So CMake can find pcodeparse.hh, etc.
target_include_directories(sleighcompiler PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(sleighcompiler PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../parser-tools)

