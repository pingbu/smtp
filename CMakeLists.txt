cmake_minimum_required(VERSION 3.16)
project(smtp)

set(CMAKE_CXX_STANDARD 20)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DDEBUG)
endif()

aux_source_directory(. DIRSRCS)

#include_directories(.)

add_executable(smtp ${DIRSRCS})
target_link_libraries(smtp ssl crypto)
