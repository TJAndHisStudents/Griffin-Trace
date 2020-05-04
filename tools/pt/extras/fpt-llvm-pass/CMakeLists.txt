cmake_minimum_required(VERSION 2.8.12)

find_package(LLVM REQUIRED CONFIG)

include_directories(${LLVM_INCLUDE_DIRS})

add_definitions(-std=c++11 -g)
add_definitions(${LLVM_DEFINITIONS})

if (NOT LLVM_ENABLE_RTTI)
    message(STATUS "LLVM was built without RTTI, so we must disable it too for linking to work properly")
    add_definitions(-fno-rtti)
endif()

add_library(fpt MODULE fpt.cpp)
