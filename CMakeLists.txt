cmake_minimum_required(VERSION 3.17)
project(python_inject)

set(CMAKE_CXX_STANDARD 14)

include_directories(${CMAKE_SOURCE_DIR})

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

include(cmake/ELFIO.cmake)

add_subdirectory(zero)

add_executable(python_inject main.cpp ptrace/tracee.cpp ptrace/executor.cpp inject/injector.cpp)
target_link_libraries(python_inject zero elfio $<$<BOOL:${STATIC_BUILD}>:-static-pie>)