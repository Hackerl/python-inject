cmake_minimum_required(VERSION 3.17)
project(python_inject)

set(CMAKE_CXX_STANDARD 14)

include_directories(${CMAKE_SOURCE_DIR})

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

include(FetchContent)

FetchContent_Declare(
        ELFIO
        GIT_REPOSITORY    https://github.com/serge1/ELFIO
        GIT_TAG           Release_3.8
)

FetchContent_MakeAvailable(ELFIO)

FetchContent_Declare(
        zero
        GIT_REPOSITORY https://github.com/Hackerl/zero
        GIT_TAG master
)

FetchContent_MakeAvailable(zero)

add_executable(python_inject main.cpp ptrace/tracee.cpp ptrace/executor.cpp inject/injector.cpp)
target_link_libraries(python_inject zero elfio $<$<BOOL:${STATIC_BUILD}>:-static-pie>)