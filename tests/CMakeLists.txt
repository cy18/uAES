# MIT License
#
# Copyright (c) 2023 Yu Chen (thecy18@gmail.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# https://github.com/cy18/uAES

cmake_minimum_required(VERSION 3.12)

# Enable compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(uaes C)

enable_testing()

add_compile_options(-Os -Wall -Wextra -Wpedantic)

add_library(uaes)
target_sources(uaes PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../uaes.c)
target_include_directories(uaes PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../)

include(cppcheck/cppcheck.cmake)

# Run test_simple with default options
add_executable(test_simple
    test_simple_main.c
    uaes_test_port_pc.c
    uaes_test_simple.c
)
target_link_libraries(test_simple uaes)
add_test(NAME test_simple COMMAND test_simple)
set_tests_properties(test_simple PROPERTIES LABELS "simple")

# Run test_simple with different options
foreach(STORE_ROUND_KEY_IN_CTX 0 1)
    foreach(SBOX_MODE 0 1 2)
        foreach(U32BIT_MODE 0 1)
            set(name test_simple_${STORE_ROUND_KEY_IN_CTX}_${SBOX_MODE}_${U32BIT_MODE})
            add_executable(${name}
                ${CMAKE_CURRENT_LIST_DIR}/../uaes.c
                test_simple_main.c
                uaes_test_port_pc.c
                uaes_test_simple.c
            )
            target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../)
            target_compile_definitions(${name} PRIVATE
                UAES_STORE_ROUND_KEY_IN_CTX=${STORE_ROUND_KEY_IN_CTX}
                UAES_SBOX_MODE=${SBOX_MODE}
                UAES_32BIT_MODE=${U32BIT_MODE}
            )
            add_test(NAME ${name} COMMAND ${name})
            set_tests_properties(${name} PROPERTIES LABELS "simple")
        endforeach()
    endforeach()
endforeach()

# Test NIST
add_executable(test_nist uaes_test_nist.c)
target_link_libraries(test_nist uaes)
target_compile_definitions(test_nist PRIVATE TEST_BASE_DIR="${CMAKE_SOURCE_DIR}")
add_test(NAME test_nist COMMAND test_nist WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
set_tests_properties(test_nist PROPERTIES LABELS "nist")

# Run test_nist with different options
foreach(STORE_ROUND_KEY_IN_CTX 0 1)
    foreach(SBOX_MODE 0 1 2)
        foreach(U32BIT_MODE 0 1)
            set(name test_nist_${STORE_ROUND_KEY_IN_CTX}_${SBOX_MODE}_${U32BIT_MODE})
            add_executable(${name}
                ${CMAKE_CURRENT_LIST_DIR}/../uaes.c
                uaes_test_nist.c
            )
            target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../)
            target_compile_definitions(${name} PRIVATE
                UAES_STORE_ROUND_KEY_IN_CTX=${STORE_ROUND_KEY_IN_CTX}
                UAES_SBOX_MODE=${SBOX_MODE}
                UAES_32BIT_MODE=${U32BIT_MODE}
            )
            target_compile_definitions(${name} PRIVATE TEST_BASE_DIR="${CMAKE_SOURCE_DIR}")
            add_test(NAME ${name} COMMAND ${name} WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
            set_tests_properties(${name} PROPERTIES LABELS "nist")
        endforeach()
    endforeach()
endforeach()

# Benchmark
add_executable(uaes_benchmark
    uaes_benchmark_main.c
    uaes_benchmark.c
    uaes_test_port_pc.c
)
target_link_libraries(uaes_benchmark uaes)

add_custom_target(benchmark
    COMMAND uaes_benchmark
    DEPENDS uaes_benchmark
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
