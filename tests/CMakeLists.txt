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

add_compile_options(-O3 -Wall -Wextra -Wpedantic)

# CMake does not support add upper level directory with add_subdirectory.
# So we create another library named uaes here.
add_library(uaes)
target_sources(uaes PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../uaes.c)
target_include_directories(uaes PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../)

set(name_prefix "")

if(DEFINED UAES_DEFAULT_CONFIG)
    target_compile_definitions(uaes PUBLIC UAES_DEFAULT_CONFIG=${UAES_DEFAULT_CONFIG})
    set(name_prefix "${name_prefix}_D${UAES_DEFAULT_CONFIG}")
endif()

if(DEFINED UAES_STORE_ROUND_KEY_IN_CTX)
    target_compile_definitions(uaes PUBLIC UAES_STORE_ROUND_KEY_IN_CTX=${UAES_STORE_ROUND_KEY_IN_CTX})
    set(name_prefix "${name_prefix}_R${UAES_STORE_ROUND_KEY_IN_CTX}")
endif()

if(DEFINED UAES_SBOX_MODE)
    target_compile_definitions(uaes PUBLIC UAES_SBOX_MODE=${UAES_SBOX_MODE})
    set(name_prefix "${name_prefix}_S${UAES_SBOX_MODE}")
endif()

if(DEFINED UAES_32BIT_MODE)
    target_compile_definitions(uaes PUBLIC UAES_32BIT_MODE=${UAES_32BIT_MODE})
    set(name_prefix "${name_prefix}_W${UAES_32BIT_MODE}")
endif()

if(DEFINED UAES_KEY_SIZE)
    target_compile_definitions(uaes PUBLIC UAES_ENABLE_${UAES_KEY_SIZE}=1)
    set(name_prefix "${name_prefix}_K128")
endif()

if(DEFINED UAES_AES_MODE)
    target_compile_definitions(uaes PUBLIC UAES_ENABLE_${UAES_AES_MODE}=1)
    set(name_prefix "${name_prefix}_M${UAES_AES_MODE}")
endif()

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

if(NOT UAES_DISABLE_NIST)
    # Test NIST
    add_executable(test_nist uaes_test_nist.c)
    target_link_libraries(test_nist uaes)
    target_compile_definitions(test_nist PRIVATE TEST_BASE_DIR="${CMAKE_SOURCE_DIR}")
    add_test(NAME test_nist COMMAND test_nist WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    set_tests_properties(test_nist PROPERTIES LABELS "nist")
endif()

if(TEST_ALL_OPTIONS)
    set(AES_MODES
        ECB
        CBC
        CFB
        CFB1
        OFB
        CTR
        CCM
        GCM
    )

    # Test different modes and key sizes for test_simple
    foreach(STORE_ROUND_KEY_IN_CTX 0 1)
        foreach(SBOX_MODE 0 1 2)
            foreach(U32BIT_MODE 0 1)
                foreach(AES_MODE ${AES_MODES})
                    foreach(KEY_SIZE 128 192 256)
                        set(name "test_simple")
                        set(name "${name}_R${STORE_ROUND_KEY_IN_CTX}")
                        set(name "${name}_S${SBOX_MODE}")
                        set(name "${name}_W${U32BIT_MODE}")
                        set(name "${name}_M${AES_MODE}")
                        set(name "${name}_K${KEY_SIZE}")
                        add_custom_target(${name} ALL
                            ${CMAKE_COMMAND} -B ${CMAKE_BINARY_DIR}/${name}
                            ${CMAKE_CURRENT_SOURCE_DIR}
                            -DUAES_DEFAULT_CONFIG=0
                            -DUAES_STORE_ROUND_KEY_IN_CTX=${STORE_ROUND_KEY_IN_CTX}
                            -DUAES_SBOX_MODE=${SBOX_MODE}
                            -DUAES_32BIT_MODE=${U32BIT_MODE}
                            -DUAES_KEY_SIZE=${KEY_SIZE}
                            -DUAES_AES_MODE=${AES_MODE}
                            -DUAES_DISABLE_NIST=1
                            -DCMAKE_MESSAGE_LOG_LEVEL=WARNING
                            COMMAND
                            ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/${name}
                        )
                        add_test(NAME ${name} COMMAND ${CMAKE_BINARY_DIR}/${name}/test_simple)
                    endforeach()
                endforeach()
            endforeach()
        endforeach()
    endforeach()

    # To reduce the number of tests, we only test NIST with all modes and key sizes turned on.
    foreach(STORE_ROUND_KEY_IN_CTX 0 1)
        foreach(SBOX_MODE 0 1 2)
            foreach(U32BIT_MODE 0 1)
                set(name "test")
                set(name "${name}_R${STORE_ROUND_KEY_IN_CTX}")
                set(name "${name}_S${SBOX_MODE}")
                set(name "${name}_W${U32BIT_MODE}")
                add_custom_target(${name} ALL
                    ${CMAKE_COMMAND} -B ${CMAKE_BINARY_DIR}/${name}
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    -DUAES_STORE_ROUND_KEY_IN_CTX=${STORE_ROUND_KEY_IN_CTX}
                    -DUAES_SBOX_MODE=${SBOX_MODE}
                    -DUAES_32BIT_MODE=${U32BIT_MODE}
                    -DCMAKE_MESSAGE_LOG_LEVEL=WARNING
                    COMMAND
                    ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}/${name}
                )
                add_test(NAME ${name}_simple COMMAND ${CMAKE_BINARY_DIR}/${name}/test_simple)
                add_test(NAME ${name}_nist COMMAND ${CMAKE_BINARY_DIR}/${name}/test_nist)
            endforeach()
        endforeach()
    endforeach()
endif()
