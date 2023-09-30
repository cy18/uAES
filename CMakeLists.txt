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

add_compile_options(-Os -Wall -Wextra -Wpedantic)

add_executable(uaes_128)
target_sources(uaes_128 PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/uaes.c
    ${CMAKE_CURRENT_LIST_DIR}/test.c
)

target_include_directories(uaes_128
    INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}
)
target_compile_definitions(uaes_128 PRIVATE
    UAES_KEY_SIZE=128u
)

add_executable(uaes_192)
target_sources(uaes_192 PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/uaes.c
    ${CMAKE_CURRENT_LIST_DIR}/test.c
)

target_include_directories(uaes_192
    INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}
)
target_compile_definitions(uaes_192 PRIVATE
    UAES_KEY_SIZE=192u
)

add_executable(uaes_256)
target_sources(uaes_256 PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/uaes.c
    ${CMAKE_CURRENT_LIST_DIR}/test.c
)

target_include_directories(uaes_256
    INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}
)
target_compile_definitions(uaes_256 PRIVATE
    UAES_KEY_SIZE=256u
)

include(cmake/cppcheck.cmake)
