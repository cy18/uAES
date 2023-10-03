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

add_library(uaes)
target_sources(uaes PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../uaes.c)
target_include_directories(uaes PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../)

include(cppcheck/cppcheck.cmake)

add_executable(test_128 test.c)
target_compile_definitions(test_128 PRIVATE TEST_KEY_SIZE=128u)
target_link_libraries(test_128 uaes)

add_executable(test_192 test.c)
target_compile_definitions(test_192 PRIVATE TEST_KEY_SIZE=192u)
target_link_libraries(test_192 uaes)

add_executable(test_256 test.c)
target_compile_definitions(test_256 PRIVATE TEST_KEY_SIZE=256u)
target_link_libraries(test_256 uaes)

add_executable(test_nist test_nist.c)
target_link_libraries(test_nist uaes)

# Add tests as custom targets
add_custom_target(tests ALL
    COMMAND test_128
    COMMAND test_192
    COMMAND test_256
    COMMAND test_nist
    DEPENDS test_128 test_192 test_256 test_nist
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

add_custom_target(do_test_nist
    COMMAND test_nist
    DEPENDS test_nist
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
