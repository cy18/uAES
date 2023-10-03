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

find_program(CPPCHECK NAMES cppcheck)

if(CPPCHECK)
    set_property(TARGET ${MAIN} PROPERTY EXPORT_COMPILE_COMMANDS "ON")
    message("CPPCheck found, start configure cppcheck")

    # Find misra.py based on location of cppcheck
    # For example, if cppcheck locates at /usr/bin/cppcheck, then try find misra.py in /usr
    get_filename_component(CPPCHECK_DIR ${CPPCHECK} DIRECTORY)
    get_filename_component(FIND_ADDON_DIR ${CPPCHECK_DIR} DIRECTORY)
    file(GLOB_RECURSE MISRA_ADDON ${FIND_ADDON_DIR}/**/misra.py
    )

    if(MISRA_ADDON)
        message("Use addon " ${MISRA_ADDON})
    else()
        message(FATAL_ERROR "CPPCheck addon misra.py not found in " ${FIND_ADDON_PATH})
    endif()

    configure_file("${CMAKE_CURRENT_LIST_DIR}/misra.json.in" "misra.json")
    configure_file("${CMAKE_CURRENT_LIST_DIR}/suppressions_list.txt.in" "suppressions_list.txt")
    list(
        APPEND CPPCHECK
        "--quiet"
        "--enable=all"
        "--suppress=missingIncludeSystem"
        "--max-ctu-depth=8"
        "--std=c99"
        "--inconclusive"
        "--inline-suppr"
        "--error-exitcode=-1"
        "--addon=${CMAKE_CURRENT_BINARY_DIR}/misra.json"
        "--suppressions-list=${CMAKE_CURRENT_BINARY_DIR}/suppressions_list.txt"
        "--project=${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json"
        "--cppcheck-build-dir=${CMAKE_CURRENT_BINARY_DIR}/cppcheck_build_dir"
        "--platform=unspecified"
    )
    message("CPPCheck command: " "${CPPCHECK}")

    # Create cppcheck build dir
    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/cppcheck_build_dir")

    # Do CPP check before link
    add_custom_target(
        cppcheck ALL
        COMMAND ${CPPCHECK}
        DEPENDS ${MAIN}
    )
else()
    message(FATAL_ERROR "CPPCheck not found")
endif()
