/*
 * MIT License
 *
 * Copyright (c) 2023 Yu Chen (thecy18@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * github.com/cy18/uAES
 *
 */
#ifndef TEST_PORT_H_

// This file is used to define the port for test, making it possible to run
// the tests on platforms without the standard C library.
// In most cases, the tests should not fail, so the log functions are not
// necessary. Just leave them empty.

#include <stdint.h>
#include <stdlib.h>

// Do necessary initialization for the porting
extern void UAES_TP_Init(void);
// Call this when a string is needed to be printed for debugging
// printf("%s %s\n", prompt, str)
extern void UAES_TP_LogString(const char *prompt, const char *str);
// Call this when a number is needed to be printed for debugging
// printf("%s %d", prompt, num")
extern void UAES_TP_LogNumber(const char *prompt, int32_t num);
// Call this when a byte array is needed to be printed for debugging
// printf("%s %02x...%02x \n", prompt, bytes[0], ...., bytes[len-1]])
extern void UAES_TP_LogBytes(const char *prompt,
                             const uint8_t *bytes,
                             size_t len);
// Get the current time in milliseconds, used for benchmarking speed, return 0
// if not needed
extern uint32_t UAES_TP_GetTimeMs(void);
// Get the left space in stack, mainly used for benchmarking stack usage, return
// 0 if not needed
extern size_t UAES_TP_GetStackWaterMark(void);
#define TEST_PORT_H_

#endif // TEST_PORT_H_
