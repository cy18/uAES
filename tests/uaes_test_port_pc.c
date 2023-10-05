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

#include "uaes_test_port.h"

#include <stdint.h>
#include <stdio.h>
#include <time.h>

void UAES_TP_Init(void)
{
    (void)0;
}

void UAES_TP_LogString(const char *prompt, const char *str)
{
    printf("%s %s\n", prompt, str);
}

void UAES_TP_LogNumber(const char *prompt, int32_t num)
{
    printf("%s %d\n", prompt, num);
}

void UAES_TP_LogBytes(const char *prompt, const uint8_t *bytes, size_t len)
{
    printf("%s ", prompt);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

uint32_t UAES_TP_GetTimeMs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t ms = ts.tv_sec * 1000u + ts.tv_nsec / 1000000u;
    return (uint32_t)ms;
}

size_t UAES_TP_GetStackWaterMark(void)
{
    return 0u;
}
