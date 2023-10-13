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

#ifndef UAES_BENCHMARK_H_
#define UAES_BENCHMARK_H_

#include <stddef.h>
#include <stdint.h>

typedef enum {
    UAES_BM_MODE_ECB_ENC,
    UAES_BM_MODE_ECB_DEC,
    UAES_BM_MODE_CBC_ENC,
    UAES_BM_MODE_CBC_DEC,
    UAES_BM_MODE_OFB,
    UAES_BM_MODE_CTR,
    UAES_BM_MODE_CFB128,
    UAES_BM_MODE_CFB8,
    UAES_BM_MODE_CFB1,
    UAES_BM_MODE_CCM,
    UAES_BM_MODE_GCM,
    UAES_BM_END,
} UAES_BM_Mode_t;

// Return the number of processed bytes per second.
// To make this work, the UAES_TP_GetTimeMs must be implemented.
// The benchmark will be run for 3 seconds, and the average value will be
// returned.
// The key_len must be 16, 24 or 32.
extern uint32_t UAES_Benchmark(UAES_BM_Mode_t mode, size_t key_len);

#endif // UAES_BENCHMARK_H_
