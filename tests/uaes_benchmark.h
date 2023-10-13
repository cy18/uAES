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

static const char UAES_BM_MODE_STR[UAES_BM_END][8] = {
    [UAES_BM_MODE_ECB_ENC] = "ECB_ENC", [UAES_BM_MODE_ECB_DEC] = "ECB_DEC",
    [UAES_BM_MODE_CBC_ENC] = "CBC_ENC", [UAES_BM_MODE_CBC_DEC] = "CBC_DEC",
    [UAES_BM_MODE_OFB] = "OFB",         [UAES_BM_MODE_CTR] = "CTR",
    [UAES_BM_MODE_CFB128] = "CFB128",   [UAES_BM_MODE_CFB8] = "CFB8",
    [UAES_BM_MODE_CFB1] = "CFB1",       [UAES_BM_MODE_CCM] = "CCM",
    [UAES_BM_MODE_GCM] = "GCM",
};

typedef struct {
    UAES_BM_Mode_t mode;
    size_t key_len;
    size_t size_of_ctx;
    size_t watermark_none;
    size_t watermark_init;
    size_t watermark_process;
    size_t watermark_full_process;
    size_t watermark_simple_process;
    size_t stack_usage1;
    size_t stack_usage2;
    size_t speed;
} UAES_BM_Info_t;

// Do benchmarking and write the result to the result pointer.
// To test speed, the UAES_TP_GetTimeMs must be implemented.
// For a more accurate result, make sure the task running the benchmark is
// running in a high priority.
// To test stack usage, the UAES_TP_GetStackWaterMark must be implemented.
// Further more, a new task should be created to run the benchmark, so that the
// stack usage is not affected by the main task or other benchmark tasks.
extern void UAES_Benchmark(UAES_BM_Info_t *info);

// Do benchmarking for all modes. UAES_TP_LogBenchmarkTitle and
// UAES_TP_LogBenchmarkResult should be implemented to print the result.
extern void UAES_BenchmarkAll(void);

#endif // UAES_BENCHMARK_H_
