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
#include "benchmark.h"

#include "test_port.h"
#include "uaes.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#define BLOCK_SIZE   1024u
#define TEST_TIME_MS 3000u

typedef enum {
    OP_NONE, // Do nothing, call this to get the overhead of stack usage
    OP_INIT, // Init the context, used for both stack usage and speed test
    OP_PROCESS, // Process one block of data, used for both stack usage and
                // speed test
    OP_FULL_PROCESS, // Init the context, encrypt then decrypt one block of
                     // data, for AEAD modes, also process AAD, generate tag and
                     // verify tag. Use this mode to benchmark the stack usage
                     // of context-based API
    OP_SIMPLE_PROCESS, // Call UAES_XXX_SimpleEncrypt and
                       // UAES_XXX_SimpleDecrypt, use this mode to benchmark the
                       // stack usage of simple API
} Operation_t;

const uint8_t KEY[32u] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                           0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                           0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                           0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
const uint8_t IV[16u] = { 0 };
static uint8_t s_data[BLOCK_SIZE] = { 0 };
static uint8_t s_aad[BLOCK_SIZE] = { 0 };
static uint8_t s_tag[16u] = { 0 };

#if UAES_ENABLE_ECB
static uint32_t TestEcbEncrypt(Operation_t op, size_t key_len)
{
    static UAES_ECB_Ctx_t ctx;
    if (op == OP_INIT) {
        UAES_ECB_Init(&ctx, KEY, key_len);
        return 0u;
    } else if (op == OP_PROCESS) {
        UAES_ECB_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else if (op == OP_FULL_PROCESS) {
        UAES_ECB_Init(&ctx, KEY, key_len);
        UAES_ECB_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else if (op == OP_SIMPLE_PROCESS) {
        UAES_ECB_SimpleEncrypt(KEY, key_len, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else {
        // Do nothing
        return 0u;
    }
}
static uint32_t TestEcbDecrypt(Operation_t op, size_t key_len)
{
    static UAES_ECB_Ctx_t ctx;
    if (op == OP_INIT) {
        UAES_ECB_Init(&ctx, KEY, key_len);
        return 0u;
    } else if (op == OP_PROCESS) {
        UAES_ECB_Decrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else if (op == OP_FULL_PROCESS) {
        UAES_ECB_Init(&ctx, KEY, key_len);
        UAES_ECB_Decrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else if (op == OP_SIMPLE_PROCESS) {
        UAES_ECB_SimpleDecrypt(KEY, key_len, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else {
        // Do nothing
        return 0u;
    }
}
#endif

#if UAES_ENABLE_CBC
static uint32_t TestCbcEncrypt(Operation_t op, size_t key_len)
{
    static UAES_CBC_Ctx_t ctx;
    if (op == OP_INIT) {
        UAES_CBC_Init(&ctx, KEY, key_len, IV);
        return 0u;
    } else if (op == OP_PROCESS) {
        UAES_CBC_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else if (op == OP_FULL_PROCESS) {
        UAES_CBC_Init(&ctx, KEY, key_len, IV);
        UAES_CBC_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else if (op == OP_SIMPLE_PROCESS) {
        UAES_CBC_SimpleEncrypt(KEY, key_len, IV, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else {
        // Do nothing
        return 0u;
    }
}
static uint32_t TestCbcDecrypt(Operation_t op, size_t key_len)
{
    static UAES_CBC_Ctx_t ctx;
    if (op == OP_INIT) {
        UAES_CBC_Init(&ctx, KEY, key_len, IV);
        return 0u;
    } else if (op == OP_PROCESS) {
        UAES_CBC_Decrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else if (op == OP_FULL_PROCESS) {
        UAES_CBC_Init(&ctx, KEY, key_len, IV);
        UAES_CBC_Decrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else if (op == OP_SIMPLE_PROCESS) {
        UAES_CBC_SimpleDecrypt(KEY, key_len, IV, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else {
        // Do nothing
        return 0u;
    }
}
#endif

#if UAES_ENABLE_OFB
static uint32_t TestOfb(Operation_t op, size_t key_len)
{
    static UAES_OFB_Ctx_t ctx;
    if (op == OP_INIT) {
        UAES_OFB_Init(&ctx, KEY, key_len, IV);
        return 0u;
    } else if (op == OP_PROCESS) {
        UAES_OFB_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else if (op == OP_FULL_PROCESS) {
        UAES_OFB_Init(&ctx, KEY, key_len, IV);
        UAES_OFB_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        UAES_OFB_Decrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else if (op == OP_SIMPLE_PROCESS) {
        UAES_OFB_SimpleEncrypt(KEY, key_len, IV, s_data, s_data, BLOCK_SIZE);
        UAES_OFB_SimpleDecrypt(KEY, key_len, IV, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else {
        // Do nothing
        return 0u;
    }
}
#endif

#if UAES_ENABLE_CFB
static uint32_t TestCfb8(Operation_t op, size_t key_len)
{
    static UAES_CFB_Ctx_t ctx;
    if (op == OP_INIT) {
        UAES_CFB_Init(&ctx, 8u, KEY, key_len, IV);
        return 0u;
    } else if (op == OP_PROCESS) {
        UAES_CFB_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else if (op == OP_FULL_PROCESS) {
        UAES_CFB_Init(&ctx, 8u, KEY, key_len, IV);
        UAES_CFB_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        UAES_CFB_Decrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else if (op == OP_SIMPLE_PROCESS) {
        UAES_CFB_SimpleEncrypt(8u, KEY, key_len, IV, s_data, s_data, BLOCK_SIZE);
        UAES_CFB_SimpleDecrypt(8u, KEY, key_len, IV, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else {
        // Do nothing
        return 0u;
    }
}
static uint32_t TestCfb128(Operation_t op, size_t key_len)
{
    static UAES_CFB_Ctx_t ctx;
    if (op == OP_INIT) {
        UAES_CFB_Init(&ctx, 128u, KEY, key_len, IV);
        return 0u;
    } else if (op == OP_PROCESS) {
        UAES_CFB_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else if (op == OP_FULL_PROCESS) {
        UAES_CFB_Init(&ctx, 128u, KEY, key_len, IV);
        UAES_CFB_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        UAES_CFB_Decrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else if (op == OP_SIMPLE_PROCESS) {
        UAES_CFB_SimpleEncrypt(128u,
                               KEY,
                               key_len,
                               IV,
                               s_data,
                               s_data,
                               BLOCK_SIZE);
        UAES_CFB_SimpleDecrypt(128u,
                               KEY,
                               key_len,
                               IV,
                               s_data,
                               s_data,
                               BLOCK_SIZE);
        return BLOCK_SIZE;
    } else {
        // Do nothing
        return 0u;
    }
}
#endif

#if UAES_ENABLE_CFB1
static uint32_t TestCfb1(Operation_t op, size_t key_len)
{
    static UAES_CFB1_Ctx_t ctx;
    if (op == OP_INIT) {
        UAES_CFB1_Init(&ctx, KEY, key_len, IV);
        return 0u;
    } else if (op == OP_PROCESS) {
        UAES_CFB1_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else if (op == OP_FULL_PROCESS) {
        UAES_CFB1_Init(&ctx, KEY, key_len, IV);
        UAES_CFB1_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        UAES_CFB1_Decrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else if (op == OP_SIMPLE_PROCESS) {
        UAES_CFB1_SimpleEncrypt(KEY, key_len, IV, s_data, s_data, BLOCK_SIZE);
        UAES_CFB1_SimpleDecrypt(KEY, key_len, IV, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else {
        // Do nothing
        return 0u;
    }
}
#endif

#if UAES_ENABLE_CTR
static uint32_t TestCtr(Operation_t op, size_t key_len)
{
    static UAES_CTR_Ctx_t ctx;
    if (op == OP_INIT) {
        UAES_CTR_Init(&ctx, KEY, key_len, IV, 12u);
        return 0u;
    } else if (op == OP_PROCESS) {
        UAES_CTR_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else if (op == OP_FULL_PROCESS) {
        UAES_CTR_Init(&ctx, KEY, key_len, IV, 12u);
        UAES_CTR_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        UAES_CTR_Decrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else if (op == OP_SIMPLE_PROCESS) {
        UAES_CTR_SimpleEncrypt(KEY,
                               key_len,
                               IV,
                               12u,
                               s_data,
                               s_data,
                               BLOCK_SIZE);
        UAES_CTR_SimpleDecrypt(KEY,
                               key_len,
                               IV,
                               12u,
                               s_data,
                               s_data,
                               BLOCK_SIZE);
        return BLOCK_SIZE;
    } else {
        // Do nothing
        return 0u;
    }
}
#endif

#if UAES_ENABLE_CCM
static uint32_t TestCcm(Operation_t op, size_t key_len)
{
    static UAES_CCM_Ctx_t ctx;
    if (op == OP_INIT) {
        // Since we don't care about the result, the data_len can be any value
        UAES_CCM_Init(&ctx, KEY, key_len, IV, 12u, 16u, 1024u, 16u);
        return 0u;
    } else if (op == OP_PROCESS) {
        UAES_CCM_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else if (op == OP_FULL_PROCESS) {
        UAES_CCM_Init(&ctx, KEY, key_len, IV, 12u, 16u, sizeof(s_aad), 16u);
        UAES_CCM_AddAad(&ctx, s_aad, 0u);
        UAES_CCM_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        UAES_CCM_GenerateTag(&ctx, s_tag, 16u);
        UAES_CCM_Init(&ctx, KEY, key_len, IV, 12u, 16u, sizeof(s_aad), 16u);
        UAES_CCM_AddAad(&ctx, s_aad, 0u);
        UAES_CCM_Decrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        (void)UAES_CCM_VerifyTag(&ctx, s_tag, 16u);
        return BLOCK_SIZE;
    } else if (op == OP_SIMPLE_PROCESS) {
        UAES_CCM_SimpleEncrypt(KEY,
                               key_len,
                               IV,
                               12u,
                               s_aad,
                               BLOCK_SIZE,
                               s_data,
                               s_data,
                               BLOCK_SIZE,
                               s_tag,
                               16u);
        (void)UAES_CCM_SimpleDecrypt(KEY,
                                     key_len,
                                     IV,
                                     12u,
                                     s_aad,
                                     BLOCK_SIZE,
                                     s_data,
                                     s_data,
                                     BLOCK_SIZE,
                                     s_tag,
                                     16u);
        return BLOCK_SIZE;
    } else {
        // Do nothing
        return 0u;
    }
}
#endif

#if UAES_ENABLE_GCM
static uint32_t TestGcm(Operation_t op, size_t key_len)
{
    static UAES_GCM_Ctx_t ctx;
    if (op == OP_INIT) {
        UAES_GCM_Init(&ctx, KEY, key_len, IV, 12u);
        return 0u;
    } else if (op == OP_PROCESS) {
        UAES_GCM_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    } else if (op == OP_FULL_PROCESS) {
        UAES_GCM_Init(&ctx, KEY, key_len, IV, 12u);
        UAES_GCM_AddAad(&ctx, s_aad, 0u);
        UAES_GCM_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        UAES_GCM_GenerateTag(&ctx, s_tag, 16u);
        UAES_GCM_Init(&ctx, KEY, key_len, IV, 12u);
        UAES_GCM_AddAad(&ctx, s_aad, 0u);
        UAES_GCM_Decrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        (void)UAES_GCM_VerifyTag(&ctx, s_tag, 16u);
        return BLOCK_SIZE;
    } else if (op == OP_SIMPLE_PROCESS) {
        UAES_GCM_SimpleEncrypt(KEY,
                               key_len,
                               IV,
                               12u,
                               s_aad,
                               BLOCK_SIZE,
                               s_data,
                               s_data,
                               BLOCK_SIZE,
                               s_tag,
                               16u);
        (void)UAES_GCM_SimpleDecrypt(KEY,
                                     key_len,
                                     IV,
                                     12u,
                                     s_aad,
                                     BLOCK_SIZE,
                                     s_data,
                                     s_data,
                                     BLOCK_SIZE,
                                     s_tag,
                                     16u);
        return BLOCK_SIZE;
    } else {
        // Do nothing
        return 0u;
    }
}
#endif

void UAES_Benchmark(UAES_BM_Info_t *info)
{
    uint32_t (*func_test)(Operation_t, size_t) = NULL;
#if UAES_ENABLE_ECB
    if (info->mode == UAES_BM_MODE_ECB_ENC) {
        func_test = TestEcbEncrypt;
        info->size_of_ctx = sizeof(UAES_ECB_Ctx_t);
    }
    if (info->mode == UAES_BM_MODE_ECB_DEC) {
        func_test = TestEcbDecrypt;
        info->size_of_ctx = sizeof(UAES_ECB_Ctx_t);
    }
#endif
#if UAES_ENABLE_CBC
    if (info->mode == UAES_BM_MODE_CBC_ENC) {
        func_test = TestCbcEncrypt;
        info->size_of_ctx = sizeof(UAES_CBC_Ctx_t);
    }
    if (info->mode == UAES_BM_MODE_CBC_DEC) {
        func_test = TestCbcDecrypt;
        info->size_of_ctx = sizeof(UAES_CBC_Ctx_t);
    }
#endif
#if UAES_ENABLE_OFB
    if (info->mode == UAES_BM_MODE_OFB) {
        func_test = TestOfb;
        info->size_of_ctx = sizeof(UAES_OFB_Ctx_t);
    }
#endif
#if UAES_ENABLE_CFB
    if (info->mode == UAES_BM_MODE_CFB128) {
        func_test = TestCfb128;
        info->size_of_ctx = sizeof(UAES_CFB_Ctx_t);
    }
    if (info->mode == UAES_BM_MODE_CFB8) {
        func_test = TestCfb8;
        info->size_of_ctx = sizeof(UAES_CFB_Ctx_t);
    }
#endif
#if UAES_ENABLE_CFB1
    if (info->mode == UAES_BM_MODE_CFB1) {
        func_test = TestCfb1;
        info->size_of_ctx = sizeof(UAES_CFB1_Ctx_t);
    }
#endif
#if UAES_ENABLE_CTR
    if (info->mode == UAES_BM_MODE_CTR) {
        func_test = TestCtr;
        info->size_of_ctx = sizeof(UAES_CTR_Ctx_t);
    }
#endif
#if UAES_ENABLE_CCM
    if (info->mode == UAES_BM_MODE_CCM) {
        func_test = TestCcm;
        info->size_of_ctx = sizeof(UAES_CCM_Ctx_t);
    }
#endif
#if UAES_ENABLE_GCM
    if (info->mode == UAES_BM_MODE_GCM) {
        func_test = TestGcm;
        info->size_of_ctx = sizeof(UAES_GCM_Ctx_t);
    }
#endif
    if (func_test == NULL) {
        memset(info, 0, sizeof(UAES_BM_Info_t));
        return;
    }
    if ((info->key_len != 16u) && (info->key_len != 24u)
        && (info->key_len != 32u)) {
        memset(info, 0, sizeof(UAES_BM_Info_t));
        return;
    }
    func_test(OP_NONE, info->key_len);
    info->watermark_none = UAES_TP_GetStackWaterMark();
    func_test(OP_INIT, info->key_len);
    info->watermark_init = UAES_TP_GetStackWaterMark();
    func_test(OP_PROCESS, info->key_len);
    info->watermark_process = UAES_TP_GetStackWaterMark();
    func_test(OP_FULL_PROCESS, info->key_len);
    info->watermark_full_process = UAES_TP_GetStackWaterMark();
    func_test(OP_SIMPLE_PROCESS, info->key_len);
    info->watermark_simple_process = UAES_TP_GetStackWaterMark();
    uint32_t num_bytes = 0u;
    func_test(OP_INIT, info->key_len);
    uint32_t time_start = UAES_TP_GetTimeMs();
    for (size_t i = 0u; i < 100000u; ++i) {
        if ((UAES_TP_GetTimeMs() - time_start) >= TEST_TIME_MS) {
            break;
        }
        num_bytes += func_test(OP_PROCESS, info->key_len);
    }
    uint32_t time_end = UAES_TP_GetTimeMs();
    uint32_t time_diff = time_end - time_start;
    if (time_diff != 0u) {
        uint64_t speed = (uint64_t)num_bytes * 1000u / time_diff;
        info->speed = (size_t)speed;
    } else {
        info->speed = 0u;
    }
    if (info->mode == UAES_BM_MODE_CFB1) {
        info->speed /= 8u;
    }
    info->stack_usage1 = info->watermark_none - info->watermark_full_process;
    info->stack_usage2 = info->watermark_none - info->watermark_simple_process;
}

extern void UAES_BenchmarkAll(void)
{
    UAES_TP_LogBenchmarkTitle();
    static UAES_BM_Info_t m_info;
    for (UAES_BM_Mode_t mode = (UAES_BM_Mode_t)0; mode < UAES_BM_END; mode++) {
        for (size_t key_len = 16u; key_len <= 32u; key_len += 8u) {
            memset(&m_info, 0, sizeof(m_info));
            m_info.mode = mode;
            m_info.key_len = key_len;
            UAES_TP_RunBenchmark(UAES_Benchmark, &m_info);
            UAES_TP_LogBenchmarkInfo(&m_info);
        }
    }
}
