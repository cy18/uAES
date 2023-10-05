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
#include "uaes_benchmark.h"

#include "uaes.h"
#include "uaes_test_port.h"

#include <stdbool.h>
#include <stddef.h>

#define BLOCK_SIZE   1024u
#define TEST_TIME_MS 3000u

const uint8_t KEY[32u] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                           0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                           0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                           0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
const uint8_t IV[16u] = { 0 };
static uint8_t s_data[BLOCK_SIZE] = { 0 };

#if UAES_ENABLE_ECB_ENCRYPT
static uint32_t TestEcbEncrypt(bool init, size_t key_len)
{
    static UAES_ECB_Ctx_t ctx;
    if (init) {
        UAES_ECB_Init(&ctx, KEY, key_len);
        return 0u;
    } else {
        UAES_ECB_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    }
}
#endif

#if UAES_ENABLE_ECB_DECRYPT
static uint32_t TestEcbDecrypt(bool init, size_t key_len)
{
    static UAES_ECB_Ctx_t ctx;
    if (init) {
        UAES_ECB_Init(&ctx, KEY, key_len);
        return 0u;
    } else {
        UAES_ECB_Decrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    }
}
#endif

#if UAES_ENABLE_CBC_ENCRYPT
static uint32_t TestCbcEncrypt(bool init, size_t key_len)
{
    static UAES_CBC_Ctx_t ctx;
    if (init) {
        UAES_CBC_Init(&ctx, KEY, key_len, IV);
        return 0u;
    } else {
        UAES_CBC_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    }
}
#endif

#if UAES_ENABLE_CBC_DECRYPT
static uint32_t TestCbcDecrypt(bool init, size_t key_len)
{
    static UAES_CBC_Ctx_t ctx;
    if (init) {
        UAES_CBC_Init(&ctx, KEY, key_len, IV);
        return 0u;
    } else {
        UAES_CBC_Decrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    }
}
#endif

static uint32_t TestCtr(bool init, size_t key_len)
{
    static UAES_CTR_Ctx_t ctx;
    if (init) {
        UAES_CTR_Init(&ctx, KEY, key_len, IV, 12u);
        return 0u;
    } else {
        UAES_CTR_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    }
}

#if UAES_ENABLE_CCM
static uint32_t TestCcm(bool init, size_t key_len)
{
    static UAES_CCM_Ctx_t ctx;
    if (init) {
        // Since we don't care about the result, the data_len can be any value
        UAES_CCM_Init(&ctx, KEY, key_len, IV, 12u, 16u, 1024u, 16u);
        return 0u;
    } else {
        UAES_CCM_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    }
}
#endif

#if UAES_ENABLE_GCM
static uint32_t TestGcm(bool init, size_t key_len)
{
    static UAES_GCM_Ctx_t ctx;
    if (init) {
        UAES_GCM_Init(&ctx, KEY, key_len, IV, 12u);
        return 0u;
    } else {
        UAES_GCM_Encrypt(&ctx, s_data, s_data, BLOCK_SIZE);
        return BLOCK_SIZE;
    }
}
#endif

uint32_t UAES_Benchmark(UAES_BM_Mode_t mode, size_t key_len)
{
    uint32_t (*func_test)(bool, size_t) = NULL;
#if UAES_ENABLE_ECB_ENCRYPT
    if (mode == UAES_BM_MODE_ECB_ENC) {
        func_test = TestEcbEncrypt;
    }
#endif
#if UAES_ENABLE_ECB_DECRYPT
    if (mode == UAES_BM_MODE_ECB_DEC) {
        func_test = TestEcbDecrypt;
    }
#endif
#if UAES_ENABLE_CBC_ENCRYPT
    if (mode == UAES_BM_MODE_CBC_ENC) {
        func_test = TestCbcEncrypt;
    }
#endif
#if UAES_ENABLE_CBC_DECRYPT
    if (mode == UAES_BM_MODE_CBC_DEC) {
        func_test = TestCbcDecrypt;
    }
#endif
#if UAES_ENABLE_CTR
    if (mode == UAES_BM_MODE_CTR) {
        func_test = TestCtr;
    }
#endif
#if UAES_ENABLE_CCM
    if (mode == UAES_BM_MODE_CCM) {
        func_test = TestCcm;
    }
#endif
#if UAES_ENABLE_GCM
    if (mode == UAES_BM_MODE_GCM) {
        func_test = TestGcm;
    }
#endif
    if (func_test == NULL) {
        return 0u;
    }
    if ((key_len != 16u) && (key_len != 24u) && (key_len != 32u)) {
        return 0u;
    }
    uint32_t time_start = UAES_TP_GetTimeMs();
    uint32_t num_bytes = 0u;
    func_test(true, key_len);
    while ((UAES_TP_GetTimeMs() - time_start) < TEST_TIME_MS) {
        num_bytes += func_test(false, key_len);
    }
    uint32_t time_end = UAES_TP_GetTimeMs();
    uint32_t time_diff = time_end - time_start;
    uint64_t speed = (uint64_t)num_bytes * 1000u / time_diff;
    return (uint32_t)speed;
}
