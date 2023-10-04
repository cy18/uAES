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

#include "uaes.h"

#include <stdio.h> // cppcheck-suppress misra-c2012-21.6 ; supprssed for testing
#include <stdlib.h>
#include <string.h>

static size_t s_success_num = 0u;
static size_t s_failure_num = 0u;

#define PRINTF(...) (void)printf(__VA_ARGS__)

static void PrintArray(const uint8_t *array, uint8_t size)
{
    for (uint8_t i = 0u; i < size; i++) {
        PRINTF("%02x ", array[i]);
    }
    PRINTF("\n");
}

static void CheckData(const uint8_t *expected,
                      const uint8_t *actual,
                      size_t len,
                      const char *msg)
{
    if (memcmp(expected, actual, len) != 0) {
        PRINTF("CheckData failed, %s\n", msg);
        PrintArray(expected, len);
        PrintArray(actual, len);
        s_failure_num++;
    } else {
        s_success_num++;
    }
}

static void CheckDataAndTag(const uint8_t *expected,
                            const uint8_t *actual,
                            size_t len,
                            const uint8_t *expected_tag,
                            const uint8_t *actual_tag,
                            size_t tag_len,
                            const char *msg)
{
    if (memcmp(expected, actual, len) != 0) {
        PRINTF("CheckDataAndTag failed, %s\n", msg);
        PrintArray(expected, len);
        PrintArray(actual, len);
        s_failure_num++;
    } else if (memcmp(expected_tag, actual_tag, tag_len) != 0) {
        PRINTF("CheckDataAndTag failed, %s\n", msg);
        PrintArray(expected_tag, tag_len);
        PrintArray(actual_tag, tag_len);
        s_failure_num++;
    } else {
        s_success_num++;
    }
}

#if UAES_ENABLE_ECB

static void TestEcbCase(const uint8_t *KEY,
                        size_t key_len,
                        const uint8_t *IN,
                        const uint8_t *OUT,
                        size_t data_len)
{
    UAES_ECB_Ctx_t ctx;
    UAES_ECB_Init(&ctx, KEY, key_len);
    uint8_t result[data_len];
#if UAES_ENABLE_ECB_ENCRYPT
    UAES_ECB_Encrypt(&ctx, IN, result, data_len);
    CheckData(OUT, result, data_len, "UAES_ECB_Encrypt");
    UAES_ECB_SimpleEncrypt(KEY, key_len, IN, result, data_len);
    CheckData(OUT, result, data_len, "UAES_ECB_SimpleEncrypt");
#endif // UAES_ENABLE_ECB_ENCRYPT
#if UAES_ENABLE_ECB_DECRYPT
    UAES_ECB_Decrypt(&ctx, OUT, result, data_len);
    CheckData(IN, result, data_len, "UAES_ECB_Decrypt");
    UAES_ECB_SimpleDecrypt(KEY, key_len, OUT, result, data_len);
    CheckData(IN, result, data_len, "UAES_ECB_SimpleDecrypt");
#endif // UAES_ENABLE_ECB_DECRYPT
}

static void TestECB(void)
{
    uint8_t const KEY256[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                               0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                               0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                               0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t const OUT256[] = { 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
                               0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8 };
    uint8_t const KEY192[] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                               0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                               0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
    uint8_t const OUT192[] = { 0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
                               0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc };
    uint8_t const KEY128[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t const OUT128[] = { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
                               0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 };
    uint8_t const IN[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                           0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    TestEcbCase(KEY256, sizeof(KEY256), IN, OUT256, sizeof(IN));
    TestEcbCase(KEY192, sizeof(KEY192), IN, OUT192, sizeof(IN));
    TestEcbCase(KEY128, sizeof(KEY128), IN, OUT128, sizeof(IN));
}
#endif // UAES_ENABLE_ECB

#if UAES_ENABLE_CBC

static void TestCbcCase(const uint8_t *KEY,
                        size_t key_len,
                        const uint8_t *IV,
                        size_t iv_len,
                        const uint8_t *IN,
                        const uint8_t *OUT,
                        size_t data_len)
{
    (void)iv_len;
    UAES_CBC_Ctx_t ctx;
    uint8_t result[data_len];
#if UAES_ENABLE_CBC_ENCRYPT
    UAES_CBC_Init(&ctx, KEY, key_len, IV);
    (void)memcpy(result, IN, data_len);
    UAES_CBC_Encrypt(&ctx, result, result, data_len);
    CheckData(OUT, result, data_len, "UAES_CBC_Encrypt");
    UAES_CBC_SimpleEncrypt(KEY, key_len, IV, IN, result, data_len);
    CheckData(OUT, result, data_len, "UAES_CBC_SimpleEncrypt");
#endif // UAES_ENABLE_CBC_ENCRYPT
#if UAES_ENABLE_CBC_DECRYPT
    UAES_CBC_Init(&ctx, KEY, key_len, IV);
    (void)memcpy(result, OUT, data_len);
    UAES_CBC_Decrypt(&ctx, result, result, data_len);
    CheckData(IN, result, data_len, "UAES_CBC_Decrypt");
    UAES_CBC_SimpleDecrypt(KEY, key_len, IV, OUT, result, data_len);
    CheckData(IN, result, data_len, "UAES_CBC_SimpleDecrypt");
#endif // UAES_ENABLE_CBC_DECRYPT
}

static void TestCBC(void)
{
    const uint8_t KEY256[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                               0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                               0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                               0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    const uint8_t OUT256[64u] = {
        0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab,
        0xfb, 0x5f, 0x7b, 0xfb, 0xd6, 0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb,
        0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d, 0x39,
        0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63,
        0x04, 0x23, 0x14, 0x61, 0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9,
        0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b
    };
    const uint8_t KEY192[] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                               0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                               0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
    const uint8_t OUT192[64u] = {
        0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d, 0x71, 0x78, 0x18,
        0x3a, 0x9f, 0xa0, 0x71, 0xe8, 0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d,
        0xed, 0xf4, 0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a, 0x57,
        0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0, 0x7f, 0xa9, 0xba, 0xac,
        0x3d, 0xf1, 0x02, 0xe0, 0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88,
        0x81, 0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd
    };
    const uint8_t KEY128[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    const uint8_t OUT128[64u] = {
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e,
        0x9b, 0x12, 0xe9, 0x19, 0x7d, 0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72,
        0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2, 0x73,
        0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e,
        0x22, 0x22, 0x95, 0x16, 0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac,
        0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7
    };
    const uint8_t IV[16u] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const uint8_t IN[64u] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                              0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                              0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                              0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                              0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                              0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                              0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                              0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
    TestCbcCase(KEY256, sizeof(KEY256), IV, sizeof(IV), IN, OUT256, sizeof(IN));
    TestCbcCase(KEY192, sizeof(KEY192), IV, sizeof(IV), IN, OUT192, sizeof(IN));
    TestCbcCase(KEY128, sizeof(KEY128), IV, sizeof(IV), IN, OUT128, sizeof(IN));
}
#endif // UAES_ENABLE_CBC

#if UAES_ENABLE_CTR

static void TestCtrCase(const uint8_t *KEY,
                        size_t key_len,
                        const uint8_t *NONCE,
                        size_t nonce_len,
                        const uint8_t *IN,
                        const uint8_t *OUT,
                        size_t data_len)
{
    uint8_t result[data_len];
    UAES_CTR_Ctx_t ctx;

    // Encrypt whole array at once
    UAES_CTR_Init(&ctx, KEY, key_len, NONCE, nonce_len);
    UAES_CTR_Encrypt(&ctx, IN, result, data_len);
    CheckData(OUT, result, data_len, "UAES_CTR_Encrypt");
    UAES_CTR_SimpleEncrypt(KEY, key_len, NONCE, nonce_len, IN, result, data_len);
    CheckData(OUT, result, data_len, "UAES_CTR_SimpleEncrypt");
    // Encrypt the array by random chunks
    UAES_CTR_Init(&ctx, KEY, key_len, NONCE, nonce_len);
    size_t pos = 0u;
    while (pos < data_len) {
        size_t chunk = (size_t)rand() % (data_len - pos);
        if (chunk > 24u) {
            chunk = 24u;
        }
        if (chunk == 0u) {
            chunk = 1u;
        }
        UAES_CTR_Encrypt(&ctx, &IN[pos], &result[pos], chunk);
        pos += chunk;
    }
    CheckData(OUT, result, data_len, "UAES_CTR_Encrypt");
    // Decrypt whole array at once
    UAES_CTR_Init(&ctx, KEY, key_len, NONCE, nonce_len);
    UAES_CTR_Decrypt(&ctx, OUT, result, data_len);
    CheckData(IN, result, data_len, "UAES_CTR_Decrypt");
    UAES_CTR_SimpleDecrypt(KEY,
                           key_len,
                           NONCE,
                           nonce_len,
                           OUT,
                           result,
                           data_len);
    CheckData(IN, result, data_len, "UAES_CTR_SimpleDecrypt");
    // Decrypt the array by random chunks
    UAES_CTR_Init(&ctx, KEY, key_len, NONCE, nonce_len);
    pos = 0u;
    while (pos < data_len) {
        size_t chunk = (size_t)rand() % (data_len - pos);
        if (chunk > 24u) {
            chunk = 24u;
        }
        if (chunk == 0u) {
            chunk = 1u;
        }
        UAES_CTR_Decrypt(&ctx, &OUT[pos], &result[pos], chunk);
        pos += chunk;
    }
    CheckData(IN, result, data_len, "UAES_CTR_Decrypt");
}

static void TestCtr(void)
{
    const uint8_t KEY256[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae,
        0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61,
        0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    const uint8_t OUT256[64] = {
        0xdf, 0x71, 0x89, 0xad, 0x91, 0x76, 0xb,  0x5e, 0x98, 0xdc, 0xac,
        0x81, 0xb6, 0x29, 0x4,  0x8d, 0xbc, 0x72, 0xa2, 0xeb, 0x73, 0x27,
        0xb8, 0x41, 0x79, 0x2e, 0xcd, 0x5e, 0x53, 0x60, 0xd1, 0xd3, 0x4a,
        0x27, 0xc6, 0x9b, 0xa7, 0x92, 0x62, 0xb,  0x7b, 0xc,  0xd9, 0xa,
        0x97, 0x7d, 0xa1, 0xb1, 0xfd, 0x6f, 0x32, 0xea, 0x95, 0x68, 0x1a,
        0x79, 0xbe, 0xd6, 0x2d, 0x96, 0xfb, 0x65, 0x3d, 0x14
    };
    const uint8_t KEY192[24] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
        0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };
    const uint8_t OUT192[64] = {
        0x2a, 0xb8, 0xbe, 0xe6, 0xa2, 0xb1, 0x44, 0x26, 0xc9, 0xcd, 0xea,
        0xb4, 0x32, 0x20, 0xaa, 0x29, 0x53, 0x46, 0x97, 0x8,  0xf3, 0x44,
        0x36, 0x4f, 0x33, 0x9a, 0xf8, 0xf7, 0x25, 0xe3, 0xa2, 0x41, 0x72,
        0x76, 0x43, 0x7d, 0xf1, 0x40, 0xd2, 0x5c, 0x4b, 0x1e, 0xa1, 0x5a,
        0x3b, 0x9d, 0xe2, 0x9f, 0xf3, 0x17, 0x1,  0x5d, 0x86, 0xce, 0x91,
        0x2e, 0x22, 0xd2, 0xe4, 0xdb, 0xa6, 0xf3, 0xf1, 0xa7
    };
    const uint8_t KEY128[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    const uint8_t OUT128[64] = {
        0x67, 0xee, 0x5,  0x54, 0x74, 0x99, 0xf8, 0xbc, 0xf0, 0xc3, 0x83,
        0x24, 0xe8, 0x60, 0x5c, 0x28, 0x1,  0x82, 0x16, 0xa5, 0xf4, 0xda,
        0xc1, 0xaf, 0x7e, 0x12, 0xae, 0x7a, 0xc,  0x2e, 0x3e, 0x9f, 0x13,
        0xe8, 0xbc, 0x4a, 0x37, 0x57, 0xa5, 0x48, 0x13, 0x98, 0x5,  0xcf,
        0x95, 0x63, 0x14, 0xd,  0x2f, 0x88, 0x8d, 0x31, 0x4b, 0x55, 0x2b,
        0x83, 0x96, 0x78, 0xe5, 0xf1, 0x2d, 0x56, 0xa9, 0x48
    };
    const uint8_t NONCE[8u] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7 };
    const uint8_t IN[64] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                             0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                             0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                             0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                             0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                             0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                             0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                             0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
    TestCtrCase(KEY256,
                sizeof(KEY256),
                NONCE,
                sizeof(NONCE),
                IN,
                OUT256,
                sizeof(IN));
    TestCtrCase(KEY192,
                sizeof(KEY192),
                NONCE,
                sizeof(NONCE),
                IN,
                OUT192,
                sizeof(IN));
    TestCtrCase(KEY128,
                sizeof(KEY128),
                NONCE,
                sizeof(NONCE),
                IN,
                OUT128,
                sizeof(IN));
}

#endif // UAES_ENABLE_CTR

#if UAES_ENABLE_CCM

static void TestCcmCase(const uint8_t *KEY,
                        size_t key_len,
                        const uint8_t *NONCE,
                        size_t nonce_len,
                        const uint8_t *IN,
                        const uint8_t *OUT,
                        size_t data_len,
                        const uint8_t *TAG,
                        size_t tag_len)
{
    uint8_t tag_out[16];
    uint8_t result[data_len];
    UAES_CCM_Ctx_t ctx;
    // Test encryption at once
    UAES_CCM_Init(&ctx, KEY, key_len, NONCE, nonce_len, 0u, data_len, tag_len);
    UAES_CCM_Encrypt(&ctx, IN, result, data_len);
    UAES_CCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
    CheckDataAndTag(OUT,
                    result,
                    data_len,
                    TAG,
                    tag_out,
                    tag_len,
                    "UAES_CCM_Encrypt");
    UAES_CCM_SimpleEncrypt(KEY,
                           key_len,
                           NONCE,
                           nonce_len,
                           NULL,
                           0u,
                           IN,
                           result,
                           data_len,
                           tag_out,
                           tag_len);
    CheckDataAndTag(OUT,
                    result,
                    data_len,
                    TAG,
                    tag_out,
                    tag_len,
                    "UAES_SimpleEncrypt");
    // Test encryption by random chunks
    UAES_CCM_Init(&ctx, KEY, key_len, NONCE, nonce_len, 0u, data_len, tag_len);
    size_t pos = 0u;
    while (pos < data_len) {
        size_t chunk = (size_t)rand() % (data_len - pos);
        if (chunk > 24u) {
            chunk = 24u;
        }
        if (chunk == 0u) {
            chunk = 1u;
        }
        UAES_CCM_Encrypt(&ctx, &IN[pos], &result[pos], chunk);
        pos += chunk;
    }
    UAES_CCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
    CheckDataAndTag(OUT,
                    result,
                    data_len,
                    TAG,
                    tag_out,
                    tag_len,
                    "UAES_CCM_Encrypt");
    // Test decryption at once
    UAES_CCM_Init(&ctx, KEY, key_len, NONCE, nonce_len, 0u, data_len, tag_len);
    // This is an intended call to make sure calling UAES_CCM_VerifyTag
    // after UAES_CCM_GenerateTag works correctly.
    (void)memcpy(result, OUT, data_len);
    UAES_CCM_Decrypt(&ctx, result, result, data_len);
    UAES_CCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
    CheckDataAndTag(IN,
                    result,
                    data_len,
                    TAG,
                    tag_out,
                    tag_len,
                    "UAES_CCM_Decrypt");
    if (!UAES_CCM_SimpleDecrypt(KEY,
                                key_len,
                                NONCE,
                                nonce_len,
                                NULL,
                                0u,
                                OUT,
                                result,
                                data_len,
                                TAG,
                                tag_len)) {
        PRINTF("UAES_CCM_SimpleDecrypt failed at verifying\n");
    } else {
        CheckData(IN, result, data_len, "UAES_CCM_SimpleDecrypt");
    }
    // Test decryption by random chunks
    UAES_CCM_Init(&ctx, KEY, key_len, NONCE, nonce_len, 0u, data_len, tag_len);
    // This is an intended call to make sure calling UAES_CCM_VerifyTag
    // after UAES_CCM_GenerateTag works correctly.
    UAES_CCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
    (void)memcpy(result, OUT, data_len);
    pos = 0u;
    while (pos < data_len) {
        size_t chunk = (size_t)rand() % (data_len - pos);
        if (chunk > 24u) {
            chunk = 24u;
        }
        if (chunk == 0u) {
            chunk = 1u;
        }
        UAES_CCM_Decrypt(&ctx, &OUT[pos], &result[pos], chunk);
        pos += chunk;
    }
    UAES_CCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
}

static void TestCcm(void)
{
    const uint8_t KEY256[32] = {
        0xfa, 0x0f, 0xf0, 0x16, 0x9d, 0xc9, 0x57, 0x56, 0x74, 0x06, 0x66,
        0x76, 0xcf, 0xb0, 0xb4, 0xeb, 0x89, 0x02, 0xc4, 0x42, 0x69, 0xda,
        0x1c, 0xf6, 0xba, 0x66, 0xd3, 0xf8, 0xb6, 0xd4, 0xb1, 0x00
    };
    const uint8_t OUT256[64] = {
        0xc6, 0xbf, 0x09, 0xfb, 0x30, 0x1c, 0xcc, 0xec, 0xba, 0x48, 0x5a,
        0x47, 0x43, 0x63, 0xc1, 0x80, 0xf5, 0x3c, 0x00, 0x55, 0x86, 0xb0,
        0xcd, 0xd9, 0x2d, 0x1b, 0xda, 0xee, 0x7a, 0x7a, 0xc1, 0x2f, 0xf9,
        0x83, 0xf2, 0x1d, 0x37, 0xf0, 0x67, 0x98, 0x8f, 0x2c, 0xdf, 0xbb,
        0xea, 0x7b, 0x63, 0xf7, 0x4e, 0xdb, 0x87, 0x08, 0x90, 0xd6, 0x3b,
        0xde, 0x61, 0x37, 0xad, 0x66, 0x21, 0x9c, 0xd1, 0x17
    };
    const uint8_t TAG256[16] = {
        0xe1, 0x01, 0x06, 0xae, 0xbe, 0x26, 0x0c, 0xc5,
        0xb9, 0x51, 0x45, 0x39, 0x2a, 0xce, 0x02, 0x37
    };
    const uint8_t KEY192[24] = {
        0xa9, 0xea, 0x0e, 0x75, 0x5a, 0x5c, 0x2e, 0x82, 0x10, 0x24, 0x2a, 0x08,
        0xe7, 0x07, 0x8f, 0x7f, 0x89, 0x38, 0x5e, 0xb0, 0x94, 0x23, 0x55, 0x51
    };
    const uint8_t OUT192[64] = {
        0xf6, 0x5e, 0xe8, 0xe4, 0x45, 0xfe, 0x27, 0x84, 0x0d, 0x66, 0xff,
        0x45, 0x30, 0x2f, 0x27, 0xf0, 0xb5, 0xfb, 0xf6, 0xd0, 0xb0, 0x57,
        0xb7, 0xea, 0xd3, 0xbb, 0x09, 0x62, 0x0b, 0x35, 0xf6, 0x51, 0xae,
        0x86, 0x49, 0xb3, 0x51, 0x31, 0x77, 0xe4, 0xff, 0x07, 0x3f, 0x1d,
        0x35, 0xb0, 0x14, 0x5c, 0x50, 0x74, 0x84, 0x30, 0xbe, 0x67, 0x4b,
        0x64, 0x94, 0x0d, 0xa5, 0xda, 0x07, 0x14, 0x96, 0xcc
    };
    const uint8_t TAG192[16] = {
        0x3a, 0xf9, 0xa6, 0x56, 0x7c, 0x17, 0x32, 0x1d,
        0x7e, 0x91, 0xb2, 0xc7, 0xde, 0xcc, 0x15, 0x5f
    };
    const uint8_t KEY128[16] = {
        0x82, 0x56, 0x8b, 0x96, 0xe8, 0xa4, 0xfe, 0xf2,
        0x3a, 0x0c, 0x9f, 0xc5, 0xaf, 0xd7, 0x60, 0x84
    };
    const uint8_t OUT128[64] = {
        0xab, 0x77, 0x29, 0x3a, 0xf7, 0x8a, 0x1f, 0x03, 0x6d, 0x19, 0xc2,
        0x76, 0x76, 0xb1, 0xb7, 0xa3, 0x7c, 0xa5, 0xe9, 0x90, 0x75, 0x47,
        0xcd, 0x6a, 0x5a, 0x51, 0xf5, 0x7a, 0xb9, 0xa2, 0x2a, 0x23, 0x39,
        0x90, 0x9b, 0x7f, 0xe0, 0xa4, 0xd5, 0x7c, 0x65, 0x23, 0xf1, 0x03,
        0x12, 0xbc, 0x90, 0x10, 0xab, 0xc5, 0x2d, 0x7b, 0xf2, 0xa7, 0x4b,
        0x66, 0x9c, 0x80, 0x36, 0x8a, 0x40, 0xf9, 0xcb, 0x51
    };
    const uint8_t TAG128[16] = {
        0x25, 0x95, 0x7a, 0x23, 0xff, 0xf0, 0x34, 0x1a,
        0x78, 0xa5, 0xec, 0xf4, 0x65, 0x08, 0x8f, 0xbc
    };
    const uint8_t IN[64] = { 0x44, 0x20, 0x82, 0x3c, 0xfd, 0xe6, 0xf1, 0xc2,
                             0x6b, 0x30, 0xf9, 0x0e, 0xc7, 0xdd, 0x01, 0xe4,
                             0x88, 0x75, 0x34, 0xa2, 0x0f, 0x0b, 0x0d, 0x04,
                             0xc3, 0x6e, 0xd8, 0x0e, 0x71, 0xe0, 0xfd, 0x77,
                             0xb0, 0x76, 0x70, 0xeb, 0x94, 0x0b, 0xd5, 0x33,
                             0x5f, 0x97, 0x3d, 0xaa, 0xd8, 0x61, 0x9b, 0x91,
                             0xff, 0xc9, 0x11, 0xf5, 0x7c, 0xce, 0xd4, 0x58,
                             0xbb, 0xbf, 0x2c, 0xe0, 0x37, 0x53, 0xc9, 0xbd };
    const uint8_t NONCE[11] = { 0x37, 0x81, 0x6b, 0xdd, 0x0a, 0x73,
                                0x09, 0xcb, 0x4a, 0x12, 0x52 };
    TestCcmCase(KEY256,
                sizeof(KEY256),
                NONCE,
                sizeof(NONCE),
                IN,
                OUT256,
                sizeof(IN),
                TAG256,
                sizeof(TAG256));
    TestCcmCase(KEY192,
                sizeof(KEY192),
                NONCE,
                sizeof(NONCE),
                IN,
                OUT192,
                sizeof(IN),
                TAG192,
                sizeof(TAG192));
    TestCcmCase(KEY128,
                sizeof(KEY128),
                NONCE,
                sizeof(NONCE),
                IN,
                OUT128,
                sizeof(IN),
                TAG128,
                sizeof(TAG128));
}

static void TestCcmWithAadCase(const uint8_t *KEY,
                               size_t key_len,
                               const uint8_t *NONCE,
                               size_t nonce_len,
                               const uint8_t *AAD,
                               size_t aad_len,
                               const uint8_t *IN,
                               const uint8_t *OUT,
                               size_t data_len,
                               const uint8_t *TAG,
                               size_t tag_len)
{
    uint8_t tag_out[16];
    uint8_t result[data_len];
    UAES_CCM_Ctx_t ctx;
    // Test encryption at once
    UAES_CCM_Init(&ctx,
                  KEY,
                  key_len,
                  NONCE,
                  nonce_len,
                  aad_len,
                  data_len,
                  tag_len);
    UAES_CCM_AddAad(&ctx, AAD, aad_len);
    UAES_CCM_Encrypt(&ctx, IN, result, data_len);
    UAES_CCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
    CheckDataAndTag(OUT,
                    result,
                    data_len,
                    TAG,
                    tag_out,
                    tag_len,
                    "UAES_CCM_Encrypt");
    UAES_CCM_SimpleEncrypt(KEY,
                           key_len,
                           NONCE,
                           nonce_len,
                           AAD,
                           aad_len,
                           IN,
                           result,
                           data_len,
                           tag_out,
                           tag_len);
    CheckDataAndTag(OUT,
                    result,
                    data_len,
                    TAG,
                    tag_out,
                    tag_len,
                    "UAES_SimpleEncrypt");
    // Test encryption by random chunks
    UAES_CCM_Init(&ctx,
                  KEY,
                  key_len,
                  NONCE,
                  nonce_len,
                  aad_len,
                  data_len,
                  tag_len);
    size_t pos = 0u;
    while (pos < aad_len) {
        size_t chunk = (size_t)rand() % (aad_len - pos);
        if (chunk > 24u) {
            chunk = 24u;
        }
        if (chunk == 0u) {
            chunk = 1u;
        }
        UAES_CCM_AddAad(&ctx, &AAD[pos], chunk);
        pos += chunk;
    }
    pos = 0u;
    while (pos < data_len) {
        size_t chunk = (size_t)rand() % (data_len - pos);
        if (chunk > 24u) {
            chunk = 24u;
        }
        if (chunk == 0u) {
            chunk = 1u;
        }
        UAES_CCM_Encrypt(&ctx, &IN[pos], &result[pos], chunk);
        pos += chunk;
    }
    UAES_CCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
    CheckDataAndTag(OUT,
                    result,
                    data_len,
                    TAG,
                    tag_out,
                    tag_len,
                    "UAES_CCM_Encrypt");
    // Test decryption at once
    UAES_CCM_Init(&ctx,
                  KEY,
                  key_len,
                  NONCE,
                  nonce_len,
                  aad_len,
                  data_len,
                  tag_len);
    UAES_CCM_AddAad(&ctx, AAD, aad_len);
    (void)memcpy(result, OUT, data_len);
    UAES_CCM_Decrypt(&ctx, result, result, data_len);
    // This is an intended call to make sure calling UAES_CCM_VerifyTag
    // after UAES_CCM_GenerateTag works correctly.
    UAES_CCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
    CheckDataAndTag(IN,
                    result,
                    data_len,
                    TAG,
                    tag_out,
                    tag_len,
                    "UAES_CCM_Decrypt");
    if (!UAES_CCM_SimpleDecrypt(KEY,
                                key_len,
                                NONCE,
                                nonce_len,
                                AAD,
                                aad_len,
                                OUT,
                                result,
                                data_len,
                                TAG,
                                tag_len)) {
        PRINTF("UAES_CCM_SimpleDecrypt failed at verifying\n");
    } else {
        CheckData(IN, result, data_len, "UAES_CCM_SimpleDecrypt");
    }
    // Test decryption by random chunks
    UAES_CCM_Init(&ctx,
                  KEY,
                  key_len,
                  NONCE,
                  nonce_len,
                  aad_len,
                  data_len,
                  tag_len);
    pos = 0u;
    while (pos < aad_len) {
        size_t chunk = (size_t)rand() % (aad_len - pos);
        if (chunk > 24u) {
            chunk = 24u;
        }
        if (chunk == 0u) {
            chunk = 1u;
        }
        UAES_CCM_AddAad(&ctx, &AAD[pos], chunk);
        pos += chunk;
    }
    (void)memcpy(result, OUT, data_len);
    pos = 0u;
    while (pos < data_len) {
        size_t chunk = (size_t)rand() % (data_len - pos);
        if (chunk > 24u) {
            chunk = 24u;
        }
        if (chunk == 0u) {
            chunk = 1u;
        }
        UAES_CCM_Decrypt(&ctx, &OUT[pos], &result[pos], chunk);
        pos += chunk;
    }
    UAES_CCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
}

static void TestCcmWithAad(void)
{
    const uint8_t KEY128[16] = {
        0xeb, 0xba, 0x24, 0x46, 0x3f, 0xce, 0xef, 0xf8,
        0x5d, 0xdd, 0xb3, 0xb7, 0x3f, 0xb5, 0x2c, 0x77,
    };
    const uint8_t OUT128[64] = {
        0xb0, 0xf4, 0x38, 0x71, 0xa0, 0x9f, 0x40, 0x5b, 0x3a, 0x10, 0x4e,
        0xb4, 0x6e, 0x3a, 0x10, 0x4a, 0xe5, 0x7b, 0x03, 0x09, 0xfe, 0x5d,
        0x51, 0x2d, 0x87, 0xce, 0xf6, 0x93, 0x0c, 0x3a, 0xe6, 0x35, 0x02,
        0x28, 0x2c, 0x94, 0xda, 0x30, 0x40, 0xf0, 0x26, 0xdc, 0xdf, 0x7c,
        0x46, 0x5f, 0xa9, 0x3b, 0x90, 0xce, 0x95, 0xf8, 0x34, 0x76, 0x03,
        0x33, 0xd6, 0xca, 0xa8, 0x88, 0x2c, 0xa0, 0x0b, 0x09,
    };
    const uint8_t TAG128[16] = {
        0x05, 0x68, 0xbc, 0x82, 0x6c, 0x5d, 0x66, 0xaa,
        0x38, 0xa7, 0x0c, 0xd9, 0xd8, 0xd5, 0x64, 0x58,
    };
    const uint8_t KEY192[24] = {
        0xde, 0xc3, 0xca, 0xf5, 0x38, 0xc1, 0xfe, 0x10, 0x81, 0xba, 0x60, 0x5a,
        0x45, 0x13, 0x73, 0x36, 0xa2, 0x36, 0x53, 0xa1, 0x3e, 0xd4, 0x19, 0xb4,
    };
    const uint8_t OUT192[64] = {
        0x66, 0xa5, 0x85, 0x70, 0x76, 0xf1, 0xa4, 0x31, 0x5d, 0xb5, 0x18,
        0x11, 0xa9, 0xca, 0x1b, 0xc8, 0x47, 0x99, 0x83, 0x34, 0x04, 0x46,
        0x23, 0xbf, 0x1f, 0xf5, 0xbf, 0x55, 0x52, 0x66, 0xdb, 0x29, 0xa4,
        0xea, 0xe5, 0x0e, 0xf3, 0xab, 0xa6, 0xf9, 0xc1, 0x34, 0xe5, 0x1c,
        0x87, 0xaa, 0xb4, 0x70, 0x3a, 0x25, 0x54, 0x0d, 0xcb, 0xa6, 0x46,
        0x68, 0xe6, 0xb2, 0x86, 0x3e, 0xd5, 0x76, 0x90, 0x3a,
    };
    const uint8_t TAG192[16] = {
        0x9a, 0x91, 0xb2, 0xd1, 0xdf, 0xfc, 0xe6, 0x5f,
        0x96, 0x07, 0xc3, 0xa5, 0x4f, 0x54, 0x5c, 0xab,
    };
    const uint8_t KEY256[32] = {
        0xb2, 0xdb, 0x74, 0xb1, 0x92, 0x0a, 0xdc, 0x00, 0x5e, 0x74, 0x23,
        0x29, 0x19, 0xcc, 0x8b, 0x3c, 0x82, 0x95, 0x17, 0x9b, 0x98, 0xe1,
        0xfe, 0x05, 0xd9, 0xca, 0xbd, 0xf0, 0x91, 0xd5, 0x07, 0xc4,
    };
    const uint8_t OUT256[64] = {
        0xbb, 0xf6, 0x7a, 0xa6, 0x22, 0xed, 0xe6, 0x99, 0x12, 0x28, 0x54,
        0x81, 0xeb, 0x6e, 0xff, 0x6c, 0x06, 0x06, 0x65, 0x54, 0xf2, 0xa8,
        0x08, 0x7a, 0x00, 0x3d, 0x57, 0x99, 0x77, 0xa5, 0x42, 0x7e, 0x76,
        0xd3, 0xfc, 0x0e, 0x11, 0xa5, 0x8c, 0x05, 0xe0, 0x8e, 0xb7, 0x47,
        0x83, 0x37, 0x9e, 0x49, 0x0a, 0x36, 0xca, 0xcd, 0x07, 0x39, 0x1e,
        0x9e, 0x3f, 0x4a, 0x5c, 0xd5, 0xf7, 0x7d, 0xf6, 0x14,
    };
    const uint8_t TAG256[16] = {
        0x6e, 0xd6, 0xff, 0xe1, 0x5f, 0x5c, 0x18, 0x98,
        0x8e, 0x56, 0xcf, 0xb9, 0x69, 0x9d, 0xaf, 0x98,
    };
    const uint8_t AAD[64] = {
        0x05, 0xa4, 0xe3, 0xda, 0x8e, 0xc7, 0x1e, 0x3f, 0x0f, 0x0e, 0x9a,
        0x66, 0xae, 0x9a, 0x62, 0xc7, 0x36, 0x16, 0x36, 0x44, 0x48, 0xb2,
        0x29, 0xca, 0xa0, 0xe8, 0xb1, 0x5d, 0x95, 0xec, 0x7c, 0x5c, 0x12,
        0x22, 0xc4, 0x3f, 0xad, 0x66, 0xd3, 0x19, 0x9e, 0x81, 0x4a, 0x7f,
        0x17, 0x02, 0xb6, 0xfc, 0x6f, 0x4f, 0x26, 0x50, 0xa8, 0x3a, 0xb3,
        0x9e, 0x80, 0x5b, 0x4c, 0x8b, 0x1d, 0x06, 0x24, 0xa7,
    };
    const uint8_t IN[64] = {
        0x2d, 0x12, 0xbb, 0x15, 0x7d, 0xf9, 0x2c, 0x7b, 0xb0, 0x5e, 0x3e,
        0x72, 0x40, 0xde, 0xff, 0x33, 0x7b, 0x40, 0x64, 0x76, 0x16, 0x87,
        0x8f, 0x35, 0x23, 0x6b, 0xf2, 0x87, 0xbc, 0xd3, 0xa1, 0xa3, 0x7a,
        0x67, 0xe1, 0x45, 0xe1, 0x65, 0x49, 0xb5, 0x60, 0x26, 0x3a, 0x08,
        0x8c, 0x16, 0xe2, 0xb4, 0x60, 0xb2, 0x95, 0xe9, 0x74, 0x15, 0x76,
        0x68, 0xe1, 0x2d, 0x42, 0x9a, 0xe1, 0xca, 0x50, 0x41,
    };
    const uint8_t NONCE[11] = {
        0xa1, 0xbb, 0x1b, 0x5c, 0x3f, 0x51, 0xc6, 0x20, 0x8a, 0x68, 0x4c,
    };
    TestCcmWithAadCase(KEY128,
                       sizeof(KEY128),
                       NONCE,
                       sizeof(NONCE),
                       AAD,
                       sizeof(AAD),
                       IN,
                       OUT128,
                       sizeof(IN),
                       TAG128,
                       sizeof(TAG128));
    TestCcmWithAadCase(KEY192,
                       sizeof(KEY192),
                       NONCE,
                       sizeof(NONCE),
                       AAD,
                       sizeof(AAD),
                       IN,
                       OUT192,
                       sizeof(IN),
                       TAG192,
                       sizeof(TAG192));
    TestCcmWithAadCase(KEY256,
                       sizeof(KEY256),
                       NONCE,
                       sizeof(NONCE),
                       AAD,
                       sizeof(AAD),
                       IN,
                       OUT256,
                       sizeof(IN),
                       TAG256,
                       sizeof(TAG256));
}

#endif // UAES_ENABLE_CCM

#if UAES_ENABLE_GCM

static void TestGcmCase(const uint8_t *KEY,
                        size_t key_len,
                        const uint8_t *IV,
                        size_t iv_len,
                        const uint8_t *AAD,
                        size_t aad_len,
                        const uint8_t *PT,
                        const uint8_t *CT,
                        size_t data_len,
                        const uint8_t *TAG,
                        size_t tag_len)
{
    UAES_GCM_Ctx_t ctx;
    uint8_t result[data_len];
    uint8_t tag_out[16];
    // Test encryption at once
    UAES_GCM_Init(&ctx, KEY, key_len, IV, iv_len);
    UAES_GCM_AddAad(&ctx, AAD, aad_len);
    UAES_GCM_Encrypt(&ctx, PT, result, data_len);
    UAES_GCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
    CheckDataAndTag(CT,
                    result,
                    data_len,
                    TAG,
                    tag_out,
                    tag_len,
                    "UAES_GCM_Encrypt");
    UAES_GCM_SimpleEncrypt(KEY,
                           key_len,
                           IV,
                           iv_len,
                           AAD,
                           aad_len,
                           PT,
                           result,
                           data_len,
                           tag_out,
                           sizeof(tag_out));
    CheckDataAndTag(CT,
                    result,
                    data_len,
                    TAG,
                    tag_out,
                    tag_len,
                    "UAES_GCM_SimpleEncrypt");
    // Test encryption by random chunks
    UAES_GCM_Init(&ctx, KEY, key_len, IV, iv_len);
    UAES_GCM_AddAad(&ctx, AAD, aad_len);
    size_t pos = 0u;
    while (pos < data_len) {
        size_t chunk = (size_t)rand() % (data_len - pos);
        if (chunk > 24u) {
            chunk = 24u;
        }
        if (chunk == 0u) {
            chunk = 1u;
        }
        UAES_GCM_Encrypt(&ctx, &PT[pos], &result[pos], chunk);
        pos += chunk;
    }
    UAES_GCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
    CheckDataAndTag(CT,
                    result,
                    data_len,
                    TAG,
                    tag_out,
                    tag_len,
                    "UAES_GCM_Encrypt");
    // Test decryption at once
    UAES_GCM_Init(&ctx, KEY, key_len, IV, iv_len);
    UAES_GCM_AddAad(&ctx, AAD, aad_len);
    (void)memcpy(result, CT, data_len);
    UAES_GCM_Decrypt(&ctx, result, result, data_len);
    // This is an intended call to make sure multiple calls to
    // UAES_GCM_VerifyTag works correctly.
    UAES_GCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
    CheckDataAndTag(PT,
                    result,
                    data_len,
                    TAG,
                    tag_out,
                    tag_len,
                    "UAES_GCM_Decrypt");
    if (!UAES_GCM_SimpleDecrypt(KEY,
                                key_len,
                                IV,
                                iv_len,
                                AAD,
                                aad_len,
                                CT,
                                result,
                                data_len,
                                TAG,
                                tag_len)) {
        PRINTF("UAES_GCM_SimpleDecrypt failed at verifying\n");
    } else {
        CheckData(PT, result, data_len, "UAES_GCM_SimpleDecrypt");
    }
    // Test decryption by random chunks
    UAES_GCM_Init(&ctx, KEY, key_len, IV, iv_len);
    UAES_GCM_AddAad(&ctx, AAD, aad_len);
    (void)memcpy(result, CT, data_len);
    pos = 0u;
    while (pos < data_len) {
        size_t chunk = (size_t)rand() % (data_len - pos);
        if (chunk > 24u) {
            chunk = 24u;
        }
        if (chunk == 0u) {
            chunk = 1u;
        }
        UAES_GCM_Decrypt(&ctx, &CT[pos], &result[pos], chunk);
        pos += chunk;
    }
    UAES_GCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
    CheckDataAndTag(PT,
                    result,
                    data_len,
                    TAG,
                    tag_out,
                    tag_len,
                    "UAES_GCM_Decrypt");
}

static void TestGcm(void)
{
    const uint8_t KEY128[16] = {
        0xfb, 0x72, 0xa0, 0x0d, 0x02, 0x60, 0xd6, 0x7c,
        0x28, 0x8a, 0x92, 0xd1, 0xba, 0x74, 0x6c, 0x93,
    };

    const uint8_t CT128[16] = {
        0x1a, 0x9b, 0x61, 0xd4, 0x45, 0x32, 0xf7, 0x06,
        0x77, 0x0b, 0xed, 0x79, 0x6a, 0x70, 0x61, 0x20,
    };

    const uint8_t TAG128[16] = {
        0xcc, 0x0a, 0x19, 0xc5, 0x20, 0x03, 0x68, 0xeb,
        0x5e, 0xcd, 0x25, 0x25, 0xfe, 0x33, 0x5d, 0xb4,
    };

    const uint8_t CT2_128[16] = {
        0x80, 0x22, 0xf0, 0x62, 0x88, 0x95, 0xc4, 0xab,
        0x41, 0x2e, 0x47, 0x96, 0xe9, 0x7e, 0x56, 0x61,
    };

    const uint8_t TAG2_128[16] = {
        0xe6, 0x40, 0x23, 0x79, 0x5e, 0x9d, 0x3f, 0x00,
        0x2d, 0x0d, 0x55, 0x83, 0x6d, 0x4d, 0x68, 0xfb,
    };

    const uint8_t KEY192[24] = {
        0xfc, 0xbb, 0xe8, 0x53, 0xee, 0x19, 0x6f, 0xf9, 0x36, 0x3c, 0xb9, 0xfd,
        0x57, 0x79, 0x21, 0x25, 0x52, 0xb9, 0x24, 0xef, 0x2f, 0x03, 0x4a, 0x6f,
    };

    const uint8_t CT192[16] = {
        0x0f, 0xf7, 0xc5, 0x5d, 0x37, 0xb6, 0xce, 0x83,
        0x98, 0x79, 0xb6, 0x69, 0xa8, 0x48, 0xd4, 0x7e,
    };

    const uint8_t TAG192[16] = {
        0x05, 0xd1, 0xda, 0x84, 0xec, 0x70, 0x3e, 0xe6,
        0x48, 0x2e, 0xce, 0x80, 0xd2, 0xb1, 0x63, 0xbe,
    };

    const uint8_t CT2_192[16] = {
        0xb7, 0x76, 0x3b, 0x1f, 0xbf, 0xd3, 0x0c, 0xf0,
        0xd0, 0x58, 0xf8, 0xdd, 0xe6, 0x03, 0x78, 0x08,
    };

    const uint8_t TAG2_192[16] = {
        0x1c, 0x80, 0xf8, 0x0b, 0x0c, 0xc4, 0xa5, 0x33,
        0xd0, 0xeb, 0xf7, 0xc5, 0xf3, 0xa8, 0x92, 0x81,
    };

    const uint8_t KEY256[32] = {
        0x47, 0x04, 0x80, 0x96, 0x9e, 0x68, 0x4a, 0xb7, 0x9d, 0x0d, 0x81,
        0xe8, 0x7f, 0xc8, 0xd1, 0x9c, 0xca, 0xf6, 0x22, 0x1e, 0xe3, 0x1e,
        0xf8, 0x63, 0x54, 0xab, 0xa1, 0xec, 0x11, 0x35, 0xc7, 0x43,
    };

    const uint8_t CT256[16] = {
        0xce, 0x8b, 0x56, 0xb0, 0x1a, 0x8d, 0x56, 0xaf,
        0x62, 0xab, 0x21, 0xca, 0xd7, 0xa7, 0x38, 0xcf,
    };

    const uint8_t TAG256[16] = {
        0xad, 0x9d, 0x54, 0x50, 0x84, 0x91, 0x0e, 0xd2,
        0x75, 0xa8, 0xc0, 0x49, 0xd6, 0x49, 0x69, 0xed,
    };

    const uint8_t CT2_256[16] = {
        0xac, 0x47, 0xc8, 0x7a, 0x75, 0xe2, 0xff, 0x03,
        0xfc, 0xe5, 0x4d, 0x5c, 0x98, 0x13, 0x1b, 0xc4,
    };

    const uint8_t TAG2_256[16] = {
        0x8a, 0xf5, 0xb3, 0xfd, 0xe2, 0x05, 0xbc, 0x3c,
        0xa6, 0x76, 0xb8, 0xbe, 0x8e, 0x87, 0x64, 0xb7,
    };
    const uint8_t AAD[16] = {
        0x8a, 0xc2, 0x83, 0x7f, 0xe6, 0x44, 0xa0, 0xc6,
        0x47, 0x29, 0x1a, 0xb2, 0xc5, 0x6c, 0xb0, 0x10,
    };

    const uint8_t PT[16] = {
        0xec, 0xd0, 0xa6, 0x3c, 0xf6, 0x26, 0xd6, 0x41,
        0x9a, 0x0a, 0xaa, 0xe7, 0xa4, 0x16, 0xfe, 0x49,
    };

    const uint8_t IV[12] = {
        0x68, 0xc6, 0xe7, 0xc1, 0xb6, 0xdd, 0x68, 0xdb, 0x63, 0x08, 0xee, 0x55,
    };

    const uint8_t IV2[30] = {
        0x3f, 0xb3, 0xaf, 0x1e, 0x15, 0xd6, 0xf1, 0xc1, 0x54, 0x85,
        0xf8, 0xcb, 0xa6, 0x77, 0xae, 0x29, 0x5f, 0x8e, 0x61, 0x1e,
        0x37, 0x7c, 0xba, 0x0b, 0x97, 0xcd, 0x72, 0xb9, 0x32, 0x5b,
    };
    TestGcmCase(KEY128,
                sizeof(KEY128),
                IV,
                sizeof(IV),
                AAD,
                sizeof(AAD),
                PT,
                CT128,
                sizeof(PT),
                TAG128,
                sizeof(TAG128));
    TestGcmCase(KEY128,
                sizeof(KEY128),
                IV2,
                sizeof(IV2),
                AAD,
                sizeof(AAD),
                PT,
                CT2_128,
                sizeof(PT),
                TAG2_128,
                sizeof(TAG2_128));
    TestGcmCase(KEY192,
                sizeof(KEY192),
                IV,
                sizeof(IV),
                AAD,
                sizeof(AAD),
                PT,
                CT192,
                sizeof(PT),
                TAG192,
                sizeof(TAG192));
    TestGcmCase(KEY192,
                sizeof(KEY192),
                IV2,
                sizeof(IV2),
                AAD,
                sizeof(AAD),
                PT,
                CT2_192,
                sizeof(PT),
                TAG2_192,
                sizeof(TAG2_192));
    TestGcmCase(KEY256,
                sizeof(KEY256),
                IV,
                sizeof(IV),
                AAD,
                sizeof(AAD),
                PT,
                CT256,
                sizeof(PT),
                TAG256,
                sizeof(TAG256));
    TestGcmCase(KEY256,
                sizeof(KEY256),
                IV2,
                sizeof(IV2),
                AAD,
                sizeof(AAD),
                PT,
                CT2_256,
                sizeof(PT),
                TAG2_256,
                sizeof(TAG2_256));
}

#endif // UAES_ENABLE_GCM

int main(void)
{
    s_failure_num = 0u;
#if UAES_ENABLE_ECB
    TestECB();
#endif
#if UAES_ENABLE_CBC
    TestCBC();
#endif
#if UAES_ENABLE_CTR
    TestCtr();
#endif
#if UAES_ENABLE_CCM
    TestCcm();
    TestCcmWithAad();
#endif
#if UAES_ENABLE_GCM
    TestGcm();
#endif
    PRINTF("Success: %zu, failure: %zu\n", s_success_num, s_failure_num);
    return (int)s_failure_num;
}
