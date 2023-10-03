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

static void PrintArray(const uint8_t *array, uint8_t size)
{
    for (uint8_t i = 0u; i < size; i++) {
        (void)printf("%02x ", array[i]);
    }
    (void)printf("\n");
}

#if UAES_ENABLE_ECB
static uint8_t TestECB(void)
{
#if TEST_KEY_SIZE == 256u
    uint8_t const KEY[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t const OUT[] = { 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
                            0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8 };
#elif TEST_KEY_SIZE == 192u
    uint8_t const KEY[] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                            0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                            0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
    uint8_t const OUT[] = { 0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
                            0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc };
#elif TEST_KEY_SIZE == 128u
    uint8_t const KEY[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t const OUT[] = { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
                            0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 };
#endif

    uint8_t const IN[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                           0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    uint8_t failure = 0u;
    UAES_ECB_Ctx_t ctx;
    UAES_ECB_Init(&ctx, KEY, sizeof(KEY));
    uint8_t result[16];
#if UAES_ENABLE_ECB_ENCRYPT
    UAES_ECB_Encrypt(&ctx, IN, result, sizeof(IN));
    if (memcmp(OUT, result, 16u) != 0) {
        (void)printf("UAES_ECB_Encrypt failed\n");
        PrintArray(OUT, sizeof(OUT));
        PrintArray(result, sizeof(result));
        failure++;
    } else {
        (void)printf("UAES_ECB_Encrypt passed\n");
    }
#endif // UAES_ENABLE_ECB_ENCRYPT
#if UAES_ENABLE_ECB_DECRYPT
    UAES_ECB_Decrypt(&ctx, OUT, result, sizeof(IN));
    if (memcmp(IN, result, sizeof(IN)) != 0) {
        (void)printf("UAES_ECB_Decrypt failed\n");
        PrintArray(IN, sizeof(IN));
        PrintArray(result, sizeof(result));
        failure++;
    } else {
        (void)printf("UAES_ECB_Decrypt passed\n");
    }
#endif // UAES_ENABLE_ECB_DECRYPT
    return failure;
}
#endif // UAES_ENABLE_ECB

#if UAES_ENABLE_CBC
static uint8_t TestCBC(void)
{
#if TEST_KEY_SIZE == 256u
    const uint8_t KEY[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    const uint8_t OUT[64u] = { 0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba,
                               0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
                               0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d,
                               0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
                               0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf,
                               0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
                               0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc,
                               0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b };
#elif TEST_KEY_SIZE == 192u
    const uint8_t KEY[] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                            0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                            0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
    const uint8_t OUT[64u] = { 0x4f, 0x02, 0x1d, 0xb2, 0x43, 0xbc, 0x63, 0x3d,
                               0x71, 0x78, 0x18, 0x3a, 0x9f, 0xa0, 0x71, 0xe8,
                               0xb4, 0xd9, 0xad, 0xa9, 0xad, 0x7d, 0xed, 0xf4,
                               0xe5, 0xe7, 0x38, 0x76, 0x3f, 0x69, 0x14, 0x5a,
                               0x57, 0x1b, 0x24, 0x20, 0x12, 0xfb, 0x7a, 0xe0,
                               0x7f, 0xa9, 0xba, 0xac, 0x3d, 0xf1, 0x02, 0xe0,
                               0x08, 0xb0, 0xe2, 0x79, 0x88, 0x59, 0x88, 0x81,
                               0xd9, 0x20, 0xa9, 0xe6, 0x4f, 0x56, 0x15, 0xcd };
#elif TEST_KEY_SIZE == 128u
    const uint8_t KEY[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    const uint8_t OUT[64u] = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
                               0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
                               0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
                               0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
                               0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b,
                               0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
                               0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09,
                               0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };
#endif
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
    UAES_CBC_Ctx_t ctx;
    uint8_t failure = 0u;
    uint8_t result[64u];
#if UAES_ENABLE_CBC_ENCRYPT
    UAES_CBC_Init(&ctx, KEY, sizeof(KEY), IV);
    (void)memcpy(result, IN, sizeof(IN));
    UAES_CBC_Encrypt(&ctx, result, result, sizeof(result));
    if (memcmp(OUT, result, sizeof(OUT)) != 0) {
        (void)printf("UAES_CBC_Encrypt failed\n");
        PrintArray(OUT, sizeof(OUT));
        PrintArray(result, sizeof(result));
        failure++;
    } else {
        (void)printf("UAES_CBC_Encrypt passed\n");
    }
#endif // UAES_ENABLE_CBC_ENCRYPT
#if UAES_ENABLE_CBC_DECRYPT
    UAES_CBC_Init(&ctx, KEY, sizeof(KEY), IV);
    (void)memcpy(result, OUT, sizeof(OUT));
    UAES_CBC_Decrypt(&ctx, result, result, sizeof(result));
    if (memcmp(IN, result, sizeof(IN)) != 0) {
        (void)printf("UAES_CBC_Decrypt failed\n");
        PrintArray(IN, sizeof(IN));
        PrintArray(result, sizeof(result));
        failure++;
    } else {
        (void)printf("UAES_CBC_Decrypt passed\n");
    }
#endif // UAES_ENABLE_CBC_DECRYPT
    return failure;
}
#endif // UAES_ENABLE_CBC

#if UAES_ENABLE_CTR
static uint8_t TestCtr(void)
{
#if TEST_KEY_SIZE == 256u
    const uint8_t KEY[32] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                              0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                              0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                              0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    const uint8_t OUT[64] = { 0xdf, 0x71, 0x89, 0xad, 0x91, 0x76, 0xb,  0x5e,
                              0x98, 0xdc, 0xac, 0x81, 0xb6, 0x29, 0x4,  0x8d,
                              0xbc, 0x72, 0xa2, 0xeb, 0x73, 0x27, 0xb8, 0x41,
                              0x79, 0x2e, 0xcd, 0x5e, 0x53, 0x60, 0xd1, 0xd3,
                              0x4a, 0x27, 0xc6, 0x9b, 0xa7, 0x92, 0x62, 0xb,
                              0x7b, 0xc,  0xd9, 0xa,  0x97, 0x7d, 0xa1, 0xb1,
                              0xfd, 0x6f, 0x32, 0xea, 0x95, 0x68, 0x1a, 0x79,
                              0xbe, 0xd6, 0x2d, 0x96, 0xfb, 0x65, 0x3d, 0x14 };
#elif TEST_KEY_SIZE == 192u
    const uint8_t KEY[24] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                              0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                              0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
    const uint8_t OUT[64] = { 0x2a, 0xb8, 0xbe, 0xe6, 0xa2, 0xb1, 0x44, 0x26,
                              0xc9, 0xcd, 0xea, 0xb4, 0x32, 0x20, 0xaa, 0x29,
                              0x53, 0x46, 0x97, 0x8,  0xf3, 0x44, 0x36, 0x4f,
                              0x33, 0x9a, 0xf8, 0xf7, 0x25, 0xe3, 0xa2, 0x41,
                              0x72, 0x76, 0x43, 0x7d, 0xf1, 0x40, 0xd2, 0x5c,
                              0x4b, 0x1e, 0xa1, 0x5a, 0x3b, 0x9d, 0xe2, 0x9f,
                              0xf3, 0x17, 0x1,  0x5d, 0x86, 0xce, 0x91, 0x2e,
                              0x22, 0xd2, 0xe4, 0xdb, 0xa6, 0xf3, 0xf1, 0xa7 };
#elif TEST_KEY_SIZE == 128u
    const uint8_t KEY[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                              0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    const uint8_t OUT[64] = { 0x67, 0xee, 0x5,  0x54, 0x74, 0x99, 0xf8, 0xbc,
                              0xf0, 0xc3, 0x83, 0x24, 0xe8, 0x60, 0x5c, 0x28,
                              0x1,  0x82, 0x16, 0xa5, 0xf4, 0xda, 0xc1, 0xaf,
                              0x7e, 0x12, 0xae, 0x7a, 0xc,  0x2e, 0x3e, 0x9f,
                              0x13, 0xe8, 0xbc, 0x4a, 0x37, 0x57, 0xa5, 0x48,
                              0x13, 0x98, 0x5,  0xcf, 0x95, 0x63, 0x14, 0xd,
                              0x2f, 0x88, 0x8d, 0x31, 0x4b, 0x55, 0x2b, 0x83,
                              0x96, 0x78, 0xe5, 0xf1, 0x2d, 0x56, 0xa9, 0x48 };
#endif
    const uint8_t NONCE[8u] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7 };
    const uint8_t IN[64] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                             0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                             0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                             0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                             0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                             0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                             0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                             0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
    uint8_t failure = 0u;
    uint8_t result[64u];
    UAES_CTR_Ctx_t ctx;

    // Encrypt whole array at once
    UAES_CTR_Init(&ctx, KEY, sizeof(KEY), NONCE, sizeof(NONCE));
    UAES_CTR_Encrypt(&ctx, IN, result, sizeof(IN));
    if (memcmp(OUT, result, sizeof(OUT)) != 0) {
        (void)printf("UAES_CTR_Encrypt failed\n");
        PrintArray(OUT, sizeof(OUT));
        PrintArray(result, sizeof(result));
        failure++;
    } else {
        (void)printf("UAES_CTR_Encrypt case 1 passed\n");
    }
    // Encrypt the array by random chunks
    UAES_CTR_Init(&ctx, KEY, sizeof(KEY), NONCE, sizeof(NONCE));
    size_t pos = 0u;
    while (pos < sizeof(IN)) {
        size_t chunk = (size_t)rand() % (sizeof(IN) - pos);
        if (chunk > 24u) {
            chunk = 24u;
        }
        if (chunk == 0u) {
            chunk = 1u;
        }
        UAES_CTR_Encrypt(&ctx, &IN[pos], &result[pos], chunk);
        pos += chunk;
    }
    if (memcmp(OUT, result, sizeof(OUT)) != 0) {
        (void)printf("UAES_CTR_Encrypt failed\n");
        PrintArray(OUT, sizeof(OUT));
        PrintArray(result, sizeof(result));
        failure++;
    } else {
        (void)printf("UAES_CTR_Encrypt case 2 passed\n");
    }
    // Decrypt whole array at once
    UAES_CTR_Init(&ctx, KEY, sizeof(KEY), NONCE, sizeof(NONCE));
    UAES_CTR_Decrypt(&ctx, OUT, result, sizeof(OUT));
    if (memcmp(IN, result, sizeof(IN)) != 0) {
        (void)printf("UAES_CTR_Decrypt failed\n");
        PrintArray(IN, sizeof(IN));
        PrintArray(result, sizeof(result));
        failure++;
    } else {
        (void)printf("UAES_CTR_Decrypt case 1 passed\n");
    }
    // Decrypt the array by random chunks
    UAES_CTR_Init(&ctx, KEY, sizeof(KEY), NONCE, sizeof(NONCE));
    pos = 0u;
    while (pos < sizeof(OUT)) {
        size_t chunk = (size_t)rand() % (sizeof(OUT) - pos);
        if (chunk > 24u) {
            chunk = 24u;
        }
        if (chunk == 0u) {
            chunk = 1u;
        }
        UAES_CTR_Decrypt(&ctx, &OUT[pos], &result[pos], chunk);
        pos += chunk;
    }
    if (memcmp(IN, result, sizeof(IN)) != 0) {
        (void)printf("UAES_CTR_Decrypt failed\n");
        PrintArray(IN, sizeof(IN));
        PrintArray(result, sizeof(result));
        failure++;
    } else {
        (void)printf("UAES_CTR_Decrypt case 2 passed\n");
    }
    return failure;
}

#endif // UAES_ENABLE_CTR

#if UAES_ENABLE_CCM

static uint8_t TestCcm(void)
{
#if TEST_KEY_SIZE == 256u
    const uint8_t KEY[32] = { 0xfa, 0x0f, 0xf0, 0x16, 0x9d, 0xc9, 0x57, 0x56,
                              0x74, 0x06, 0x66, 0x76, 0xcf, 0xb0, 0xb4, 0xeb,
                              0x89, 0x02, 0xc4, 0x42, 0x69, 0xda, 0x1c, 0xf6,
                              0xba, 0x66, 0xd3, 0xf8, 0xb6, 0xd4, 0xb1, 0x00 };
    const uint8_t OUT[64] = { 0xc6, 0xbf, 0x09, 0xfb, 0x30, 0x1c, 0xcc, 0xec,
                              0xba, 0x48, 0x5a, 0x47, 0x43, 0x63, 0xc1, 0x80,
                              0xf5, 0x3c, 0x00, 0x55, 0x86, 0xb0, 0xcd, 0xd9,
                              0x2d, 0x1b, 0xda, 0xee, 0x7a, 0x7a, 0xc1, 0x2f,
                              0xf9, 0x83, 0xf2, 0x1d, 0x37, 0xf0, 0x67, 0x98,
                              0x8f, 0x2c, 0xdf, 0xbb, 0xea, 0x7b, 0x63, 0xf7,
                              0x4e, 0xdb, 0x87, 0x08, 0x90, 0xd6, 0x3b, 0xde,
                              0x61, 0x37, 0xad, 0x66, 0x21, 0x9c, 0xd1, 0x17 };
    const uint8_t TAG[16] = { 0xe1, 0x01, 0x06, 0xae, 0xbe, 0x26, 0x0c, 0xc5,
                              0xb9, 0x51, 0x45, 0x39, 0x2a, 0xce, 0x02, 0x37 };
#elif TEST_KEY_SIZE == 192u
    const uint8_t KEY[24] = { 0xa9, 0xea, 0x0e, 0x75, 0x5a, 0x5c, 0x2e, 0x82,
                              0x10, 0x24, 0x2a, 0x08, 0xe7, 0x07, 0x8f, 0x7f,
                              0x89, 0x38, 0x5e, 0xb0, 0x94, 0x23, 0x55, 0x51 };
    const uint8_t OUT[64] = { 0xf6, 0x5e, 0xe8, 0xe4, 0x45, 0xfe, 0x27, 0x84,
                              0x0d, 0x66, 0xff, 0x45, 0x30, 0x2f, 0x27, 0xf0,
                              0xb5, 0xfb, 0xf6, 0xd0, 0xb0, 0x57, 0xb7, 0xea,
                              0xd3, 0xbb, 0x09, 0x62, 0x0b, 0x35, 0xf6, 0x51,
                              0xae, 0x86, 0x49, 0xb3, 0x51, 0x31, 0x77, 0xe4,
                              0xff, 0x07, 0x3f, 0x1d, 0x35, 0xb0, 0x14, 0x5c,
                              0x50, 0x74, 0x84, 0x30, 0xbe, 0x67, 0x4b, 0x64,
                              0x94, 0x0d, 0xa5, 0xda, 0x07, 0x14, 0x96, 0xcc };
    const uint8_t TAG[16] = { 0x3a, 0xf9, 0xa6, 0x56, 0x7c, 0x17, 0x32, 0x1d,
                              0x7e, 0x91, 0xb2, 0xc7, 0xde, 0xcc, 0x15, 0x5f };
#elif TEST_KEY_SIZE == 128u
    const uint8_t KEY[16] = { 0x82, 0x56, 0x8b, 0x96, 0xe8, 0xa4, 0xfe, 0xf2,
                              0x3a, 0x0c, 0x9f, 0xc5, 0xaf, 0xd7, 0x60, 0x84 };
    const uint8_t OUT[64] = { 0xab, 0x77, 0x29, 0x3a, 0xf7, 0x8a, 0x1f, 0x03,
                              0x6d, 0x19, 0xc2, 0x76, 0x76, 0xb1, 0xb7, 0xa3,
                              0x7c, 0xa5, 0xe9, 0x90, 0x75, 0x47, 0xcd, 0x6a,
                              0x5a, 0x51, 0xf5, 0x7a, 0xb9, 0xa2, 0x2a, 0x23,
                              0x39, 0x90, 0x9b, 0x7f, 0xe0, 0xa4, 0xd5, 0x7c,
                              0x65, 0x23, 0xf1, 0x03, 0x12, 0xbc, 0x90, 0x10,
                              0xab, 0xc5, 0x2d, 0x7b, 0xf2, 0xa7, 0x4b, 0x66,
                              0x9c, 0x80, 0x36, 0x8a, 0x40, 0xf9, 0xcb, 0x51 };
    const uint8_t TAG[16] = { 0x25, 0x95, 0x7a, 0x23, 0xff, 0xf0, 0x34, 0x1a,
                              0x78, 0xa5, 0xec, 0xf4, 0x65, 0x08, 0x8f, 0xbc };
#endif
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
    uint8_t tag_out[16];
    uint8_t result[64];
    UAES_CCM_Ctx_t ctx;
    uint8_t failure = 0u;
    // Test encryption at once
    UAES_CCM_Init(&ctx,
                  KEY,
                  sizeof(KEY),
                  NONCE,
                  sizeof(NONCE),
                  0u,
                  sizeof(IN),
                  sizeof(TAG));
    UAES_CCM_Encrypt(&ctx, IN, result, sizeof(IN));
    UAES_CCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
    if (memcmp(OUT, result, sizeof(OUT)) != 0) {
        (void)printf("UAES_CCM_Encrypt result error\n");
        PrintArray(OUT, sizeof(OUT));
        PrintArray(result, sizeof(result));
        failure++;
    } else if (memcmp(TAG, tag_out, sizeof(TAG)) != 0) {
        (void)printf("UAES_CCM_Encrypt tag error\n");
        PrintArray(TAG, sizeof(TAG));
        PrintArray(tag_out, sizeof(tag_out));
        failure++;
    } else {
        (void)printf("UAES_CCM_Encrypt case 1 passed\n");
    }
    // Test encryption by random chunks
    UAES_CCM_Init(&ctx,
                  KEY,
                  sizeof(KEY),
                  NONCE,
                  sizeof(NONCE),
                  0u,
                  sizeof(IN),
                  sizeof(TAG));
    size_t pos = 0u;
    while (pos < sizeof(IN)) {
        size_t chunk = (size_t)rand() % (sizeof(IN) - pos);
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
    if (memcmp(OUT, result, sizeof(OUT)) != 0) {
        (void)printf("UAES_CCM_Encrypt result error\n");
        PrintArray(OUT, sizeof(OUT));
        PrintArray(result, sizeof(result));
        failure++;
    } else if (memcmp(TAG, tag_out, sizeof(TAG)) != 0) {
        (void)printf("UAES_CCM_GenerateTag error\n");
        PrintArray(TAG, sizeof(TAG));
        PrintArray(tag_out, sizeof(tag_out));
        failure++;
    } else {
        (void)printf("UAES_CCM_Encrypt case 2 passed\n");
    }
    // Test decryption at once
    UAES_CCM_Init(&ctx,
                  KEY,
                  sizeof(KEY),
                  NONCE,
                  sizeof(NONCE),
                  0u,
                  sizeof(IN),
                  sizeof(TAG));
    // This is an intended call to make sure calling UAES_CCM_VerifyTag
    // after UAES_CCM_GenerateTag works correctly.
    (void)memcpy(result, OUT, sizeof(OUT));
    UAES_CCM_Decrypt(&ctx, result, result, sizeof(OUT));
    UAES_CCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
    if (memcmp(IN, result, sizeof(IN)) != 0) {
        (void)printf("UAES_CCM_Decrypt result error\n");
        PrintArray(IN, sizeof(IN));
        PrintArray(result, sizeof(result));
        failure++;
    } else if (!UAES_CCM_VerifyTag(&ctx, TAG, sizeof(TAG))) {
        (void)printf("UAES_CCM_VerifyTag failed\n");
        failure++;
    } else {
        (void)printf("UAES_CCM_Decrypt case 1 passed\n");
    }
    // Test decryption by random chunks
    UAES_CCM_Init(&ctx,
                  KEY,
                  sizeof(KEY),
                  NONCE,
                  sizeof(NONCE),
                  0u,
                  sizeof(IN),
                  sizeof(TAG));
    // This is an intended call to make sure calling UAES_CCM_VerifyTag
    // after UAES_CCM_GenerateTag works correctly.
    UAES_CCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
    (void)memcpy(result, OUT, sizeof(OUT));
    pos = 0u;
    while (pos < sizeof(OUT)) {
        size_t chunk = (size_t)rand() % (sizeof(OUT) - pos);
        if (chunk > 24u) {
            chunk = 24u;
        }
        if (chunk == 0u) {
            chunk = 1u;
        }
        UAES_CCM_Decrypt(&ctx, &OUT[pos], &result[pos], chunk);
        pos += chunk;
    }
    if (memcmp(IN, result, sizeof(IN)) != 0) {
        (void)printf("UAES_CCM_Decrypt result error\n");
        PrintArray(IN, sizeof(IN));
        PrintArray(result, sizeof(result));
        failure++;
    } else if (!UAES_CCM_VerifyTag(&ctx, TAG, sizeof(TAG))) {
        (void)printf("UAES_CCM_VerifyTag failed\n");
        failure++;
    } else {
        (void)printf("UAES_CCM_Decrypt case 2 passed\n");
    }
    return failure;
}

static uint8_t TestCcmWithAad(void)
{
#if TEST_KEY_SIZE == 128u
    const uint8_t KEY[16] = {
        0xeb, 0xba, 0x24, 0x46, 0x3f, 0xce, 0xef, 0xf8,
        0x5d, 0xdd, 0xb3, 0xb7, 0x3f, 0xb5, 0x2c, 0x77,
    };
    const uint8_t OUT[64] = {
        0xb0, 0xf4, 0x38, 0x71, 0xa0, 0x9f, 0x40, 0x5b, 0x3a, 0x10, 0x4e,
        0xb4, 0x6e, 0x3a, 0x10, 0x4a, 0xe5, 0x7b, 0x03, 0x09, 0xfe, 0x5d,
        0x51, 0x2d, 0x87, 0xce, 0xf6, 0x93, 0x0c, 0x3a, 0xe6, 0x35, 0x02,
        0x28, 0x2c, 0x94, 0xda, 0x30, 0x40, 0xf0, 0x26, 0xdc, 0xdf, 0x7c,
        0x46, 0x5f, 0xa9, 0x3b, 0x90, 0xce, 0x95, 0xf8, 0x34, 0x76, 0x03,
        0x33, 0xd6, 0xca, 0xa8, 0x88, 0x2c, 0xa0, 0x0b, 0x09,
    };
    const uint8_t TAG[16] = {
        0x05, 0x68, 0xbc, 0x82, 0x6c, 0x5d, 0x66, 0xaa,
        0x38, 0xa7, 0x0c, 0xd9, 0xd8, 0xd5, 0x64, 0x58,
    };
#elif TEST_KEY_SIZE == 192u
    const uint8_t KEY[24] = {
        0xde, 0xc3, 0xca, 0xf5, 0x38, 0xc1, 0xfe, 0x10, 0x81, 0xba, 0x60, 0x5a,
        0x45, 0x13, 0x73, 0x36, 0xa2, 0x36, 0x53, 0xa1, 0x3e, 0xd4, 0x19, 0xb4,
    };
    const uint8_t OUT[64] = {
        0x66, 0xa5, 0x85, 0x70, 0x76, 0xf1, 0xa4, 0x31, 0x5d, 0xb5, 0x18,
        0x11, 0xa9, 0xca, 0x1b, 0xc8, 0x47, 0x99, 0x83, 0x34, 0x04, 0x46,
        0x23, 0xbf, 0x1f, 0xf5, 0xbf, 0x55, 0x52, 0x66, 0xdb, 0x29, 0xa4,
        0xea, 0xe5, 0x0e, 0xf3, 0xab, 0xa6, 0xf9, 0xc1, 0x34, 0xe5, 0x1c,
        0x87, 0xaa, 0xb4, 0x70, 0x3a, 0x25, 0x54, 0x0d, 0xcb, 0xa6, 0x46,
        0x68, 0xe6, 0xb2, 0x86, 0x3e, 0xd5, 0x76, 0x90, 0x3a,
    };
    const uint8_t TAG[16] = {
        0x9a, 0x91, 0xb2, 0xd1, 0xdf, 0xfc, 0xe6, 0x5f,
        0x96, 0x07, 0xc3, 0xa5, 0x4f, 0x54, 0x5c, 0xab,
    };
#elif TEST_KEY_SIZE == 256u
    const uint8_t KEY[32] = {
        0xb2, 0xdb, 0x74, 0xb1, 0x92, 0x0a, 0xdc, 0x00, 0x5e, 0x74, 0x23,
        0x29, 0x19, 0xcc, 0x8b, 0x3c, 0x82, 0x95, 0x17, 0x9b, 0x98, 0xe1,
        0xfe, 0x05, 0xd9, 0xca, 0xbd, 0xf0, 0x91, 0xd5, 0x07, 0xc4,
    };
    const uint8_t OUT[64] = {
        0xbb, 0xf6, 0x7a, 0xa6, 0x22, 0xed, 0xe6, 0x99, 0x12, 0x28, 0x54,
        0x81, 0xeb, 0x6e, 0xff, 0x6c, 0x06, 0x06, 0x65, 0x54, 0xf2, 0xa8,
        0x08, 0x7a, 0x00, 0x3d, 0x57, 0x99, 0x77, 0xa5, 0x42, 0x7e, 0x76,
        0xd3, 0xfc, 0x0e, 0x11, 0xa5, 0x8c, 0x05, 0xe0, 0x8e, 0xb7, 0x47,
        0x83, 0x37, 0x9e, 0x49, 0x0a, 0x36, 0xca, 0xcd, 0x07, 0x39, 0x1e,
        0x9e, 0x3f, 0x4a, 0x5c, 0xd5, 0xf7, 0x7d, 0xf6, 0x14,
    };
    const uint8_t TAG[16] = {
        0x6e, 0xd6, 0xff, 0xe1, 0x5f, 0x5c, 0x18, 0x98,
        0x8e, 0x56, 0xcf, 0xb9, 0x69, 0x9d, 0xaf, 0x98,
    };
#endif
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
    uint8_t tag_out[16];
    uint8_t result[64];
    UAES_CCM_Ctx_t ctx;
    uint8_t failure = 0u;
    // Test encryption at once
    UAES_CCM_Init(&ctx,
                  KEY,
                  sizeof(KEY),
                  NONCE,
                  sizeof(NONCE),
                  sizeof(AAD),
                  sizeof(IN),
                  sizeof(TAG));
    UAES_CCM_AddAad(&ctx, AAD, sizeof(AAD));
    UAES_CCM_Encrypt(&ctx, IN, result, sizeof(IN));
    UAES_CCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
    if (memcmp(OUT, result, sizeof(OUT)) != 0) {
        (void)printf("UAES_CCM_Encrypt result error\n");
        PrintArray(OUT, sizeof(OUT));
        PrintArray(result, sizeof(result));
        failure++;
    } else if (memcmp(TAG, tag_out, sizeof(TAG)) != 0) {
        (void)printf("UAES_CCM_Encrypt tag error\n");
        PrintArray(TAG, sizeof(TAG));
        PrintArray(tag_out, sizeof(tag_out));
        failure++;
    } else {
        (void)printf("UAES_CCM_Encrypt case 3 passed\n");
    }
    // Test encryption by random chunks
    UAES_CCM_Init(&ctx,
                  KEY,
                  sizeof(KEY),
                  NONCE,
                  sizeof(NONCE),
                  sizeof(AAD),
                  sizeof(IN),
                  sizeof(TAG));
    size_t pos = 0u;
    while (pos < sizeof(AAD)) {
        size_t chunk = (size_t)rand() % (sizeof(AAD) - pos);
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
    while (pos < sizeof(IN)) {
        size_t chunk = (size_t)rand() % (sizeof(IN) - pos);
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
    if (memcmp(OUT, result, sizeof(OUT)) != 0) {
        (void)printf("UAES_CCM_Encrypt result error\n");
        PrintArray(OUT, sizeof(OUT));
        PrintArray(result, sizeof(result));
        failure++;
    } else if (memcmp(TAG, tag_out, sizeof(TAG)) != 0) {
        (void)printf("UAES_CCM_GenerateTag error\n");
        PrintArray(TAG, sizeof(TAG));
        PrintArray(tag_out, sizeof(tag_out));
        failure++;
    } else {
        (void)printf("UAES_CCM_Encrypt case 4 passed\n");
    }
    // Test decryption at once
    UAES_CCM_Init(&ctx,
                  KEY,
                  sizeof(KEY),
                  NONCE,
                  sizeof(NONCE),
                  sizeof(AAD),
                  sizeof(IN),
                  sizeof(TAG));
    UAES_CCM_AddAad(&ctx, AAD, sizeof(AAD));
    (void)memcpy(result, OUT, sizeof(OUT));
    UAES_CCM_Decrypt(&ctx, result, result, sizeof(OUT));
    // This is an intended call to make sure calling UAES_CCM_VerifyTag
    // after UAES_CCM_GenerateTag works correctly.
    UAES_CCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
    if (memcmp(IN, result, sizeof(IN)) != 0) {
        (void)printf("UAES_CCM_Decrypt result error\n");
        PrintArray(IN, sizeof(IN));
        PrintArray(result, sizeof(result));
        failure++;
    } else if (!UAES_CCM_VerifyTag(&ctx, TAG, sizeof(TAG))) {
        (void)printf("UAES_CCM_VerifyTag failed\n");
        failure++;
    } else {
        (void)printf("UAES_CCM_Decrypt case 3 passed\n");
    }
    // Test decryption by random chunks
    UAES_CCM_Init(&ctx,
                  KEY,
                  sizeof(KEY),
                  NONCE,
                  sizeof(NONCE),
                  sizeof(AAD),
                  sizeof(IN),
                  sizeof(TAG));
    pos = 0u;
    while (pos < sizeof(AAD)) {
        size_t chunk = (size_t)rand() % (sizeof(AAD) - pos);
        if (chunk > 24u) {
            chunk = 24u;
        }
        if (chunk == 0u) {
            chunk = 1u;
        }
        UAES_CCM_AddAad(&ctx, &AAD[pos], chunk);
        pos += chunk;
    }
    (void)memcpy(result, OUT, sizeof(OUT));
    pos = 0u;
    while (pos < sizeof(OUT)) {
        size_t chunk = (size_t)rand() % (sizeof(OUT) - pos);
        if (chunk > 24u) {
            chunk = 24u;
        }
        if (chunk == 0u) {
            chunk = 1u;
        }
        UAES_CCM_Decrypt(&ctx, &OUT[pos], &result[pos], chunk);
        pos += chunk;
    }
    if (memcmp(IN, result, sizeof(IN)) != 0) {
        (void)printf("UAES_CCM_Decrypt result error\n");
        PrintArray(IN, sizeof(IN));
        PrintArray(result, sizeof(result));
        failure++;
    } else if (!UAES_CCM_VerifyTag(&ctx, TAG, sizeof(TAG))) {
        (void)printf("UAES_CCM_VerifyTag failed\n");
        failure++;
    } else {
        (void)printf("UAES_CCM_Decrypt case 4 passed\n");
    }
    return failure;
}

#endif // UAES_ENABLE_CCM

#if UAES_ENABLE_GCM

static uint8_t TestGcm(void)
{
#if TEST_KEY_SIZE == 128u
    const uint8_t KEY[16] = {
        0xfb, 0x72, 0xa0, 0x0d, 0x02, 0x60, 0xd6, 0x7c,
        0x28, 0x8a, 0x92, 0xd1, 0xba, 0x74, 0x6c, 0x93,
    };

    const uint8_t CT[16] = {
        0x1a, 0x9b, 0x61, 0xd4, 0x45, 0x32, 0xf7, 0x06,
        0x77, 0x0b, 0xed, 0x79, 0x6a, 0x70, 0x61, 0x20,
    };

    const uint8_t TAG[16] = {
        0xcc, 0x0a, 0x19, 0xc5, 0x20, 0x03, 0x68, 0xeb,
        0x5e, 0xcd, 0x25, 0x25, 0xfe, 0x33, 0x5d, 0xb4,
    };

    const uint8_t CT2[16] = {
        0x80, 0x22, 0xf0, 0x62, 0x88, 0x95, 0xc4, 0xab,
        0x41, 0x2e, 0x47, 0x96, 0xe9, 0x7e, 0x56, 0x61,
    };

    const uint8_t TAG2[16] = {
        0xe6, 0x40, 0x23, 0x79, 0x5e, 0x9d, 0x3f, 0x00,
        0x2d, 0x0d, 0x55, 0x83, 0x6d, 0x4d, 0x68, 0xfb,
    };

#elif TEST_KEY_SIZE == 192u
    const uint8_t KEY[24] = {
        0xfc, 0xbb, 0xe8, 0x53, 0xee, 0x19, 0x6f, 0xf9, 0x36, 0x3c, 0xb9, 0xfd,
        0x57, 0x79, 0x21, 0x25, 0x52, 0xb9, 0x24, 0xef, 0x2f, 0x03, 0x4a, 0x6f,
    };

    const uint8_t CT[16] = {
        0x0f, 0xf7, 0xc5, 0x5d, 0x37, 0xb6, 0xce, 0x83,
        0x98, 0x79, 0xb6, 0x69, 0xa8, 0x48, 0xd4, 0x7e,
    };

    const uint8_t TAG[16] = {
        0x05, 0xd1, 0xda, 0x84, 0xec, 0x70, 0x3e, 0xe6,
        0x48, 0x2e, 0xce, 0x80, 0xd2, 0xb1, 0x63, 0xbe,
    };

    const uint8_t CT2[16] = {
        0xb7, 0x76, 0x3b, 0x1f, 0xbf, 0xd3, 0x0c, 0xf0,
        0xd0, 0x58, 0xf8, 0xdd, 0xe6, 0x03, 0x78, 0x08,
    };

    const uint8_t TAG2[16] = {
        0x1c, 0x80, 0xf8, 0x0b, 0x0c, 0xc4, 0xa5, 0x33,
        0xd0, 0xeb, 0xf7, 0xc5, 0xf3, 0xa8, 0x92, 0x81,
    };

#elif TEST_KEY_SIZE == 256u
    const uint8_t KEY[32] = {
        0x47, 0x04, 0x80, 0x96, 0x9e, 0x68, 0x4a, 0xb7, 0x9d, 0x0d, 0x81,
        0xe8, 0x7f, 0xc8, 0xd1, 0x9c, 0xca, 0xf6, 0x22, 0x1e, 0xe3, 0x1e,
        0xf8, 0x63, 0x54, 0xab, 0xa1, 0xec, 0x11, 0x35, 0xc7, 0x43,
    };

    const uint8_t CT[16] = {
        0xce, 0x8b, 0x56, 0xb0, 0x1a, 0x8d, 0x56, 0xaf,
        0x62, 0xab, 0x21, 0xca, 0xd7, 0xa7, 0x38, 0xcf,
    };

    const uint8_t TAG[16] = {
        0xad, 0x9d, 0x54, 0x50, 0x84, 0x91, 0x0e, 0xd2,
        0x75, 0xa8, 0xc0, 0x49, 0xd6, 0x49, 0x69, 0xed,
    };

    const uint8_t CT2[16] = {
        0xac, 0x47, 0xc8, 0x7a, 0x75, 0xe2, 0xff, 0x03,
        0xfc, 0xe5, 0x4d, 0x5c, 0x98, 0x13, 0x1b, 0xc4,
    };

    const uint8_t TAG2[16] = {
        0x8a, 0xf5, 0xb3, 0xfd, 0xe2, 0x05, 0xbc, 0x3c,
        0xa6, 0x76, 0xb8, 0xbe, 0x8e, 0x87, 0x64, 0xb7,
    };

#endif
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
    UAES_GCM_Ctx_t ctx;
    uint8_t result[64];
    uint8_t tag_out[16];
    uint8_t failure = 0u;
    // Test encryption at once
    UAES_GCM_Init(&ctx, KEY, sizeof(KEY), IV, sizeof(IV));
    UAES_GCM_AddAad(&ctx, AAD, sizeof(AAD));
    UAES_GCM_Encrypt(&ctx, PT, result, sizeof(PT));
    UAES_GCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
    if (memcmp(CT, result, sizeof(CT)) != 0) {
        (void)printf("UAES_GCM_Encrypt result error\n");
        PrintArray(CT, sizeof(CT));
        PrintArray(result, sizeof(result));
        failure++;
    } else if (memcmp(TAG, tag_out, sizeof(TAG)) != 0) {
        (void)printf("UAES_GCM_Encrypt tag error\n");
        PrintArray(TAG, sizeof(TAG));
        PrintArray(tag_out, sizeof(tag_out));
        failure++;
    } else {
        (void)printf("UAES_GCM_Encrypt case 1 passed\n");
    }
    // Test encryption by random chunks
    UAES_GCM_Init(&ctx, KEY, sizeof(KEY), IV, sizeof(IV));
    UAES_GCM_AddAad(&ctx, AAD, sizeof(AAD));
    size_t pos = 0u;
    while (pos < sizeof(PT)) {
        size_t chunk = (size_t)rand() % (sizeof(PT) - pos);
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
    if (memcmp(CT, result, sizeof(CT)) != 0) {
        (void)printf("UAES_GCM_Encrypt result error\n");
        PrintArray(CT, sizeof(CT));
        PrintArray(result, sizeof(result));
        failure++;
    } else if (memcmp(TAG, tag_out, sizeof(TAG)) != 0) {
        (void)printf("UAES_GCM_Encrypt tag error\n");
        PrintArray(TAG, sizeof(TAG));
        PrintArray(tag_out, sizeof(tag_out));
        failure++;
    } else {
        (void)printf("UAES_GCM_Encrypt case 2 passed\n");
    }
    // Test nonce2 with length other than 12
    UAES_GCM_Init(&ctx, KEY, sizeof(KEY), IV2, sizeof(IV2));
    UAES_GCM_AddAad(&ctx, AAD, sizeof(AAD));
    UAES_GCM_Encrypt(&ctx, PT, result, sizeof(PT));
    UAES_GCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
    if (memcmp(CT2, result, sizeof(CT2)) != 0) {
        (void)printf("UAES_GCM_Encrypt result error\n");
        PrintArray(CT2, sizeof(CT2));
        PrintArray(result, sizeof(result));
        failure++;
    } else if (memcmp(TAG2, tag_out, sizeof(TAG2)) != 0) {
        (void)printf("UAES_GCM_Encrypt tag error\n");
        PrintArray(TAG2, sizeof(TAG2));
        PrintArray(tag_out, sizeof(tag_out));
        failure++;
    } else {
        (void)printf("UAES_GCM_Encrypt case 3 passed\n");
    }

    // Test decryption at once
    UAES_GCM_Init(&ctx, KEY, sizeof(KEY), IV, sizeof(IV));
    UAES_GCM_AddAad(&ctx, AAD, sizeof(AAD));
    (void)memcpy(result, CT, sizeof(CT));
    UAES_GCM_Decrypt(&ctx, result, result, sizeof(CT));
    // This is an intended call to make sure multiple calls to
    // UAES_GCM_VerifyTag works correctly.
    UAES_GCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
    if (memcmp(PT, result, sizeof(PT)) != 0) {
        (void)printf("UAES_GCM_Decrypt result error\n");
        PrintArray(PT, sizeof(PT));
        PrintArray(result, sizeof(result));
        failure++;
    } else if (!UAES_GCM_VerifyTag(&ctx, TAG, sizeof(TAG))) {
        (void)printf("UAES_GCM_VerifyTag failed\n");
        failure++;
    } else {
        (void)printf("UAES_GCM_Decrypt case 1 passed\n");
    }
    // Test decryption by random chunks
    UAES_GCM_Init(&ctx, KEY, sizeof(KEY), IV, sizeof(IV));
    UAES_GCM_AddAad(&ctx, AAD, sizeof(AAD));
    (void)memcpy(result, CT, sizeof(CT));
    pos = 0u;
    while (pos < sizeof(CT)) {
        size_t chunk = (size_t)rand() % (sizeof(CT) - pos);
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
    if (memcmp(PT, result, sizeof(PT)) != 0) {
        (void)printf("UAES_GCM_Decrypt result error\n");
        PrintArray(PT, sizeof(PT));
        PrintArray(result, sizeof(result));
        failure++;
    } else if (!UAES_GCM_VerifyTag(&ctx, TAG, sizeof(TAG))) {
        (void)printf("UAES_GCM_VerifyTag failed\n");
        failure++;
    } else {
        (void)printf("UAES_GCM_Decrypt case 2 passed\n");
    }
    // Test nonce2 with length other than 12
    UAES_GCM_Init(&ctx, KEY, sizeof(KEY), IV2, sizeof(IV2));
    UAES_GCM_AddAad(&ctx, AAD, sizeof(AAD));
    (void)memcpy(result, CT2, sizeof(CT2));
    UAES_GCM_Decrypt(&ctx, result, result, sizeof(CT2));
    // This is an intended call to make sure multiple calls to
    // UAES_GCM_GenerateTag works correctly.
    UAES_GCM_GenerateTag(&ctx, tag_out, sizeof(tag_out));
    if (memcmp(PT, result, sizeof(PT)) != 0) {
        (void)printf("UAES_GCM_Decrypt result error\n");
        PrintArray(PT, sizeof(PT));
        PrintArray(result, sizeof(result));
        failure++;
    } else if (!UAES_GCM_VerifyTag(&ctx, TAG2, sizeof(TAG2))) {
        (void)printf("UAES_GCM_VerifyTag failed\n");
        failure++;
    } else {
        (void)printf("UAES_GCM_Decrypt case 3 passed\n");
    }
    return failure;
}

#endif // UAES_ENABLE_GCM

int main(void)
{
    uint8_t failure = 0u;
    (void)printf("Testing AES-%u\n", TEST_KEY_SIZE);
#if UAES_ENABLE_ECB
    failure += TestECB();
#endif
#if UAES_ENABLE_CBC
    failure += TestCBC();
#endif
#if UAES_ENABLE_CTR
    failure += TestCtr();
#endif
#if UAES_ENABLE_CCM
    failure += TestCcm();
    failure += TestCcmWithAad();
#endif
#if UAES_ENABLE_GCM
    failure += TestGcm();
#endif
    return (int)failure;
}
