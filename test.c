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
 * https://github.com/cy18/uAES
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

#if (UAES_ECB_ENCRYPT != 0) || (UAES_ECB_DECRYPT != 0)
static uint8_t TestECB(void)
{
#if UAES_KEY_SIZE == 256u
    uint8_t const KEY[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                            0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                            0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t const OUT[] = { 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
                            0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8 };
#elif UAES_KEY_SIZE == 192u
    uint8_t const KEY[] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
                            0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
                            0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
    uint8_t const OUT[] = { 0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
                            0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc };
#elif UAES_KEY_SIZE == 128u
    uint8_t const KEY[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    uint8_t const OUT[] = { 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
                            0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 };
#endif

    uint8_t const IN[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                           0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    uint8_t failure = 0u;
    UAES_ECB_Ctx_t ctx;
    UAES_ECB_Init(&ctx, KEY);
    uint8_t result[16];
#if UAES_ECB_ENCRYPT
    UAES_ECB_Encrypt(&ctx, IN, result);
    if (memcmp(OUT, result, 16u) != 0) {
        (void)printf("UAES_ECB_Encrypt failed\n");
        PrintArray(OUT, sizeof(OUT));
        PrintArray(result, sizeof(result));
        failure++;
    } else {
        (void)printf("UAES_ECB_Encrypt passed\n");
    }
#endif // UAES_ECB_ENCRYPT
#if UAES_ECB_DECRYPT
    UAES_ECB_Decrypt(&ctx, OUT, result);
    if (memcmp(IN, result, sizeof(IN)) != 0) {
        (void)printf("UAES_ECB_Decrypt failed\n");
        PrintArray(IN, sizeof(IN));
        PrintArray(result, sizeof(result));
        failure++;
    } else {
        (void)printf("UAES_ECB_Decrypt passed\n");
    }
#endif // UAES_ECB_DECRYPT
    return failure;
}
#endif // (UAES_ECB_ENCRYPT != 0) || (UAES_ECB_DECRYPT != 0)

#if UAES_CTR
static uint8_t TestCtr(void)
{
#if UAES_KEY_SIZE == 256u
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
#elif UAES_KEY_SIZE == 192u
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
#elif UAES_KEY_SIZE == 128u
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
    UAES_CTR_Init(&ctx, KEY, NONCE, sizeof(NONCE));
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
    UAES_CTR_Init(&ctx, KEY, NONCE, sizeof(NONCE));
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
    UAES_CTR_Init(&ctx, KEY, NONCE, sizeof(NONCE));
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
    UAES_CTR_Init(&ctx, KEY, NONCE, sizeof(NONCE));
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

#endif

int main(void)
{
    uint8_t failure = 0u;
    (void)printf("Testing AES-%u\n", UAES_KEY_SIZE);
#if (UAES_ECB_ENCRYPT != 0) || (UAES_ECB_DECRYPT != 0)
    failure += TestECB();
#endif
#if UAES_CTR
    failure += TestCtr();
#endif
    return (int)failure;
}
