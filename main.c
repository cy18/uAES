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
#include <time.h> // cppcheck-suppress misra-c2012-21.10 ; supprssed for testing

#define TEST_SPEED       0
#define TEST_ENCRYPT_NUM 10000000u
#define TEST_DECRYPT_NUM 1000000u

int main(void)
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
    UAES_ECB_Ctx_t ctx;
    UAES_ECB_Init(&ctx, KEY);
    uint8_t result[16];
    (void)printf("Testing uAES key size %u\n", UAES_KEY_SIZE);
#if TEST_SPEED
    {
        struct timespec start;
        struct timespec end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (uint32_t i = 0u; i < TEST_ENCRYPT_NUM; ++i) {
            UAES_ECB_Encrypt(&ctx, IN, result);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        uint64_t start_ns =
                start.tv_sec * (uint64_t)1000000000u + (uint64_t)start.tv_nsec;
        uint64_t end_ns =
                end.tv_sec * (uint64_t)1000000000u + (uint64_t)end.tv_nsec;
        (void)printf("UAES_ECB_Encrypt took %llu ns\n",
                     (end_ns - start_ns) / TEST_ENCRYPT_NUM);
    }
#else
    UAES_ECB_Encrypt(&ctx, IN, result);
#endif
    if (memcmp(OUT, result, 16u) != 0) {
        (void)printf("UAES_ECB_Encrypt failed\n");
        for (int i = 0; i < 16; i++) {
            (void)printf("%02x ", OUT[i]);
        }
        (void)printf("\n");
        for (int i = 0; i < 16; i++) {
            (void)printf("%02x ", result[i]);
        }
        (void)printf("\n");
    } else {
        (void)printf("UAES_ECB_Encrypt passed\n");
    }
#if TEST_SPEED
    {
        struct timespec start;
        struct timespec end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        for (uint32_t i = 0u; i < TEST_DECRYPT_NUM; ++i) {
            UAES_ECB_Decrypt(&ctx, OUT, result);
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        uint64_t start_ns =
                start.tv_sec * (uint64_t)1000000000u + (uint64_t)start.tv_nsec;
        uint64_t end_ns =
                end.tv_sec * (uint64_t)1000000000u + (uint64_t)end.tv_nsec;
        (void)printf("UAES_ECB_Decrypt took %llu ns\n",
                     (end_ns - start_ns) / TEST_DECRYPT_NUM);
    }
#else
    UAES_ECB_Decrypt(&ctx, OUT, result);
#endif
    if (memcmp(IN, result, 16u) != 0) {
        (void)printf("UAES_ECB_Decrypt failed\n");
        for (int i = 0; i < 16; i++) {
            (void)printf("%02x ", IN[i]);
        }
        (void)printf("\n");
        for (int i = 0; i < 16; i++) {
            (void)printf("%02x ", result[i]);
        }
        (void)printf("\n");
    } else {
        (void)printf("UAES_ECB_Decrypt passed\n");
    }
    return 0;
}
