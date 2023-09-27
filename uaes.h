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

#ifndef UAES_H_
#define UAES_H_

#include <stdint.h>
#include <stdlib.h>

#ifndef UAES_KEY_SIZE
#define UAES_KEY_SIZE 128u
// #define UAES_KEY_SIZE 192u
// #define UAES_KEY_SIZE 256u
#endif

#ifndef UAES_ECB_ENCRYPT
#define UAES_ECB_ENCRYPT 1
#endif

#ifndef UAES_ECB_DECRYPT
#define UAES_ECB_DECRYPT 1
#endif

#if (UAES_ECB_ENCRYPT != 0) || (UAES_ECB_DECRYPT != 0)
typedef struct {
    uint8_t key[UAES_KEY_SIZE / 8u];
} UAES_ECB_Ctx_t;

/**
 * @brief Initialize the context for ECB mode.
 *
 * Note that ECB is considered insecure for most uses.
 *
 * @param ctx The context to initialize.
 * @param key The 128-, 192-, or 256-bit key.
 */
extern void UAES_ECB_Init(UAES_ECB_Ctx_t *ctx, const uint8_t *key);
#endif

#if UAES_ECB_ENCRYPT
/**
 * @brief Encrypt a 16-byte block of data using ECB mode.
 *
 * It is allowed for input and output to point to the same buffer.
 *
 * @param ctx The ECB context to use.
 * @param input The 16-byte block to encrypt.
 * @param output The 16-byte block to write the encrypted data to.
 */
extern void UAES_ECB_Encrypt(const UAES_ECB_Ctx_t *ctx,
                             const uint8_t *input,
                             uint8_t *output);
#endif // UAES_ECB_ENCRYPT
#if UAES_ECB_DECRYPT
/**
 * @brief Decrypt a 16-byte block of data using ECB mode.
 * @param ctx The ECB context to use.
 * @param input The 16-byte block to decrypt.
 * @param output The 16-byte block to write the decrypted data to.
 */
extern void UAES_ECB_Decrypt(const UAES_ECB_Ctx_t *ctx,
                             const uint8_t *input,
                             uint8_t *output);
#endif // UAES_ECB_DECRYPT

#endif // UAES_H_
