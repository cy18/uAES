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

#ifndef UAES_CBC_ENCRYPT
#define UAES_CBC_ENCRYPT 1
#endif

#ifndef UAES_CBC_DECRYPT
#define UAES_CBC_DECRYPT 1
#endif

#ifndef UAES_CTR
#define UAES_CTR 1
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

#if (UAES_CBC_ENCRYPT != 0) || (UAES_CBC_DECRYPT != 0)
typedef struct {
    uint8_t key[UAES_KEY_SIZE / 8u];
    uint8_t iv[16u];
} UAES_CBC_Ctx_t;

/**
 * @brief Initialize the context for AES CBC mode.
 *
 * As a block cipher, the CBC mode requires padding if the data length is not a
 * multiple of 16 bytes. The padding method is not specified in this library. It
 * is recommended to use PKCS#7 padding.
 * (https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7)
 *
 * CBC mode need an initialization vector (IV) at initialization. The IV is
 * generally considered public information. However, the IV should NEVER be
 * reused with the same key. The IV length is always 16 bytes.
 *
 * The CBC mode need the AES decryption cipher to do decryption. Thus it
 * requires more code space than CTR mode. Furthermore, the AES decryption of
 * this library is slower than the encryption. Thus, the CBC decryption is
 * slower than CTC. For these reasons, CTR mode is recommended over CBC mode
 * if possible.
 *
 * @param ctx The context to initialize.
 * @param key The 128-, 192-, or 256-bit key.
 * @param iv The 16-byte initialization vector.
 */
extern void UAES_CBC_Init(UAES_CBC_Ctx_t *ctx,
                          const uint8_t *key,
                          const uint8_t *iv);

#if UAES_CBC_ENCRYPT
/**
 * @brief Encrypt data using AES CBC mode.
 *
 * This function can be called multiple times to process multiple blocks.
 * However, the length of each block must be a multiple of 16 bytes. Otherwise,
 * the result is undefined.
 *
 * Overlapping the input and output is allowed. However, if they are in the same
 * buffer, the output must not be before the input. Otherwise, the input will be
 * overwritten before it is read.
 *
 * @param ctx The CBC context to use.
 * @param input The data to encrypt.
 * @param output The buffer to write the encrypted data to.
 * @param length The length of the data in bytes, must be a multiple of 16.
 */
extern void UAES_CBC_Encrypt(UAES_CBC_Ctx_t *ctx,
                             const uint8_t *input,
                             uint8_t *output,
                             size_t length);
#endif // UAES_CBC_ENCRYPT

#if UAES_CBC_DECRYPT
/**
 * @brief Decrypt data using AES CBC mode.
 * @param ctx The CBC context to use.
 * @param input The data to decrypt.
 * @param output The buffer to write the decrypted data to.
 * @param length The length of the data in bytes, must be a multiple of 16.
 */
extern void UAES_CBC_Decrypt(UAES_CBC_Ctx_t *ctx,
                             const uint8_t *input,
                             uint8_t *output,
                             size_t length);
#endif // UAES_CBC_DECRYPT
#endif // (UAES_CBC_ENCRYPT != 0) || (UAES_CBC_DECRYPT != 0)

#if UAES_CTR
typedef struct {
    uint8_t key[UAES_KEY_SIZE / 8u];
    uint8_t counter[16u];
    uint8_t byte_pos;
} UAES_CTR_Ctx_t;

/**
 * @brief Initialize the context for AES CTR mode.
 *
 * The CTR mode is recommended for most uses. There are many advantages to using
 * CTR mode, including:
 * - It is generally considered secure.
 * - It is a stream cipher, so it does not require padding.
 * - It only requires the encryption cipher of AES, thus not only faster than
 *  CBC, but also requires less code space.
 * It is worth noting that CTR mode need a nonce at initialization. There is no
 * need to keep the nonce secret, but the nonce should NEVER be reused with the
 * same key. The nonce length is in range 0~15 and the recommended length
 * is 8 bytes.
 *
 * @param ctx The context to initialize.
 * @param key The 128-, 192-, or 256-bit key.
 * @param nonce The nonce to use. A same nonce/key pair must not be reused.
 * @param nonce_len The length of the nonce in bytes. It must be between 0~15.
 */
extern void UAES_CTR_Init(UAES_CTR_Ctx_t *ctx,
                          const uint8_t *key,
                          const uint8_t *nonce,
                          size_t nonce_len);

/**
 * @brief Encrypt data using AES CTR mode.
 *
 * As a stream cipher, this function can be called multiple times to process
 * multiple blocks of arbitrary length.
 * It is allowed for the input and output to overlap. However, the output should
 * not be before the input in a same buffer. This is because the function
 * process the data byte by byte. If the output is before the input, the input
 * will be overwritten before it is read.
 * Example:
 *   uint8_t buf[256u];
 *   UAES_CTR_Encrypt(&ctx, buf, buf, 256u); // Legal
 *   UAES_CTR_Encrypt(&ctx, buf, buf + 16u, 240u); // Illegal
 *   UAES_CTR_Encrypt(&ctx, buf + 16u, buf, 240u); // Legal
 *
 * @param ctx The CTR context to use.
 * @param input The data to encrypt.
 * @param output The buffer to write the encrypted data to.
 * @param length The length of the data in bytes.
 */
extern void UAES_CTR_Encrypt(UAES_CTR_Ctx_t *ctx,
                             const uint8_t *input,
                             uint8_t *output,
                             size_t length);

/**
 * @brief Decrypt data using AES CTR mode.
 *
 * Since the encryption and decryption are the same in CTR mode, this function
 * calls UAES_CTR_Encrypt internally. All the rules of UAES_CTR_Encrypt apply
 * here.
 *
 * @param ctx The CTR context to use.
 * @param input The data to decrypt.
 * @param output The buffer to write the decrypted data to.
 * @param length The length of the data in bytes.
 */
extern void UAES_CTR_Decrypt(UAES_CTR_Ctx_t *ctx,
                             const uint8_t *input,
                             uint8_t *output,
                             size_t length);

#endif

#endif // UAES_H_
