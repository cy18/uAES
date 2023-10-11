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

#ifndef UAES_H_
#define UAES_H_

#include <stdint.h>
#include <stdlib.h>

#ifndef UAES_DEFAULT_CONFIG
#define UAES_DEFAULT_CONFIG 1
#endif

#ifndef UAES_ENABLE_128
#define UAES_ENABLE_128 UAES_DEFAULT_CONFIG
#endif

#ifndef UAES_ENABLE_192
#define UAES_ENABLE_192 UAES_DEFAULT_CONFIG
#endif

#ifndef UAES_ENABLE_256
#define UAES_ENABLE_256 UAES_DEFAULT_CONFIG
#endif

/*
 * UAES_STORE_ROUND_KEY_IN_CTX
 * 0: Do not store the round key in the context.
 * 1: Store the round key in the context.
 * Default: 0
 *
 * The AES algorithm expands the key into a round key and use the round key for
 * encryption and decryption. The round key is 176/208/240 bytes long for
 * 128/192/256 bit key. Typically, it is generated at initialization and stored
 * in the context.
 *
 * To reduce the RAM usage, this library allows the round key to be generated on
 * the fly when needed. This saves some RAM, but cost more code space and CPU
 * time. On a 120MHz Cortex-M4 MCU with arm-none-eabi-gcc -Os, the code size
 * is increased by 72 bytes and the speed reduced from 252.1kBps to 167.4kBps
 * (about 33% slower).
 *
 * The reduced RAM usage depends on the maximum key size enabled (may be
 * larger than key_len given at initialization). Since the original key is no
 * longer needed after the round key is generated, the increased RAM usage
 * equals to the size of the round key minus the size of the original key. It is
 * 160 bytes for 128-bit key, 184 bytes for 192-bit key, and 208 bytes for
 * 256-bit key.
 */
#ifndef UAES_STORE_ROUND_KEY_IN_CTX
#define UAES_STORE_ROUND_KEY_IN_CTX 1
#endif

/*
 * UAES_SBOX_MODE
 *
 * A 8-bit substitution box (S-box) is used in the AES algorithm. Usually, it
 * can be archived by a constant 256-byte table. However, if the flash space is
 * limited, it can be generated on the fly or at initialization. The three
 * options are:
 *
 * UAES_SBOX_MODE = 0: Generate the S-box on the fly. This is very slow, but
 * saves about 120 bytes of code space without additional RAM usage. On a 120MHz
 * Cortex-M4 MCU with arm-none-eabi-gcc -Os, the speed is reduced from 264.4kBps
 * to 11.5kBps. Only use this option if the speed is not important.
 *
 * UAES_SBOX_MODE = 1: Store the S-box as a constant table. This is the
 * default option.
 *
 * UAES_SBOX_MODE = 2: Generate the S-box at initialization. The speed is the
 * same as option 1. It saves about 172 bytes in code space but cost 256 bytes
 * of additional RAM to store the S-box. This option is recommended if the flash
 * space is limited while the RAM is not. One example is a bootloader.
 *
 * Note that the code space is measured with arm-none-eabi-gcc -Os. The result
 * may vary with different compilers.
 *
 * Furthermore, the tests are done with only CTR mode enabled. if modes
 * requiring AES decryption, such as CBC, are enabled, a reverse S-box is also
 * needed. This would cost extra code space or RAM, depending on the option.
 */
#ifndef UAES_SBOX_MODE
#define UAES_SBOX_MODE 1
#endif

/*
 * UAES_32BIT_MODE
 *
 * 0: Use 8-bit operations for AES when possible. Recommended for 8-bit MCU or
 * the Flash space is limited.
 * 1: Use 32-bit operations for AES when possible. Recommended for 32-bit MCU.
 *
 * Though the AES algorithm is defined in terms of 8-bit operations, many
 * operations can be done in 32-bit. On a 32-bit MCU, this can improve the
 * speed by about 30% with a small increase in code size. However, on a 8-bit
 * MCU, it may be slower and larger.
 *
 * On a 120MHz Cortex-M4 MCU with arm-none-eabi-gcc -Os with only CTR mode, the
 * code size is 950 bytes for UAES_32BIT_MODE = 0 and 1038 bytes for
 * UAES_32BIT_MODE = 0. The speed is 300.0kBps for UAES_32BIT_MODE = 0 and
 * 386.4kBps for UAES_32BIT_MODE = 1.
 *
 * When the speed is important, using -O3 together with UAES_32BIT_MODE = 1 is
 * recommended. On the same 120MHz Cortex-M4 MCU, the speed increased from
 * 386.4kBps to  1097.7kBps.
 *
 * The code size and speed may vary with different compilers and MCUs. The speed
 * can be tested with the benchmark program tests/uaes_benchmark.c on your
 * platform.
 */
#ifndef UAES_32BIT_MODE
#define UAES_32BIT_MODE 1
#endif

#ifndef UAES_ENABLE_ECB_ENCRYPT
#define UAES_ENABLE_ECB_ENCRYPT UAES_DEFAULT_CONFIG
#endif

#ifndef UAES_ENABLE_ECB_DECRYPT
#define UAES_ENABLE_ECB_DECRYPT UAES_DEFAULT_CONFIG
#endif

#ifndef UAES_ENABLE_CBC_ENCRYPT
#define UAES_ENABLE_CBC_ENCRYPT UAES_DEFAULT_CONFIG
#endif

#ifndef UAES_ENABLE_CBC_DECRYPT
#define UAES_ENABLE_CBC_DECRYPT UAES_DEFAULT_CONFIG
#endif

#ifndef UAES_ENABLE_CTR
#define UAES_ENABLE_CTR UAES_DEFAULT_CONFIG
#endif

#ifndef UAES_ENABLE_CCM
#define UAES_ENABLE_CCM UAES_DEFAULT_CONFIG
#endif

#ifndef UAES_ENABLE_GCM
#define UAES_ENABLE_GCM UAES_DEFAULT_CONFIG
#endif

#if ((UAES_ENABLE_ECB_ENCRYPT != 0) || (UAES_ENABLE_ECB_DECRYPT != 0))
#define UAES_ENABLE_ECB 1
#endif

#if ((UAES_ENABLE_CBC_ENCRYPT != 0) || (UAES_ENABLE_CBC_DECRYPT != 0))
#define UAES_ENABLE_CBC 1
#endif

#if (UAES_ENABLE_CCM != 0) || (UAES_ENABLE_GCM != 0)
#include <stdbool.h>
#endif

#if UAES_ENABLE_256
#define UAES_MAX_KEY_SIZE 256u
#elif UAES_ENABLE_192
#define UAES_MAX_KEY_SIZE 192u
#elif UAES_ENABLE_128
#define UAES_MAX_KEY_SIZE 128u
#else
#error "No key size specified."
#endif

#if UAES_32BIT_MODE == 0
typedef struct {
    // The number of 32-bit word of AES key.
    // It is 4 for AES128, 6 for AES192, and 8 for AES256.
    uint8_t keysize_word;
#if UAES_STORE_ROUND_KEY_IN_CTX == 0
    uint8_t key[UAES_MAX_KEY_SIZE / 8u];
#else
    uint8_t key[((UAES_MAX_KEY_SIZE / 32u) + 7u) * 16u];
#endif
} UAES_AES_Ctx_t;
#else
typedef struct {
    // The number of 32-bit word of AES key.
    // It is 4 for AES128, 6 for AES192, and 8 for AES256.
    uint8_t keysize_word;
#if UAES_STORE_ROUND_KEY_IN_CTX == 0
    uint32_t key[UAES_MAX_KEY_SIZE / 32u];
#else
    uint32_t key[((UAES_MAX_KEY_SIZE / 32u) + 7u) * 4u];
#endif
} UAES_AES_Ctx_t;
#endif // UAES_32BIT_MODE == 0

#if UAES_ENABLE_ECB
typedef struct {
    UAES_AES_Ctx_t aes_ctx;
} UAES_ECB_Ctx_t;

/**
 * @brief Initialize the context for ECB mode.
 *
 * Note that ECB is considered insecure for most uses.
 *
 * @param ctx The context to initialize.
 * @param key The key to use.
 * @param key_len The length of the key in bytes. It must be 16, 24, or 32.
 */
extern void UAES_ECB_Init(UAES_ECB_Ctx_t *ctx,
                          const uint8_t *key,
                          size_t key_len);

#endif // UAES_ENABLE_ECB

#if UAES_ENABLE_ECB_ENCRYPT
/**
 * @brief Encrypt the data using ECB mode.
 *
 * The data length must be a multiple of 16 bytes. Otherwise, the result is
 * undefined.
 * It is allowed for input and output to point to the same buffer, but the
 * output must not be before the input in a same buffer. Otherwise the input
 * will be overwritten before it is read.
 *
 * @param ctx The ECB context to use.
 * @param input The data to encrypt.
 * @param output The buffer to write the encrypted data to.
 * @param len The length of the data in bytes, must be a multiple of 16.
 */
extern void UAES_ECB_Encrypt(const UAES_ECB_Ctx_t *ctx,
                             const uint8_t *input,
                             uint8_t *output,
                             size_t len);

/**
 * @brief Simple function for encrypting data using ECB mode.
 *
 * All the rules of UAES_ECB_Init and UAES_ECB_Encrypt apply here.
 *
 * @param key The key to use.
 * @param key_len The length of the key in bytes. It must be 16, 24, or 32.
 * @param input The data to encrypt.
 * @param output The buffer to write the encrypted data to.
 * @param data_len The length of the data in bytes, must be a multiple of 16.
 */
extern void UAES_ECB_SimpleEncrypt(const uint8_t *key,
                                   size_t key_len,
                                   const uint8_t *input,
                                   uint8_t *output,
                                   size_t data_len);

#endif // UAES_ENABLE_ECB_ENCRYPT

#if UAES_ENABLE_ECB_DECRYPT
/**
 * @brief Decrypt a 16-byte block of data using ECB mode.
 *
 * All the rules of UAES_ECB_Encrypt apply here.
 *
 * @param ctx The ECB context to use.
 * @param input The data to decrypt.
 * @param output The buffer to write the encrypted data to.
 * @param len The length of the data in bytes, must be a multiple of 16.
 */
extern void UAES_ECB_Decrypt(const UAES_ECB_Ctx_t *ctx,
                             const uint8_t *input,
                             uint8_t *output,
                             size_t len);

/**
 * @brief Simple function for decrypting data using ECB mode.
 *
 * All the rules of UAES_ECB_Init and UAES_ECB_Decrypt apply here.
 *
 * @param key The key to use.
 * @param key_len The length of the key in bytes. It must be 16, 24, or 32.
 * @param input The data to decrypt.
 * @param output The buffer to write the encrypted data to.
 * @param data_len The length of the data in bytes, must be a multiple of 16.
 */
extern void UAES_ECB_SimpleDecrypt(const uint8_t *key,
                                   size_t key_len,
                                   const uint8_t *input,
                                   uint8_t *output,
                                   size_t data_len);

#endif // UAES_ENABLE_ECB_DECRYPT

#if UAES_ENABLE_CBC
typedef struct {
    UAES_AES_Ctx_t aes_ctx;
    uint8_t iv[16u];
} UAES_CBC_Ctx_t;

/**
 * @brief Initialize the context for AES CBC mode.
 *
 * As a block cipher, the CBC mode requires padding if the data length is not a
 * multiple of 16 bytes. The padding method is not specified in this library. It
 * is recommended to use PKCS#7 padding.
 * (en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7)
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
 * @param key The key to use.
 * @param key_len The length of the key in bytes. It must be 16, 24, or 32.
 * @param iv The 16-byte initialization vector.
 */
extern void UAES_CBC_Init(UAES_CBC_Ctx_t *ctx,
                          const uint8_t *key,
                          size_t key_len,
                          const uint8_t *iv);

#endif // UAES_ENABLE_CBC

#if UAES_ENABLE_CBC_ENCRYPT
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
 * @param len The length of the data in bytes, must be a multiple of 16.
 */
extern void UAES_CBC_Encrypt(UAES_CBC_Ctx_t *ctx,
                             const uint8_t *input,
                             uint8_t *output,
                             size_t len);

/**
 * @brief The Simple function for encrypting data using CBC mode.
 *
 * All the rules of UAES_CBC_Init and UAES_CBC_Encrypt apply here.
 *
 * @param key The key to use.
 * @param key_len The length of the key in bytes. It must be 16, 24, or 32.
 * @param iv The 16-byte initialization vector.
 * @param input The data to encrypt.
 * @param output The buffer to write the encrypted data to.
 * @param data_len The length of the data in bytes, must be a multiple of 16.
 */
extern void UAES_CBC_SimpleEncrypt(const uint8_t *key,
                                   size_t key_len,
                                   const uint8_t *iv,
                                   const uint8_t *input,
                                   uint8_t *output,
                                   size_t data_len);

#endif // UAES_ENABLE_CBC_ENCRYPT

#if UAES_ENABLE_CBC_DECRYPT
/**
 * @brief Decrypt data using AES CBC mode.
 * @param ctx The CBC context to use.
 * @param input The data to decrypt.
 * @param output The buffer to write the decrypted data to.
 * @param len The length of the data in bytes, must be a multiple of 16.
 */
extern void UAES_CBC_Decrypt(UAES_CBC_Ctx_t *ctx,
                             const uint8_t *input,
                             uint8_t *output,
                             size_t len);

/**
 * @brief Simple function for decrypting data using CBC mode.
 *
 * All the rules of UAES_CBC_Init and UAES_CBC_Decrypt apply here.
 *
 * @param key The key to use.
 * @param key_len The length of the key in bytes. It must be 16, 24, or 32.
 * @param iv The 16-byte initialization vector.
 * @param input The data to decrypt.
 * @param output The buffer to write the decrypted data to.
 * @param data_len The length of the data in bytes, must be a multiple of 16.
 */
extern void UAES_CBC_SimpleDecrypt(const uint8_t *key,
                                   size_t key_len,
                                   const uint8_t *iv,
                                   const uint8_t *input,
                                   uint8_t *output,
                                   size_t data_len);

#endif // UAES_ENABLE_CBC_DECRYPT

#if UAES_ENABLE_CTR
typedef struct {
    UAES_AES_Ctx_t aes_ctx;
    uint8_t byte_pos;
    uint8_t counter[16u];
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
 * @param key The key to use.
 * @param key_len The length of the key in bytes. It must be 16, 24, or 32.
 * @param nonce The nonce to use. A same nonce/key pair must not be reused.
 * @param nonce_len The length of the nonce in bytes. It must be between 0~15.
 */
extern void UAES_CTR_Init(UAES_CTR_Ctx_t *ctx,
                          const uint8_t *key,
                          size_t key_len,
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
 *   UAES_CTR_Encrypt(&ctx, buf, buf, 256u); Legal
 *   UAES_CTR_Encrypt(&ctx, buf, buf + 16u, 240u); Illegal
 *   UAES_CTR_Encrypt(&ctx, buf + 16u, buf, 240u); Legal
 *
 * @param ctx The CTR context to use.
 * @param input The data to encrypt.
 * @param output The buffer to write the encrypted data to.
 * @param len The length of the data in bytes.
 */
extern void UAES_CTR_Encrypt(UAES_CTR_Ctx_t *ctx,
                             const uint8_t *input,
                             uint8_t *output,
                             size_t len);

/**
 * @brief Simple function for encrypting data using CTR mode.
 *
 * All the rules of UAES_CTR_Init and UAES_CTR_Encrypt apply here.
 *
 * @param key The key to use.
 * @param key_len The length of the key in bytes. It must be 16, 24, or 32.
 * @param nonce The nonce to use. A same nonce/key pair must not be reused.
 * @param nonce_len The length of the nonce in bytes. It must be between 0~15.
 * @param input The data to encrypt.
 * @param output The buffer to write the encrypted data to.
 * @param data_len The length of the data in bytes.
 */
extern void UAES_CTR_SimpleEncrypt(const uint8_t *key,
                                   size_t key_len,
                                   const uint8_t *nonce,
                                   size_t nonce_len,
                                   const uint8_t *input,
                                   uint8_t *output,
                                   size_t data_len);

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
 * @param len The length of the data in bytes.
 */
extern void UAES_CTR_Decrypt(UAES_CTR_Ctx_t *ctx,
                             const uint8_t *input,
                             uint8_t *output,
                             size_t len);

/**
 * @brief Simple function for decrypting data using CTR mode.
 *
 * All the rules of UAES_CTR_Init and UAES_CTR_Decrypt apply here.
 *
 * @param key The key to use.
 * @param key_len The length of the key in bytes. It must be 16, 24, or 32.
 * @param nonce The nonce to use. A same nonce/key pair must not be reused.
 * @param nonce_len The length of the nonce in bytes. It must be between 0~15.
 * @param input The data to decrypt.
 * @param output The buffer to write the decrypted data to.
 * @param data_len The length of the data in bytes.
 */
extern void UAES_CTR_SimpleDecrypt(const uint8_t *key,
                                   size_t key_len,
                                   const uint8_t *nonce,
                                   size_t nonce_len,
                                   const uint8_t *input,
                                   uint8_t *output,
                                   size_t data_len);

#endif // UAES_ENABLE_CTR

#if UAES_ENABLE_CCM
typedef struct {
    UAES_AES_Ctx_t aes_ctx;
    uint8_t byte_pos;
    uint8_t nonce_len;
    uint8_t aad_byte_pos;
    uint8_t cbc_buf[16u];
    uint8_t counter[16u];
} UAES_CCM_Ctx_t;

/**
 * @brief Initialize the context for AES CCM mode.
 *
 * The CCM mode is an authenticated encryption mode. It use CTR mode for
 * encryption and CBC-MAC for authentication. Since only AES encryption cipher
 * is needed in both encryption and authentication, the CCM mode is smaller than
 * GCM mode.
 *
 * The CCM mode need a nonce at initialization. There is no need to keep the
 * nonce secret, but the nonce should NEVER be reused with the same key. The
 * nonce length should in range 7~13.
 *
 * The aad_len is the number of bytes of the AAD (Additional Authenticate Data).
 * If there is no AAD, the aad_len should be 0. If aad_len is not 0, the
 * function UAES_CCM_AddAad must be called after UAES_CCM_Init and before
 * UAES_CCM_Encrypt or UAES_CCM_Decrypt. The total length of the AAD must be the
 * same as the aad_len given in UAES_CCM_Init. Otherwise, the authentication
 * will fail.
 *
 * The data_len is the number of bytes to be encrypted/decrypted. The maximum
 * data length depends on the nonce length. data_len must be less than
 * 2^(8 * (15 - nonce_len)). The data_len should be given at initialization as
 * required by the algorithm of authentication.
 *
 * The tag_len is the length of the authentication tag. It must be even and
 * between 4~16. The recommended tag length is 16. The tag_len should be given
 * at initialization as required by the algorithm of authentication.
 *
 * @param ctx The context to initialize.
 * @param key The key to use.
 * @param key_len The length of the key in bytes. It must be 16, 24, or 32.
 * @param nonce The nonce to use. A same nonce/key pair must not be reused.
 * @param nonce_len The length of the nonce in bytes. It must be between 7~13.
 * @param aad_len The length of the AAD in bytes.
 * @param data_len The length of the data in bytes.
 * @param tag_len The length of the authentication tag in bytes. It must be even
 * and between 4~16.
 */
extern void UAES_CCM_Init(UAES_CCM_Ctx_t *ctx,
                          const uint8_t *key,
                          size_t key_len,
                          const uint8_t *nonce,
                          uint8_t nonce_len,
                          size_t aad_len,
                          size_t data_len,
                          uint8_t tag_len);

/**
 * @brief Add AAD (Additional Authenticate Data).
 *
 * This function MUST be called after UAES_CCM_Init and before UAES_CCM_Encrypt
 * or UAES_CCM_Decrypt. To make the library compact, this condition is not
 * checked. If this condition is not met, the result is undefined.
 *
 * This function can be called multiple times to to process long AAD in chunks.
 *
 * @param ctx The CCM context to use.
 * @param aad The AAD to add.
 * @param len The length of the AAD in bytes.
 */
extern void UAES_CCM_AddAad(UAES_CCM_Ctx_t *ctx,
                            const uint8_t *aad,
                            size_t len);

/**
 * @brief Encrypt data using AES CCM mode.
 *
 * This function can be called multiple times to process multiple
 * blocks. However, the total length of the data must be the same as the
 * data_len given in UAES_CCM_Init. Otherwise, the authentication will
 * fail.
 *
 * The input and output can overlap. However, if they are in the same
 * buffer, the output must not be before the input. Otherwise, the input
 * will be overwritten before it is read.
 *
 * @param ctx The CCM context to use.
 * @param input The data to encrypt.
 * @param output The buffer to write the encrypted data to.
 * @param len The length of the data in bytes.
 */
extern void UAES_CCM_Encrypt(UAES_CCM_Ctx_t *ctx,
                             const uint8_t *input,
                             uint8_t *output,
                             size_t len);

/**
 * @brief Decrypt data using AES CCM mode.
 *
 * All the rules of UAES_CCM_Encrypt apply here.
 *
 * @param ctx The CCM context to use.
 * @param input The data to decrypt.
 * @param output The buffer to write the decrypted data to.
 * @param len The length of the data in bytes.
 */
extern void UAES_CCM_Decrypt(UAES_CCM_Ctx_t *ctx,
                             const uint8_t *input,
                             uint8_t *output,
                             size_t len);

/**
 * @brief Generate the authentication tag.
 *
 * This function MUST be called after UAES_CCM_Encrypt or UAES_CCM_Decrypt.
 * The total length of the encrypted/decrypted data must be exactly the same as
 * the data_len given in UAES_CCM_Init.
 *
 * @param ctx The CCM context to use.
 * @param tag The buffer to write the tag to.
 * @param tag_len The length of the tag in bytes, must be the same as the
 * tag_len given in UAES_CCM_Init.
 */
extern void UAES_CCM_GenerateTag(const UAES_CCM_Ctx_t *ctx,
                                 uint8_t *tag,
                                 uint8_t tag_len);

/**
 * @brief Verify the authentication tag.
 * @param ctx The CCM context to use.
 * @param tag The tag to verify.
 * @param tag_len The length of the tag in bytes, must be the same as the
 * tag_len given in UAES_CCM_Init.
 * @return true if the tag matches, false otherwise.
 */
extern bool UAES_CCM_VerifyTag(const UAES_CCM_Ctx_t *ctx,
                               const uint8_t *tag,
                               uint8_t tag_len);

/**
 * @brief Simple function for encrypting and generating tag using CCM mode.
 *
 * All the rules of UAES_CCM_Init, UAES_CCM_Encrypt and UAES_CCM_GenerateTag
 * apply here.
 *
 * @param key The key to use.
 * @param key_len The length of the key in bytes. It must be 16, 24, or 32.
 * @param nonce The nonce to use. A same nonce/key pair must not be reused.
 * @param nonce_len The length of the nonce in bytes. It must be between 7~13.
 * @param aad The AAD to add.
 * @param aad_len The length of the AAD in bytes.
 * @param input The data to encrypt.
 * @param output The buffer to write the encrypted data to.
 * @param data_len The length of the data in bytes.
 * @param tag The buffer to write the tag to.
 * @param tag_len The length of the tag in bytes, must be the same as the
 */
extern void UAES_CCM_SimpleEncrypt(const uint8_t *key,
                                   size_t key_len,
                                   const uint8_t *nonce,
                                   uint8_t nonce_len,
                                   const uint8_t *aad,
                                   size_t aad_len,
                                   const uint8_t *input,
                                   uint8_t *output,
                                   size_t data_len,
                                   uint8_t *tag,
                                   uint8_t tag_len);

/**
 * @brief Simple function for decrypting and verifying tag using CCM mode.
 *
 * All the rules of UAES_CCM_Init, UAES_CCM_Decrypt and UAES_CCM_VerifyTag apply
 * here.
 *
 * @param key The key to use.
 * @param key_len The length of the key in bytes. It must be 16, 24, or 32.
 * @param nonce The nonce to use. A same nonce/key pair must not be reused.
 * @param nonce_len The length of the nonce in bytes. It must be between 7~13.
 * @param aad The AAD to add.
 * @param aad_len The length of the AAD in bytes.
 * @param input The data to decrypt.
 * @param output The buffer to write the decrypted data to.
 * @param data_len The length of the data in bytes.
 * @param tag The tag to verify.
 * @param tag_len The length of the tag in bytes, must be the same as the
 * @return true if the tag matches, false otherwise.
 */
extern bool UAES_CCM_SimpleDecrypt(const uint8_t *key,
                                   size_t key_len,
                                   const uint8_t *nonce,
                                   uint8_t nonce_len,
                                   const uint8_t *aad,
                                   size_t aad_len,
                                   const uint8_t *input,
                                   uint8_t *output,
                                   size_t data_len,
                                   const uint8_t *tag,
                                   uint8_t tag_len);

#endif // UAES_ENABLE_CCM

#if UAES_ENABLE_GCM
typedef struct {
    UAES_AES_Ctx_t aes_ctx;
    uint8_t counter[16];
    size_t data_len;
    size_t aad_len;
    uint32_t hash_key[4u];
    uint8_t hash_buf[16u];
} UAES_GCM_Ctx_t;

/**
 * @brief Initialize the context for AES GCM mode.
 *
 * The GCM mode is an authenticated encryption mode. It use CTR mode for
 * encryption and Galois mode for authentication. Generally, GCM mode is faster
 * than CCM mode. Further more, it supports parallel processing both encryption
 * and authentication.
 *
 * However, as a library focusing on MCU applications, this implementation
 * trades off speed for code and RAM size, making the GCM mode slower than CCM
 * mode. Furthermore, the GCM mode requires more code space than CCM mode. Thus,
 * the CCM mode is recommended over GCM mode if possible.
 *
 * The GCM mode need an initialization vector (IV) at initialization. The IV is
 * generally considered public information. However, the IV should NEVER be
 * reused with the same key. There is no requirement on the length of the IV for
 * GCM mode. However, it is HIGHLY recommended to use a 12-byte (96-bit)  IV.
 *
 * @param ctx The context to initialize.
 * @param key The key to use.
 * @param key_len The length of the key in bytes. It must be 16, 24, or 32.
 * @param iv The initialization vector to use.
 * @param iv_len The length of the initialization vector in bytes.
 */
extern void UAES_GCM_Init(UAES_GCM_Ctx_t *ctx,
                          const uint8_t *key,
                          size_t key_len,
                          const uint8_t *iv,
                          size_t iv_len);

/**
 * @brief Add AAD (Additional Authenticate Data).
 *
 * This function MUST be called after UAES_GCM_Init and before UAES_GCM_Encrypt
 * or UAES_GCM_Decrypt. To make the library smaller, this condition is not
 * checked. If this condition is not met, the result is undefined.
 *
 * This function can be called multiple times to to process long AAD in chunks.
 *
 * @param ctx The GCM context to use.
 * @param aad The AAD to add.
 * @param len The length of the AAD in bytes.
 */
extern void UAES_GCM_AddAad(UAES_GCM_Ctx_t *ctx,
                            const uint8_t *aad,
                            size_t len);

/**
 * @brief Encrypt data using AES GCM mode.
 *
 * This function can be called multiple times to process multiple blocks. Note
 * that only one of UAES_GCM_Encrypt and UAES_GCM_Decrypt can be called for one
 * context. If both are called, the result is undefined.
 *
 * @param ctx The GCM context to use.
 * @param input The data to encrypt.
 * @param output The buffer to write the encrypted data to.
 * @param len The length of the data in bytes.
 */
extern void UAES_GCM_Encrypt(UAES_GCM_Ctx_t *ctx,
                             const uint8_t *input,
                             uint8_t *output,
                             size_t len);

/**
 * @brief Decrypt data using AES GCM mode.
 *
 * All the rules of UAES_GCM_Encrypt apply here.
 *
 * @param ctx The GCM context to use.
 * @param input The data to decrypt.
 * @param output The buffer to write the decrypted data to.
 * @param len The length of the data in bytes.
 */
extern void UAES_GCM_Decrypt(UAES_GCM_Ctx_t *ctx,
                             const uint8_t *input,
                             uint8_t *output,
                             size_t len);

/**
 * @brief Generate the authentication tag.
 *
 * This function should only be called when all the data has been processed.
 *
 * @param ctx The GCM context to use.
 * @param tag The buffer to write the tag to.
 * @param tag_len The length of the tag in bytes.
 */
extern void UAES_GCM_GenerateTag(const UAES_GCM_Ctx_t *ctx,
                                 uint8_t *tag,
                                 size_t tag_len);

/**
 * @brief Verify the authentication tag.
 *
 * This function calls UAES_GCM_GenerateTag internally, thus it should only be
 * called when all the data has been processed.
 *
 * @param ctx The GCM context to use.
 * @param tag The tag to verify.
 * @param tag_len The length of the tag in bytes.
 * @return true if the tag matches, false otherwise.
 */
extern bool UAES_GCM_VerifyTag(const UAES_GCM_Ctx_t *ctx,
                               const uint8_t *tag,
                               size_t tag_len);

/**
 * @brief Simple function for encrypting and generating tag using GCM mode.
 * @param key The key to use.
 * @param key_len The length of the key in bytes. It must be 16, 24, or 32.
 * @param iv The initialization vector to use.
 * @param iv_len The length of the initialization vector in bytes.
 * @param aad The AAD to add.
 * @param aad_len The length of the AAD in bytes.
 * @param input The data to encrypt.
 * @param output The buffer to write the encrypted data to.
 * @param len The length of the data in bytes.
 * @param tag The buffer to write the tag to.
 * @param tag_len The length of the tag in bytes.
 */
extern void UAES_GCM_SimpleEncrypt(const uint8_t *key,
                                   size_t key_len,
                                   const uint8_t *iv,
                                   size_t iv_len,
                                   const uint8_t *aad,
                                   size_t aad_len,
                                   const uint8_t *input,
                                   uint8_t *output,
                                   size_t data_len,
                                   uint8_t *tag,
                                   size_t tag_len);

/**
 * @brief Simple function for decrypting and verifying tag using GCM mode.
 *
 * All the rules of UAES_GCM_SimpleEncrypt apply here.
 *
 * @param key The key to use.
 * @param key_len The length of the key in bytes. It must be 16, 24, or 32.
 * @param iv The initialization vector to use.
 * @param iv_len The length of the initialization vector in bytes.
 * @param aad The AAD to use.
 * @param aad_len The length of the AAD in bytes.
 * @param input The data to decrypt.
 * @param output The buffer to write the decrypted data to.
 * @param data_len The length of the data in bytes.
 * @param tag The tag to verify.
 * @param tag_len The length of the tag in bytes.
 * @return true if the tag matches, false otherwise.
 */
extern bool UAES_GCM_SimpleDecrypt(const uint8_t *key,
                                   size_t key_len,
                                   const uint8_t *iv,
                                   size_t iv_len,
                                   const uint8_t *aad,
                                   size_t aad_len,
                                   const uint8_t *input,
                                   uint8_t *output,
                                   size_t data_len,
                                   const uint8_t *tag,
                                   size_t tag_len);

#endif // UAES_ENABLE_GCM

#endif // UAES_H_
