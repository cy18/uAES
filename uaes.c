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

#include <string.h>

#if (UAES_ENABLE_ECB_DECRYPT != 0) || (UAES_ENABLE_CBC_DECRYPT != 0)
#define ENABLE_INV_CIPHER 1
#else
#define ENABLE_INV_CIPHER 0
#endif

#if UAES_32BIT_MODE == 0
typedef uint8_t State_t[16];
#else
// Store the 4x4 bytes AES cipher matrix by 4 uint32.
// Each uint32 represents a row in the matrix.
// In each uint32, the LSB is the first element in the row, and the MSB is the
// last. In other words, the bytes are stored in little endian order in uint32.
typedef uint32_t State_t[4];
#endif

#if UAES_STORE_ROUND_KEY_IN_CTX == 0
// Store the necessary information for generating round key.
#if UAES_32BIT_MODE == 0
typedef struct {
    uint8_t iter_num;
    uint8_t buf[UAES_MAX_KEY_SIZE / 8u];
} RoundKey_t;
#else
typedef struct {
    uint8_t iter_num;
    uint32_t buf[UAES_MAX_KEY_SIZE / 32u];
} RoundKey_t;
#endif
#endif // UAES_STORE_ROUND_KEY_IN_CTX

#if UAES_32BIT_MODE == 0
// Declare the static functions.
static void Cipher(const UAES_AES_Ctx_t *ctx,
                   const uint8_t input[16u],
                   uint8_t output[16u]);
static void SubBytes(State_t state);
static void ShiftRows(State_t state);
static void MixColumns(State_t state);
static uint8_t Times2(uint8_t x);
static void InitAesCtx(UAES_AES_Ctx_t *ctx, const uint8_t *key, size_t key_len);
#if UAES_STORE_ROUND_KEY_IN_CTX
static void ExpandRoundKey(UAES_AES_Ctx_t *ctx);
static void AddRoundKey(const UAES_AES_Ctx_t *ctx,
                        uint8_t round,
                        State_t state);
#else
static void AddRoundKey(const UAES_AES_Ctx_t *ctx,
                        uint8_t round,
                        State_t state,
                        RoundKey_t *round_key);
static void InitRoundKey(const UAES_AES_Ctx_t *ctx, RoundKey_t *round_key);
static uint8_t GetRoundKey(const UAES_AES_Ctx_t *ctx,
                           RoundKey_t *round_key,
                           uint8_t idx);
static void ExpandRoundKey(uint8_t key_num_words,
                           uint8_t *round_key_buf,
                           uint8_t step,
                           uint8_t iter_num);
#endif // UAES_STORE_ROUND_KEY_IN_CTX
#if ENABLE_INV_CIPHER
static void InvCipher(const UAES_AES_Ctx_t *ctx,
                      const uint8_t input[16u],
                      uint8_t output[16u]);
static void InvMixColumns(State_t state);
static void InvSubBytes(State_t state);
static void InvShiftRows(State_t state);
#endif // ENABLE_INV_CIPHER
#else
// Declare the static functions.
static void Cipher(const UAES_AES_Ctx_t *ctx,
                   const uint8_t input[16u],
                   uint8_t output[16u]);
static void DataToState(const uint8_t data[16u], State_t state);
static void StateToData(const State_t state, uint8_t data[16u]);
static void SubBytes(State_t state);
static uint32_t SubWord(uint32_t x);
static void ShiftRows(State_t state);
static void MixColumns(State_t state);
static uint32_t Times2(uint32_t x);
static void InitAesCtx(UAES_AES_Ctx_t *ctx, const uint8_t *key, size_t key_len);

#if UAES_STORE_ROUND_KEY_IN_CTX
static void ExpandRoundKey(UAES_AES_Ctx_t *ctx);
static void AddRoundKey(const UAES_AES_Ctx_t *ctx,
                        uint8_t round,
                        State_t state);
#else
static void AddRoundKey(const UAES_AES_Ctx_t *ctx,
                        uint8_t round,
                        State_t state,
                        RoundKey_t *round_key);
static void InitRoundKey(const UAES_AES_Ctx_t *ctx, RoundKey_t *round_key);
static uint32_t GetRoundKey(const UAES_AES_Ctx_t *ctx,
                            RoundKey_t *round_key,
                            uint8_t word_idx);
static void ExpandRoundKey(uint8_t key_num_words,
                           uint32_t *round_key_buf,
                           uint8_t step,
                           uint8_t iter_num);
#endif // UAES_STORE_ROUND_KEY_IN_CTX
#if ENABLE_INV_CIPHER
static void InvCipher(const UAES_AES_Ctx_t *ctx,
                      const uint8_t input[16u],
                      uint8_t output[16u]);
static void InvMixColumns(State_t state);
static void InvSubBytes(State_t state);
static uint32_t InvSubWord(uint32_t x);
static void InvShiftRows(State_t state);
#endif
#endif // UAES_32BIT_MODE == 0

static uint8_t SubByte(uint8_t x);
#if ENABLE_INV_CIPHER
static uint8_t InvSubByte(uint8_t x);
#endif

#if UAES_SBOX_MODE == 0
static uint8_t Gf28Div(uint16_t a, uint16_t b, uint16_t *p_remain);
static uint8_t Gf28Inv(uint8_t x);
#endif // UAES_STATIC_SBOX == 0

#if (UAES_SBOX_MODE == 0) || (UAES_SBOX_MODE == 2)
static uint8_t SboxAffineTransform(uint8_t x);
#endif

#if UAES_SBOX_MODE == 2
static uint8_t s_sbox[256u] = { 0 };
#if ENABLE_INV_CIPHER
static uint8_t s_rsbox[256u] = { 0 };
#endif
static void EnsureSboxInitialized(void);
#endif

#if (ENABLE_INV_CIPHER == 1) || (UAES_SBOX_MODE == 0)
static uint32_t Multiply(uint32_t x, uint8_t y);
#endif

#if (ENABLE_INV_CIPHER == 1) && (UAES_SBOX_MODE == 0)
static uint8_t RSboxAffineTransform(uint8_t x);
#endif

#if (UAES_ENABLE_CTR != 0) || (UAES_ENABLE_CCM != 0) || (UAES_ENABLE_GCM != 0)
static void IterateKeyStream(const UAES_AES_Ctx_t *ctx,
                             uint8_t *counter,
                             uint8_t *key_stream);
#endif

#if (UAES_ENABLE_CBC != 0) || (UAES_ENABLE_CCM != 0)
static void XorBlocks(const uint8_t *b1, const uint8_t *b2, uint8_t *output);
#endif

#if UAES_ENABLE_CFB
static void CFB_Xcrypt(UAES_CFB_Ctx_t *ctx,
                       const uint8_t *input,
                       uint8_t *output,
                       size_t len,
                       uint8_t encrypt);
#endif

#if UAES_ENABLE_CFB1
static void CFB1_Xcrypt(UAES_CFB1_Ctx_t *ctx,
                        const uint8_t *input,
                        uint8_t *output,
                        size_t bit_len,
                        uint8_t encrypt);
#endif

#if UAES_ENABLE_CCM
static void CCM_Xcrypt(UAES_CCM_Ctx_t *ctx,
                       const uint8_t *input,
                       uint8_t *output,
                       size_t len,
                       bool encrypt);
#endif // UAES_ENABLE_CCM

#if UAES_ENABLE_GCM
static void DataToGhashState(const uint8_t data[16u], uint32_t u32[4u]);
static void GhashStateToData(const uint32_t u32[4u], uint8_t data[16u]);
static void Ghash(const UAES_GCM_Ctx_t *ctx,
                  const uint8_t input[16],
                  uint8_t output[16]);
static void GCM_Xcrypt(UAES_GCM_Ctx_t *ctx,
                       size_t len,
                       const uint8_t *input,
                       uint8_t *output,
                       bool encrypt);
#endif

#if UAES_ENABLE_ECB
void UAES_ECB_Init(UAES_ECB_Ctx_t *ctx, const uint8_t *key, size_t key_len)
{
    InitAesCtx(&ctx->aes_ctx, key, key_len);
}
#endif // UAES_ENABLE_ECB

#if UAES_ENABLE_ECB_ENCRYPT
void UAES_ECB_Encrypt(const UAES_ECB_Ctx_t *ctx,
                      const uint8_t *input,
                      uint8_t *output,
                      size_t len)
{
    for (size_t i = 0u; i < len; i += 16u) {
        Cipher(&ctx->aes_ctx, &input[i], &output[i]);
    }
}

void UAES_ECB_SimpleEncrypt(const uint8_t *key,
                            size_t key_len,
                            const uint8_t *input,
                            uint8_t *output,
                            size_t data_len)
{
    UAES_ECB_Ctx_t ctx;
    UAES_ECB_Init(&ctx, key, key_len);
    UAES_ECB_Encrypt(&ctx, input, output, data_len);
}

#endif // UAES_ENABLE_ECB_ENCRYPT

#if UAES_ENABLE_ECB_DECRYPT
void UAES_ECB_Decrypt(const UAES_ECB_Ctx_t *ctx,
                      const uint8_t *input,
                      uint8_t *output,
                      size_t len)
{
    for (size_t i = 0u; i < len; i += 16u) {
        InvCipher(&ctx->aes_ctx, &input[i], &output[i]);
    }
}

void UAES_ECB_SimpleDecrypt(const uint8_t *key,
                            size_t key_len,
                            const uint8_t *input,
                            uint8_t *output,
                            size_t data_len)
{
    UAES_ECB_Ctx_t ctx;
    UAES_ECB_Init(&ctx, key, key_len);
    UAES_ECB_Decrypt(&ctx, input, output, data_len);
}

#endif // UAES_ENABLE_ECB_DECRYPT

#if UAES_ENABLE_CBC
void UAES_CBC_Init(UAES_CBC_Ctx_t *ctx,
                   const uint8_t *key,
                   size_t key_len,
                   const uint8_t *iv)
{
    InitAesCtx(&ctx->aes_ctx, key, key_len);
    (void)memcpy(ctx->iv, iv, sizeof(ctx->iv));
}
#endif // UAES_ENABLE_CBC

#if UAES_ENABLE_CBC_ENCRYPT
void UAES_CBC_Encrypt(UAES_CBC_Ctx_t *ctx,
                      const uint8_t *input,
                      uint8_t *output,
                      size_t len)
{
    const uint8_t *iv = ctx->iv;
    for (size_t i = 0u; i < len; i += 16u) {
        XorBlocks(iv, &input[i], &output[i]);
        Cipher(&ctx->aes_ctx, &output[i], &output[i]);
        iv = &output[i];
    }
    // Store the iv in the context for later use.
    (void)memcpy(ctx->iv, iv, sizeof(ctx->iv));
}

void UAES_CBC_SimpleEncrypt(const uint8_t *key,
                            size_t key_len,
                            const uint8_t *iv,
                            const uint8_t *input,
                            uint8_t *output,
                            size_t data_len)
{
    UAES_CBC_Ctx_t ctx;
    UAES_CBC_Init(&ctx, key, key_len, iv);
    UAES_CBC_Encrypt(&ctx, input, output, data_len);
}

#endif // UAES_ENABLE_CBC_ENCRYPT

#if UAES_ENABLE_CBC_DECRYPT
void UAES_CBC_Decrypt(UAES_CBC_Ctx_t *ctx,
                      const uint8_t *input,
                      uint8_t *output,
                      size_t len)
{
    uint8_t next_iv[16u];
    for (size_t i = 0u; i < len; i += 16u) {
        (void)memcpy(next_iv, &input[i], 16u);
        InvCipher(&ctx->aes_ctx, &input[i], &output[i]);
        XorBlocks(ctx->iv, &output[i], &output[i]);
        (void)memcpy(ctx->iv, next_iv, 16u);
    }
}

void UAES_CBC_SimpleDecrypt(const uint8_t *key,
                            size_t key_len,
                            const uint8_t *iv,
                            const uint8_t *input,
                            uint8_t *output,
                            size_t data_len)
{
    UAES_CBC_Ctx_t ctx;
    UAES_CBC_Init(&ctx, key, key_len, iv);
    UAES_CBC_Decrypt(&ctx, input, output, data_len);
}

#endif // UAES_ENABLE_CBC_DECRYPT

#if UAES_ENABLE_CFB
void UAES_CFB_Init(UAES_CFB_Ctx_t *ctx,
                   uint8_t segment_size,
                   const uint8_t *key,
                   size_t key_len,
                   const uint8_t *iv)
{
    InitAesCtx(&ctx->aes_ctx, key, key_len);
    (void)memcpy(ctx->input_block, iv, sizeof(ctx->input_block));
    Cipher(&ctx->aes_ctx, ctx->input_block, ctx->cipher_block);
    ctx->byte_pos = 0u;
    // Limit the segment size to avoid unexpected behavior.
    ctx->segment_bytes = segment_size / 8u;
    if (ctx->segment_bytes < 1u) {
        ctx->segment_bytes = 1u;
    } else if (ctx->segment_bytes > 16u) {
        ctx->segment_bytes = 16u;
    } else {
        // Do nothing.
    }
}

void UAES_CFB_Encrypt(UAES_CFB_Ctx_t *ctx,
                      const uint8_t *input,
                      uint8_t *output,
                      size_t len)
{
    CFB_Xcrypt(ctx, input, output, len, 1);
}

void UAES_CFB_SimpleEncrypt(uint8_t segment_size,
                            const uint8_t *key,
                            size_t key_len,
                            const uint8_t *iv,
                            const uint8_t *input,
                            uint8_t *output,
                            size_t data_len)
{
    UAES_CFB_Ctx_t ctx;
    UAES_CFB_Init(&ctx, segment_size, key, key_len, iv);
    UAES_CFB_Encrypt(&ctx, input, output, data_len);
}

void UAES_CFB_Decrypt(UAES_CFB_Ctx_t *ctx,
                      const uint8_t *input,
                      uint8_t *output,
                      size_t len)
{
    CFB_Xcrypt(ctx, input, output, len, 0);
}

void UAES_CFB_SimpleDecrypt(uint8_t segment_size,
                            const uint8_t *key,
                            size_t key_len,
                            const uint8_t *iv,
                            const uint8_t *input,
                            uint8_t *output,
                            size_t data_len)
{
    UAES_CFB_Ctx_t ctx;
    UAES_CFB_Init(&ctx, segment_size, key, key_len, iv);
    UAES_CFB_Decrypt(&ctx, input, output, data_len);
}

static void CFB_Xcrypt(UAES_CFB_Ctx_t *ctx,
                       const uint8_t *input,
                       uint8_t *output,
                       size_t len,
                       uint8_t encrypt)
{
    for (size_t i = 0u; i < len; ++i) {
        if (ctx->byte_pos >= ctx->segment_bytes) {
            // Shift according to the segment size.
            (void)memcpy(ctx->cipher_block,
                         &ctx->input_block[ctx->segment_bytes],
                         (size_t)(16u - (size_t)ctx->segment_bytes));
            (void)memcpy(&ctx->cipher_block[16u - ctx->segment_bytes],
                         ctx->input_block,
                         ctx->segment_bytes);
            (void)memcpy(ctx->input_block, ctx->cipher_block, 16u);
            // Generate the next cipher block.
            Cipher(&ctx->aes_ctx, ctx->input_block, ctx->cipher_block);
            ctx->byte_pos = 0u;
        }
        if (encrypt == 0u) {
            ctx->input_block[ctx->byte_pos] = input[i];
        }
        output[i] = input[i] ^ ctx->cipher_block[ctx->byte_pos];
        if (encrypt == 1u) {
            ctx->input_block[ctx->byte_pos] = output[i];
        }
        ctx->byte_pos++;
    }
}

#endif // UAES_ENABLE_CFB

#if UAES_ENABLE_CFB1
void UAES_CFB1_Init(UAES_CFB1_Ctx_t *ctx,
                    const uint8_t *key,
                    size_t key_len,
                    const uint8_t *iv)
{
    InitAesCtx(&ctx->aes_ctx, key, key_len);
    (void)memcpy(ctx->input_block, iv, sizeof(ctx->input_block));
}

void UAES_CFB1_Encrypt(UAES_CFB1_Ctx_t *ctx,
                       const uint8_t *input,
                       uint8_t *output,
                       size_t bit_len)
{
    CFB1_Xcrypt(ctx, input, output, bit_len, 1);
}

void UAES_CFB1_SimpleEncrypt(const uint8_t *key,
                             size_t key_len,
                             const uint8_t *iv,
                             const uint8_t *input,
                             uint8_t *output,
                             size_t bit_len)
{
    UAES_CFB1_Ctx_t ctx;
    UAES_CFB1_Init(&ctx, key, key_len, iv);
    UAES_CFB1_Encrypt(&ctx, input, output, bit_len);
}

void UAES_CFB1_Decrypt(UAES_CFB1_Ctx_t *ctx,
                       const uint8_t *input,
                       uint8_t *output,
                       size_t bit_len)
{
    CFB1_Xcrypt(ctx, input, output, bit_len, 0);
}

void UAES_CFB1_SimpleDecrypt(const uint8_t *key,
                             size_t key_len,
                             const uint8_t *iv,
                             const uint8_t *input,
                             uint8_t *output,
                             size_t bit_len)
{
    UAES_CFB1_Ctx_t ctx;
    UAES_CFB1_Init(&ctx, key, key_len, iv);
    UAES_CFB1_Decrypt(&ctx, input, output, bit_len);
}

static void CFB1_Xcrypt(UAES_CFB1_Ctx_t *ctx,
                        const uint8_t *input,
                        uint8_t *output,
                        size_t bit_len,
                        uint8_t encrypt)
{
    uint8_t cipher_block[16u];
    for (size_t i = 0u; i < bit_len; ++i) {
        uint8_t byte_pos = (uint8_t)(i / 8u);
        uint8_t bit_mask = (uint8_t)(1u << (7u - (i % 8u)));
        uint8_t ct_bit = 0u;
        // Generate the cipher block.
        Cipher(&ctx->aes_ctx, ctx->input_block, cipher_block);
        uint8_t bit = (uint8_t)(input[byte_pos] & bit_mask);
        // When decrypting, the cipher text bit is the input bit.
        if (encrypt == 0u) {
            ct_bit = bit;
        }
        // Compute the cipher text bit.
        if ((cipher_block[0] & 0x80u) != 0u) {
            bit ^= bit_mask;
        }
        // When encrypting, the cipher text bit is the output bit.
        if (encrypt == 1u) {
            ct_bit = bit;
        }
        // Write the cipher text bit to the output.
        output[byte_pos] &= (uint8_t)(~bit_mask);
        output[byte_pos] |= bit;
        // Shift the input block.
        for (uint8_t j = 0u; j < 15u; ++j) {
            ctx->input_block[j] <<= 1u;
            ctx->input_block[j] |= (uint8_t)(ctx->input_block[j + 1u] >> 7u);
        }
        ctx->input_block[15u] <<= 1u;
        if (ct_bit != 0u) {
            ctx->input_block[15u] |= 1u;
        }
    }
}

#endif // UAES_ENABLE_CFB1

#if UAES_ENABLE_OFB
void UAES_OFB_Init(UAES_OFB_Ctx_t *ctx,
                   const uint8_t *key,
                   size_t key_len,
                   const uint8_t *iv)
{
    InitAesCtx(&ctx->aes_ctx, key, key_len);
    (void)memcpy(ctx->cipher_stream, iv, sizeof(ctx->cipher_stream));
    ctx->byte_pos = 16u;
}

void UAES_OFB_Encrypt(UAES_OFB_Ctx_t *ctx,
                      const uint8_t *input,
                      uint8_t *output,
                      size_t len)
{
    for (size_t i = 0u; i < len; ++i) {
        // If all the 16 bytes are used, generate the next block.
        if (ctx->byte_pos >= 16u) {
            Cipher(&ctx->aes_ctx, ctx->cipher_stream, ctx->cipher_stream);
            ctx->byte_pos = 0u;
        }
        output[i] = input[i] ^ ctx->cipher_stream[ctx->byte_pos];
        ctx->byte_pos++;
    }
}

void UAES_OFB_SimpleEncrypt(const uint8_t *key,
                            size_t key_len,
                            const uint8_t *iv,
                            const uint8_t *input,
                            uint8_t *output,
                            size_t data_len)
{
    UAES_OFB_Ctx_t ctx;
    UAES_OFB_Init(&ctx, key, key_len, iv);
    UAES_OFB_Encrypt(&ctx, input, output, data_len);
}

void UAES_OFB_Decrypt(UAES_OFB_Ctx_t *ctx,
                      const uint8_t *input,
                      uint8_t *output,
                      size_t len)
{
    UAES_OFB_Encrypt(ctx, input, output, len);
}

void UAES_OFB_SimpleDecrypt(const uint8_t *key,
                            size_t key_len,
                            const uint8_t *iv,
                            const uint8_t *input,
                            uint8_t *output,
                            size_t data_len)
{
    UAES_OFB_SimpleEncrypt(key, key_len, iv, input, output, data_len);
}
#endif // UAES_ENABLE_OFB

#if UAES_ENABLE_CTR
void UAES_CTR_Init(UAES_CTR_Ctx_t *ctx,
                   const uint8_t *key,
                   size_t key_len,
                   const uint8_t *nonce,
                   size_t nonce_len)
{
    InitAesCtx(&ctx->aes_ctx, key, key_len);
    for (size_t i = 0u; i < sizeof(ctx->counter); ++i) {
        if (i < nonce_len) {
            ctx->counter[i] = nonce[i];
        } else {
            ctx->counter[i] = 0u;
        }
    }
    ctx->byte_pos = 0u;
}

void UAES_CTR_Encrypt(UAES_CTR_Ctx_t *ctx,
                      const uint8_t *input,
                      uint8_t *output,
                      size_t len)
{
    uint8_t key_stream[16u];
    // Generate the key stream as it is not stored in the context.
    Cipher(&ctx->aes_ctx, ctx->counter, key_stream);
    for (size_t i = 0u; i < len; ++i) {
        // If all the 16 bytes are used, generate the next block.
        if (ctx->byte_pos >= 16u) {
            ctx->byte_pos = 0u;
            IterateKeyStream(&ctx->aes_ctx, ctx->counter, key_stream);
        }
        output[i] = input[i] ^ key_stream[ctx->byte_pos];
        ctx->byte_pos++;
    }
}

void UAES_CTR_SimpleEncrypt(const uint8_t *key,
                            size_t key_len,
                            const uint8_t *nonce,
                            size_t nonce_len,
                            const uint8_t *input,
                            uint8_t *output,
                            size_t data_len)
{
    UAES_CTR_Ctx_t ctx;
    UAES_CTR_Init(&ctx, key, key_len, nonce, nonce_len);
    UAES_CTR_Encrypt(&ctx, input, output, data_len);
}

void UAES_CTR_Decrypt(UAES_CTR_Ctx_t *ctx,
                      const uint8_t *input,
                      uint8_t *output,
                      size_t len)
{
    UAES_CTR_Encrypt(ctx, input, output, len);
}

void UAES_CTR_SimpleDecrypt(const uint8_t *key,
                            size_t key_len,
                            const uint8_t *nonce,
                            size_t nonce_len,
                            const uint8_t *input,
                            uint8_t *output,
                            size_t data_len)
{
    UAES_CTR_SimpleEncrypt(key,
                           key_len,
                           nonce,
                           nonce_len,
                           input,
                           output,
                           data_len);
}

#endif

#if UAES_ENABLE_CCM
void UAES_CCM_Init(UAES_CCM_Ctx_t *ctx,
                   const uint8_t *key,
                   size_t key_len,
                   const uint8_t *nonce,
                   uint8_t nonce_len,
                   size_t aad_len,
                   size_t data_len,
                   uint8_t tag_len)
{
    (void)memset(ctx, 0, sizeof(UAES_CCM_Ctx_t));
    InitAesCtx(&ctx->aes_ctx, key, key_len);
    uint8_t tag_bits_l = 14u - (uint8_t)nonce_len;
    uint8_t tag_bits_m = (uint8_t)((tag_len - 2u) / 2u);
    ctx->cbc_buf[0u] = tag_bits_l | (uint8_t)(tag_bits_m << 3u);
    if (aad_len > 0u) {
        ctx->cbc_buf[0u] |= 0x40u;
    }
    ctx->counter[0u] = tag_bits_l;
    for (uint8_t i = 1u; i <= nonce_len; ++i) {
        ctx->counter[i] = nonce[i - 1u];
        ctx->cbc_buf[i] = nonce[i - 1u];
    }
    size_t tmp = data_len;
    for (uint8_t i = 15u; i > nonce_len; --i) {
        ctx->counter[i] = 0u;
        ctx->cbc_buf[i] = (uint8_t)tmp;
        tmp >>= 8u;
    }
    ctx->nonce_len = nonce_len;
    // Process AAD length field.
    if (aad_len > 0u) {
        Cipher(&ctx->aes_ctx, ctx->cbc_buf, ctx->cbc_buf);
        uint8_t aad_len_bytes;
        if (aad_len < 0xFF00u) {
            ctx->aad_byte_pos = 0u;
            aad_len_bytes = 2u;
        } else if (aad_len < 0xFFFFFFFFu) {
            ctx->cbc_buf[0] ^= 0xFFu;
            ctx->cbc_buf[1] ^= 0xFEu;
            ctx->aad_byte_pos = 2u;
            aad_len_bytes = 4u;
        } else {
            ctx->cbc_buf[0] ^= 0xFFu;
            ctx->cbc_buf[1] ^= 0xFFu;
            ctx->aad_byte_pos = 2u;
            aad_len_bytes = 8u;
        }
        for (uint8_t i = 0u; i < aad_len_bytes; ++i) {
            uint8_t shift = (uint8_t)(8u * ((aad_len_bytes - i) - 1u));
            ctx->cbc_buf[ctx->aad_byte_pos + i] ^= (uint8_t)(aad_len >> shift);
        }
        ctx->aad_byte_pos += aad_len_bytes;
    }
    // Counter == 0 is not used for encryption in CCM mode.
    // set ctx->byte_pos = 16u to skip it.
    ctx->byte_pos = 16u;
}

void UAES_CCM_AddAad(UAES_CCM_Ctx_t *ctx, const uint8_t *aad, size_t len)
{
    for (size_t i = 0u; i < len; ++i) {
        if (ctx->aad_byte_pos >= 16u) {
            Cipher(&ctx->aes_ctx, ctx->cbc_buf, ctx->cbc_buf);
            ctx->aad_byte_pos = 0u;
        }
        ctx->cbc_buf[ctx->aad_byte_pos] ^= aad[i];
        ctx->aad_byte_pos++;
    }
}

void UAES_CCM_Encrypt(UAES_CCM_Ctx_t *ctx,
                      const uint8_t *input,
                      uint8_t *output,
                      size_t len)
{
    CCM_Xcrypt(ctx, input, output, len, true);
}

void UAES_CCM_Decrypt(UAES_CCM_Ctx_t *ctx,
                      const uint8_t *input,
                      uint8_t *output,
                      size_t len)
{
    CCM_Xcrypt(ctx, input, output, len, false);
}

void UAES_CCM_GenerateTag(const UAES_CCM_Ctx_t *ctx,
                          uint8_t *tag,
                          uint8_t tag_len)
{
    uint8_t ctr_tag[16u];
    uint8_t cbc_tag[16u];
    for (uint8_t i = 0u; i < 16u; ++i) {
        if (i <= ctx->nonce_len) {
            ctr_tag[i] = ctx->counter[i];
        } else {
            ctr_tag[i] = 0u;
        }
    }
    Cipher(&ctx->aes_ctx, ctr_tag, ctr_tag);
    Cipher(&ctx->aes_ctx, ctx->cbc_buf, cbc_tag);
    XorBlocks(ctr_tag, cbc_tag, cbc_tag);
    (void)memcpy(tag, cbc_tag, tag_len);
}

bool UAES_CCM_VerifyTag(const UAES_CCM_Ctx_t *ctx,
                        const uint8_t *tag,
                        uint8_t tag_len)
{
    uint8_t expected_tag[16u];
    UAES_CCM_GenerateTag(ctx, expected_tag, tag_len);
    return (memcmp(expected_tag, tag, tag_len) == 0);
}

void UAES_CCM_SimpleEncrypt(const uint8_t *key,
                            size_t key_len,
                            const uint8_t *nonce,
                            uint8_t nonce_len,
                            const uint8_t *aad,
                            size_t aad_len,
                            const uint8_t *input,
                            uint8_t *output,
                            size_t data_len,
                            uint8_t *tag,
                            uint8_t tag_len)
{
    UAES_CCM_Ctx_t ctx;
    UAES_CCM_Init(&ctx,
                  key,
                  key_len,
                  nonce,
                  nonce_len,
                  aad_len,
                  data_len,
                  tag_len);
    UAES_CCM_AddAad(&ctx, aad, aad_len);
    UAES_CCM_Encrypt(&ctx, input, output, data_len);
    UAES_CCM_GenerateTag(&ctx, tag, tag_len);
}

bool UAES_CCM_SimpleDecrypt(const uint8_t *key,
                            size_t key_len,
                            const uint8_t *nonce,
                            uint8_t nonce_len,
                            const uint8_t *aad,
                            size_t aad_len,
                            const uint8_t *input,
                            uint8_t *output,
                            size_t data_len,
                            const uint8_t *tag,
                            uint8_t tag_len)
{
    UAES_CCM_Ctx_t ctx;
    UAES_CCM_Init(&ctx,
                  key,
                  key_len,
                  nonce,
                  nonce_len,
                  aad_len,
                  data_len,
                  tag_len);
    UAES_CCM_AddAad(&ctx, aad, aad_len);
    UAES_CCM_Decrypt(&ctx, input, output, data_len);
    return UAES_CCM_VerifyTag(&ctx, tag, tag_len);
}

#endif // UAES_ENABLE_CCM

#if UAES_ENABLE_GCM
void UAES_GCM_Init(UAES_GCM_Ctx_t *ctx,
                   const uint8_t *key,
                   size_t key_len,
                   const uint8_t *iv,
                   size_t iv_len)
{
    (void)memset(ctx, 0, sizeof(UAES_GCM_Ctx_t));
    InitAesCtx(&ctx->aes_ctx, key, key_len);

    // Compute the hash key by encrypting a zero vector with AES cipher
    uint8_t hash_key[16u];
    (void)memset(hash_key, 0, sizeof(hash_key));
    Cipher(&ctx->aes_ctx, hash_key, hash_key);
    DataToGhashState(hash_key, ctx->hash_key);

    // If iv is 12 bytes, use it directly as the initial counter value.
    // Otherwise, compute the initial counter value from the IV with GHash.
    if (iv_len == 12u) {
        (void)memcpy(ctx->counter, iv, 12u);
        ctx->counter[15u] = 1u; // start "counting" from 1 (not 0)
    } else {
        // Step 1: pad IV with zeros to multiple of 16 bytes and do GHash for
        // each 16 bytes block.
        for (size_t i = 0u; i < iv_len; i += 16u) {
            for (size_t j = 0u; j < 16u; ++j) {
                if ((i + j) < iv_len) {
                    ctx->counter[j] ^= iv[i + j];
                } else {
                    break;
                }
            }
            Ghash(ctx, ctx->counter, ctx->counter);
        }
        // Step 2: the last block consists 64 zeros and the big-endian encoding
        // of the number of bits in the IV.
        size_t iv_len_bits = iv_len * 8u;
        for (size_t i = 0u; i < sizeof(iv_len_bits); ++i) {
            ctx->counter[15u - i] ^= (uint8_t)(iv_len_bits >> (i * 8u));
        }
        Ghash(ctx, ctx->counter, ctx->counter);
    }
}

void UAES_GCM_AddAad(UAES_GCM_Ctx_t *ctx, const uint8_t *aad, size_t len)
{
    // To simplify the implementation, there would be an redundant Ghash(0) at
    // the beginning of the GCM. However, since the result of Ghash(0) is still
    // 0, it does not affect the result.
    for (size_t i = 0u; i < len; ++i) {
        if ((ctx->aad_len % 16u) == 0u) {
            Ghash(ctx, ctx->hash_buf, ctx->hash_buf);
        }
        ctx->hash_buf[ctx->aad_len % 16u] ^= aad[i];
        ctx->aad_len++;
    }
}

void UAES_GCM_Encrypt(UAES_GCM_Ctx_t *ctx,
                      const uint8_t *input,
                      uint8_t *output,
                      size_t len)
{
    GCM_Xcrypt(ctx, len, input, output, true);
}

void UAES_GCM_Decrypt(UAES_GCM_Ctx_t *ctx,
                      const uint8_t *input,
                      uint8_t *output,
                      size_t len)
{
    GCM_Xcrypt(ctx, len, input, output, false);
}

void UAES_GCM_GenerateTag(const UAES_GCM_Ctx_t *ctx,
                          uint8_t *tag,
                          size_t tag_len)
{
    // Use a local hash_buf to avoid error when called multiple times.
    uint8_t hash_buf[16];
    size_t data_bits = ctx->data_len * 8u;
    size_t aad_bits = ctx->aad_len * 8u;

    (void)memcpy(hash_buf, ctx->hash_buf, 16u);
    // Do Ghash on the last data block.
    // If len_data > 0, this is the last block of the data.
    // If len_data == 0, this is the last block of the additional data.
    // If both len_data and len_add == 0, the input is all zero, thus has no
    // effect.
    Ghash(ctx, hash_buf, hash_buf);
    // The last block of Ghash consists the length of AAD and data in bits.
    for (size_t i = 0u; i < 8u; ++i) {
        hash_buf[i] ^= (uint8_t)(aad_bits >> (8u * (7u - i)));
    }
    for (size_t i = 8u; i < 16u; ++i) {
        hash_buf[i] ^= (uint8_t)(data_bits >> (8u * (15u - i)));
    }
    Ghash(ctx, hash_buf, hash_buf);
    // To save RAM, the counter0 is not stored in the context. Instead, it is
    // recovered by subtracting the counter with data_len/16.
    uint8_t counter0[16u];
    size_t remain = (ctx->data_len + 15u) / 16u;
    (void)memcpy(counter0, ctx->counter, sizeof(counter0));
    for (uint8_t pos = 15u; pos > 0u; --pos) {
        if (counter0[pos] >= (remain & 0xFFu)) {
            counter0[pos] -= (uint8_t)(remain & 0xFFu);
            remain = remain >> 8u;
            if (remain == 0u) {
                break;
            }
        } else {
            counter0[pos] += (uint8_t)(0x100u - (remain & 0xFFu));
            remain = (remain >> 8u) + 1u;
        }
    }
    // The tag is the encrypted counter0 XORed with the hash_buf.
    Cipher(&ctx->aes_ctx, counter0, counter0);
    for (size_t i = 0u; i < tag_len; ++i) {
        tag[i] = hash_buf[i] ^ counter0[i];
    }
}

bool UAES_GCM_VerifyTag(const UAES_GCM_Ctx_t *ctx,
                        const uint8_t *tag,
                        size_t tag_len)
{
    uint8_t expected_tag[16u];
    UAES_GCM_GenerateTag(ctx, expected_tag, tag_len);
    return (memcmp(expected_tag, tag, tag_len) == 0);
}

void UAES_GCM_SimpleEncrypt(const uint8_t *key,
                            size_t key_len,
                            const uint8_t *iv,
                            size_t iv_len,
                            const uint8_t *aad,
                            size_t aad_len,
                            const uint8_t *input,
                            uint8_t *output,
                            size_t data_len,
                            uint8_t *tag,
                            size_t tag_len)
{
    UAES_GCM_Ctx_t ctx;
    UAES_GCM_Init(&ctx, key, key_len, iv, iv_len);
    UAES_GCM_AddAad(&ctx, aad, aad_len);
    UAES_GCM_Encrypt(&ctx, input, output, data_len);
    UAES_GCM_GenerateTag(&ctx, tag, tag_len);
}

bool UAES_GCM_SimpleDecrypt(const uint8_t *key,
                            size_t key_len,
                            const uint8_t *iv,
                            size_t iv_len,
                            const uint8_t *aad,
                            size_t aad_len,
                            const uint8_t *input,
                            uint8_t *output,
                            size_t data_len,
                            const uint8_t *tag,
                            size_t tag_len)
{
    UAES_GCM_Ctx_t ctx;
    UAES_GCM_Init(&ctx, key, key_len, iv, iv_len);
    UAES_GCM_AddAad(&ctx, aad, aad_len);
    UAES_GCM_Decrypt(&ctx, input, output, data_len);
    return UAES_GCM_VerifyTag(&ctx, tag, tag_len);
}

static void Ghash(const UAES_GCM_Ctx_t *ctx,
                  const uint8_t input[16],
                  uint8_t output[16])
{
    // The state is stored in 4 big endianess uint32.
    // the low bit of buf[3] is the highest bit of the state.
    // the high bit of buf[0] is the lowest bit of the state.
    // The algorithm compute H*input by multiplying each bit of input with H
    // from the highest bit to the lowest bit.
    // Note that this is different  function Multiply() used in InvMixColumns().
    uint32_t buf[4u];
    (void)memset(buf, 0, sizeof(buf));
    for (uint8_t i = 16u; i > 0u; --i) {
        uint8_t tmp = input[i - 1u];
        for (uint8_t j = 0u; j < 8u; ++j) {
            uint32_t carry = buf[3] & 1u;
            buf[3] = (buf[3] >> 1u) | (buf[2] << 31u);
            buf[2] = (buf[2] >> 1u) | (buf[1] << 31u);
            buf[1] = (buf[1] >> 1u) | (buf[0] << 31u);
            buf[0] = (buf[0] >> 1u);
            if (carry != 0u) {
                // Corresponds to the polynomial x^128 + x^7 + x^2 + x + 1
                buf[0] ^= 0xe1000000u;
            }
            if ((tmp & 1u) != 0u) {
                buf[0] ^= ctx->hash_key[0u];
                buf[1] ^= ctx->hash_key[1u];
                buf[2] ^= ctx->hash_key[2u];
                buf[3] ^= ctx->hash_key[3u];
            }
            tmp >>= 1u;
        }
    }
    GhashStateToData(buf, output);
}

// Do encryption/decryption.
static void GCM_Xcrypt(UAES_GCM_Ctx_t *ctx,
                       size_t len,
                       const uint8_t *input,
                       uint8_t *output,
                       bool encrypt)
{
    uint8_t key_stream[16u];
    // Generate the key stream as it is not stored in the context.
    Cipher(&ctx->aes_ctx, ctx->counter, key_stream);
    for (size_t i = 0u; i < len; i++) {
        if ((ctx->data_len % 16u) == 0u) {
            IterateKeyStream(&ctx->aes_ctx, ctx->counter, key_stream);
            // Do Ghash for previous block.
            // If called the first time in this function, it compute the Ghash
            // for the last block of AAD. If len_aad == 0, then the hash_buf is
            // all zero, thus has no effect.
            Ghash(ctx, ctx->hash_buf, ctx->hash_buf);
        }
        size_t byte_pos = ctx->data_len % 16u;
        // The only difference between encryption and decryption is here.
        // When encrypting, the hash_buf is XORed with the output after
        // encryption, and when decrypting, the hash_buf is XORed with the
        // input before decryption.
        if (encrypt) {
            output[i] = (uint8_t)(key_stream[byte_pos] ^ input[i]);
            ctx->hash_buf[byte_pos] ^= output[i];
        } else {
            ctx->hash_buf[byte_pos] ^= input[i];
            output[i] = (uint8_t)(key_stream[byte_pos] ^ input[i]);
        }
        ctx->data_len++;
    }
}
#endif // UAES_ENABLE_GCM

#if UAES_32BIT_MODE == 0
// Cipher is the main function that encrypts the PlainText.
static void Cipher(const UAES_AES_Ctx_t *ctx,
                   const uint8_t input[16u],
                   uint8_t output[16u])
{
    (void)memcpy(output, input, 16u);
#if UAES_STORE_ROUND_KEY_IN_CTX
    // Add the First round key to the state before starting the rounds.
    AddRoundKey(ctx, 0, output);
#else
    RoundKey_t round_key;
    InitRoundKey(ctx, &round_key);
    // Add the First round key to the state before starting the rounds.
    AddRoundKey(ctx, 0, output, &round_key);
#endif

    // There are NUM_ROUNDS rounds.
    // The first NUM_ROUNDS-1 rounds are identical.
    // Last one without MixColumns()
    // It is 10 for 128-bit key, 12 for 192-bit key, and 14 for 256-bit key.
    uint8_t num_rounds = ctx->keysize_word + 6u;
    for (uint8_t round = 1u; round <= num_rounds; ++round) {
        SubBytes(output);
        ShiftRows(output);
        if (round < num_rounds) {
            MixColumns(output);
        }
#if UAES_STORE_ROUND_KEY_IN_CTX
        AddRoundKey(ctx, round, output);
#else
        AddRoundKey(ctx, round, output, &round_key);
#endif
    }
}

// Substitutes the whole matrix with values in the S-box.
static void SubBytes(State_t state)
{
    for (uint8_t i = 0u; i < 16u; ++i) {
        state[i] = SubByte(state[i]);
    }
}

// Shifts the rows in the state to the left. Each row is shifted with different
// offset. Offset = Row number. So the first row is not shifted.
// Since the data is stored in little endian order, the shift direction is
// reversed.
static void ShiftRows(State_t state)
{
    uint8_t tmp;
    // No change on first row
    // Row 1
    tmp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = tmp;
    // Row 2
    tmp = state[2];
    state[2] = state[10];
    state[10] = tmp;
    tmp = state[6];
    state[6] = state[14];
    state[14] = tmp;
    // Row 3
    tmp = state[3];
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = tmp;
}

// Mixes the columns of the state matrix.
static void MixColumns(State_t state)
{
    for (uint8_t i = 0u; i < 4u; ++i) {
        uint8_t *p = &state[i * 4u];
        uint8_t sum = p[0] ^ p[1] ^ p[2] ^ p[3];
        uint8_t p0 = p[0];
        p[0] ^= sum ^ Times2(p[0] ^ p[1]);
        p[1] ^= sum ^ Times2(p[1] ^ p[2]);
        p[2] ^= sum ^ Times2(p[2] ^ p[3]);
        p[3] ^= sum ^ Times2(p[3] ^ p0);
    }
}

// Multiply each byte in the word by 2 in the field GF(2^8).
static uint8_t Times2(uint8_t x)
{
    return (uint8_t)((x << 1u) ^ ((x >> 7u) * 0x1Bu));
}

// Initialize the context of AES cipher.
static void InitAesCtx(UAES_AES_Ctx_t *ctx, const uint8_t *key, size_t key_len)
{
#if UAES_SBOX_MODE == 2
    EnsureSboxInitialized();
#endif
    // A valid key length is required as input.
    // However, if an invalid key length is given, set it to a valid value to
    // avoid crashing.
    ctx->keysize_word = 0u;
#if UAES_ENABLE_128
    if (key_len == 16u) {
        ctx->keysize_word = 4u;
    }
#endif
#if UAES_ENABLE_192
    if (key_len == 24u) {
        ctx->keysize_word = 6u;
    }
#endif
#if UAES_ENABLE_256
    if (key_len == 32u) {
        ctx->keysize_word = 8u;
    }
#endif
    if (ctx->keysize_word == 0u) {
        ctx->keysize_word = (uint8_t)(UAES_MAX_KEY_SIZE / 32u);
    }
#if UAES_32BIT_MODE == 0
    (void)memcpy(ctx->key, key, key_len);
#else
    for (uint8_t i = 0u; i < ctx->keysize_word; ++i) {
        ctx->key[i] = 0u;
        for (uint8_t j = 0u; j < 4u; ++j) {
            uint32_t shift = (uint32_t)j * 8u;
            ctx->key[i] |= ((uint32_t)key[(i * 4u) + j]) << shift;
        }
    }
#endif
#if UAES_STORE_ROUND_KEY_IN_CTX
    ExpandRoundKey(ctx);
#endif
}

#if UAES_STORE_ROUND_KEY_IN_CTX
// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(const UAES_AES_Ctx_t *ctx, uint8_t round, State_t state)
{
    uint8_t key_start = (uint8_t)(round * 16u);
    for (uint8_t i = 0u; i < 16u; ++i) {
        state[i] ^= ctx->key[key_start + i];
    }
}

// Expand the round key. This is only called at the initialization.
static void ExpandRoundKey(UAES_AES_Ctx_t *ctx)
{
    // The round constant word array, RCON[i], contains the values given by
    // x power i in the field GF(2^8).
    static const uint8_t RCON[10] = { 0x01, 0x02, 0x04, 0x08, 0x10,
                                      0x20, 0x40, 0x80, 0x1b, 0x36 };
    uint8_t round_key_len = (uint8_t)((ctx->keysize_word + 7u) * 4u);
    uint8_t rcon_idx = 0u;
    for (uint8_t i = ctx->keysize_word; i < round_key_len; ++i) {
        uint8_t tmp[4]; // Store the intermediate results
        tmp[0] = ctx->key[(i * 4u) - 4u];
        tmp[1] = ctx->key[(i * 4u) - 3u];
        tmp[2] = ctx->key[(i * 4u) - 2u];
        tmp[3] = ctx->key[(i * 4u) - 1u];
        if ((i % ctx->keysize_word) == 0u) {
            uint8_t tt = tmp[0];
            tmp[0] = SubByte(tmp[1]) ^ RCON[rcon_idx];
            tmp[1] = SubByte(tmp[2]);
            tmp[2] = SubByte(tmp[3]);
            tmp[3] = SubByte(tt);
            rcon_idx++;
        }
#if UAES_ENABLE_256
        if ((ctx->keysize_word == 8u) && ((i % 8u) == 4u)) {
            tmp[0] = SubByte(tmp[0]);
            tmp[1] = SubByte(tmp[1]);
            tmp[2] = SubByte(tmp[2]);
            tmp[3] = SubByte(tmp[3]);
        }
#endif
        uint8_t p = i * 4u;
        uint8_t q = (i - ctx->keysize_word) * 4u;
        ctx->key[p] = ctx->key[q] ^ tmp[0];
        ctx->key[p + 1u] = ctx->key[q + 1u] ^ tmp[1];
        ctx->key[p + 2u] = ctx->key[q + 2u] ^ tmp[2];
        ctx->key[p + 3u] = ctx->key[q + 3u] ^ tmp[3];
    }
}
#else

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(const UAES_AES_Ctx_t *ctx,
                        uint8_t round,
                        State_t state,
                        RoundKey_t *round_key)
{
    uint8_t key_start = (uint8_t)(round * 16u);
    for (uint8_t i = 0u; i < 16u; ++i) {
        state[i] ^= GetRoundKey(ctx, round_key, key_start + i);
    }
}

// Initializing the round key struct by storing the key to the buffer.
// Refer to https://en.wikipedia.org/wiki/AES_key_schedule for more details.
static void InitRoundKey(const UAES_AES_Ctx_t *ctx, RoundKey_t *round_key)
{
    round_key->iter_num = 0u;
    (void)memcpy(round_key->buf, ctx->key, sizeof(round_key->buf));
}

// Get the specific byte of the round keys. Do key expansion when necessary.
static uint8_t GetRoundKey(const UAES_AES_Ctx_t *ctx,
                           RoundKey_t *round_key,
                           uint8_t idx)
{
    // Iterate until
    // iter_num * NUM_KEY_WORDS <= idx/4 < (iter_num + 1) * NUM_KEY_WORDS
    while (((round_key->iter_num + 1u) * ctx->keysize_word) <= (idx >> 2u)) {
        for (uint8_t i = 0u; i < ctx->keysize_word; ++i) {
            ExpandRoundKey(ctx->keysize_word,
                           round_key->buf,
                           i,
                           round_key->iter_num);
        }
        round_key->iter_num++;
    }
    // When invert cipher is disabled, word_idx will always be increasing, so
    // there is no need to iterate back.
#if ENABLE_INV_CIPHER
    while ((round_key->iter_num * ctx->keysize_word) > (idx >> 2u)) {
        round_key->iter_num--;
        for (uint8_t i = 0u; i < ctx->keysize_word; ++i) {
            ExpandRoundKey(ctx->keysize_word,
                           round_key->buf,
                           (uint8_t)((ctx->keysize_word - i) - 1u),
                           round_key->iter_num);
        }
    }
#endif
    return round_key->buf[idx - (round_key->iter_num * ctx->keysize_word * 4u)];
}

// Iterate the round key expansion.
static void ExpandRoundKey(uint8_t key_num_words,
                           uint8_t *round_key_buf,
                           uint8_t step,
                           uint8_t iter_num)
{
    // The round constant word array, RCON[i], contains the values given by
    // x power i in the field GF(2^8).
    static const uint8_t RCON[10] = { 0x01, 0x02, 0x04, 0x08, 0x10,
                                      0x20, 0x40, 0x80, 0x1b, 0x36 };
    uint8_t tmp[4u]; // Store the intermediate results
    const uint8_t *p;
    if (step > 0u) {
        p = (const uint8_t *)&round_key_buf[(step - 1u) * 4u];
    } else {
        p = (const uint8_t *)&round_key_buf[(key_num_words - 1u) * 4u];
    }
    tmp[0] = p[0];
    tmp[1] = p[1];
    tmp[2] = p[2];
    tmp[3] = p[3];
    if (step == 0u) {
        uint8_t tt = tmp[0];
        tmp[0] = SubByte(tmp[1]) ^ RCON[iter_num];
        tmp[1] = SubByte(tmp[2]);
        tmp[2] = SubByte(tmp[3]);
        tmp[3] = SubByte(tt);
    }
#if UAES_ENABLE_256
    if ((key_num_words == 8u) && (step == 4u)) {
        tmp[0] = SubByte(tmp[0]);
        tmp[1] = SubByte(tmp[1]);
        tmp[2] = SubByte(tmp[2]);
        tmp[3] = SubByte(tmp[3]);
    }
#endif
    round_key_buf[step * 4u] ^= tmp[0];
    round_key_buf[(step * 4u) + 1u] ^= tmp[1];
    round_key_buf[(step * 4u) + 2u] ^= tmp[2];
    round_key_buf[(step * 4u) + 3u] ^= tmp[3];
}
#endif // UAES_STORE_ROUND_KEY_IN_CTX
#if ENABLE_INV_CIPHER
// The main function that decrypts the CipherText.
static void InvCipher(const UAES_AES_Ctx_t *ctx,
                      const uint8_t input[16u],
                      uint8_t output[16u])
{
#if UAES_STORE_ROUND_KEY_IN_CTX == 0
    RoundKey_t round_key;
    InitRoundKey(ctx, &round_key);
#endif
    (void)memcpy(output, input, 16u);
    // It is 10 for 128-bit key, 12 for 192-bit key, and 14 for 256-bit key.
    uint8_t num_rounds = ctx->keysize_word + 6u;
    // The decryption process is the reverse of encrypting process.
    for (uint8_t round = num_rounds; round > 0u; --round) {
#if UAES_STORE_ROUND_KEY_IN_CTX
        AddRoundKey(ctx, round, output);
#else
        AddRoundKey(ctx, round, output, &round_key);
#endif
        if (round < num_rounds) {
            InvMixColumns(output);
        }
        InvShiftRows(output);
        InvSubBytes(output);
    }
#if UAES_STORE_ROUND_KEY_IN_CTX
    AddRoundKey(ctx, 0, output);
#else
    // Add the First round key as the last step
    AddRoundKey(ctx, 0, output, &round_key);
#endif
}

// Reverses the MixColumns step in the Cipher.
static void InvMixColumns(State_t state)
{
    for (uint8_t i = 0u; i < 4u; ++i) {
        uint8_t a[4];
        a[0] = state[i * 4u];
        a[1] = state[(i * 4u) + 1u];
        a[2] = state[(i * 4u) + 2u];
        a[3] = state[(i * 4u) + 3u];
        for (uint8_t j = 0u; j < 4u; ++j) {
            state[(i * 4u) + j] = Multiply(a[j], 0x0e);
            state[(i * 4u) + j] ^= Multiply(a[(j + 1u) & 3u], 0x0b);
            state[(i * 4u) + j] ^= Multiply(a[(j + 2u) & 3u], 0x0d);
            state[(i * 4u) + j] ^= Multiply(a[(j + 3u) & 3u], 0x09);
        }
    }
}

// Reverses the SubBytes step in the Cipher.
static void InvSubBytes(State_t state)
{
    for (uint8_t i = 0u; i < 16u; ++i) {
        state[i] = InvSubByte(state[i]);
    }
}

// Reverses the ShiftRows step in the Cipher.
static void InvShiftRows(State_t state)
{
    uint8_t tmp;
    // No change on first row
    // Row 1
    tmp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = tmp;
    // Row 2
    tmp = state[10];
    state[10] = state[2];
    state[2] = tmp;
    tmp = state[14];
    state[14] = state[6];
    state[6] = tmp;
    // Row 3
    tmp = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = state[3];
    state[3] = tmp;
}

#endif
#else
// Cipher is the main function that encrypts the PlainText.
static void Cipher(const UAES_AES_Ctx_t *ctx,
                   const uint8_t input[16u],
                   uint8_t output[16u])
{
    State_t state;
    DataToState(input, state);

#if UAES_STORE_ROUND_KEY_IN_CTX
    // Add the First round key to the state before starting the rounds.
    AddRoundKey(ctx, 0, state);
#else
    RoundKey_t round_key;
    InitRoundKey(ctx, &round_key);
    // Add the First round key to the state before starting the rounds.
    AddRoundKey(ctx, 0, state, &round_key);
#endif

    // There are NUM_ROUNDS rounds.
    // The first NUM_ROUNDS-1 rounds are identical.
    // Last one without MixColumns()
    // It is 10 for 128-bit key, 12 for 192-bit key, and 14 for 256-bit key.
    uint8_t num_rounds = ctx->keysize_word + 6u;
    for (uint8_t round = 1u; round <= num_rounds; ++round) {
        SubBytes(state);
        ShiftRows(state);
        if (round < num_rounds) {
            MixColumns(state);
        }
#if UAES_STORE_ROUND_KEY_IN_CTX
        AddRoundKey(ctx, round, state);
#else
        AddRoundKey(ctx, round, state, &round_key);
#endif
    }
    StateToData(state, output);
}

// Store the 4x4 bytes AES cipher matrix by 4 uint32.
// To make the best use of 32-bit CPU, each uint32 represents a row in the
// matrix.
static void DataToState(const uint8_t data[16u], State_t state)
{
    for (uint8_t i = 0u; i < 4u; ++i) {
        state[i] = 0u;
        for (uint8_t j = 0u; j < 4u; ++j) {
            uint32_t shift = (uint32_t)j * 8u;
            state[i] |= ((uint32_t)data[i + (j * 4u)]) << shift;
        }
    }
}

// Reverse of DataToState()
static void StateToData(const State_t state, uint8_t data[16u])
{
    for (uint8_t i = 0u; i < 4u; ++i) {
        for (uint8_t j = 0u; j < 4u; ++j) {
            uint32_t shift = (uint32_t)j * 8u;
            data[i + (j * 4u)] = (uint8_t)((state[i] >> shift) & 0xFFu);
        }
    }
}

// Substitutes the whole matrix with values in the S-box.
static void SubBytes(State_t state)
{
    state[0] = SubWord(state[0]);
    state[1] = SubWord(state[1]);
    state[2] = SubWord(state[2]);
    state[3] = SubWord(state[3]);
}

// Substitutes each byte in the word with values in the S-box.
static uint32_t SubWord(uint32_t x)
{
    uint32_t tmp = 0u;
    for (uint8_t i = 0u; i <= 24u; i += 8u) {
        tmp |= (uint32_t)SubByte((uint8_t)(x >> i)) << i;
    }
    return tmp;
}

// Shifts the rows in the state to the left. Each row is shifted with different
// offset. Offset = Row number. So the first row is not shifted.
// Since the data is stored in little endian order, the shift direction is
// reversed.
static void ShiftRows(State_t state)
{
    // No change on first row
    state[1] = (state[1] >> 8u) | (state[1] << 24u);
    state[2] = (state[2] >> 16u) | (state[2] << 16u);
    state[3] = (state[3] >> 24u) | (state[3] << 8u);
}

// Mixes the columns of the state matrix.
// Since most operations are bitwise, the four columns are mixed at the same
// time to make the best use of 32-bit CPU.
static void MixColumns(State_t state)
{
    uint32_t sum = state[0] ^ state[1] ^ state[2] ^ state[3];
    uint32_t tmp = state[0];
    state[0] ^= sum ^ Times2(state[0] ^ state[1]);
    state[1] ^= sum ^ Times2(state[1] ^ state[2]);
    state[2] ^= sum ^ Times2(state[2] ^ state[3]);
    state[3] ^= sum ^ Times2(state[3] ^ tmp);
}

// Multiply each byte in the word by 2 in the field GF(2^8).
static uint32_t Times2(uint32_t x)
{
    uint32_t p1 = (x << 1u) & 0xFEFEFEFEu;
    uint32_t p2 = ((x >> 7u) & 0x01010101u) * 0x1Bu;
    return p1 ^ p2;
}

// Initialize the context of AES cipher.
static void InitAesCtx(UAES_AES_Ctx_t *ctx, const uint8_t *key, size_t key_len)
{
#if UAES_SBOX_MODE == 2
    EnsureSboxInitialized();
#endif
    // A valid key length is required as input.
    // However, if an invalid key length is given, set it to a valid value to
    // avoid crashing.
    ctx->keysize_word = 0u;
#if UAES_ENABLE_128
    if (key_len == 16u) {
        ctx->keysize_word = 4u;
    }
#endif
#if UAES_ENABLE_192
    if (key_len == 24u) {
        ctx->keysize_word = 6u;
    }
#endif
#if UAES_ENABLE_256
    if (key_len == 32u) {
        ctx->keysize_word = 8u;
    }
#endif
    if (ctx->keysize_word == 0u) {
        ctx->keysize_word = (uint8_t)(UAES_MAX_KEY_SIZE / 32u);
    }
    for (uint8_t i = 0u; i < ctx->keysize_word; ++i) {
        ctx->key[i] = 0u;
        for (uint8_t j = 0u; j < 4u; ++j) {
            uint32_t shift = (uint32_t)j * 8u;
            ctx->key[i] |= ((uint32_t)key[(i * 4u) + j]) << shift;
        }
    }
#if UAES_STORE_ROUND_KEY_IN_CTX
    ExpandRoundKey(ctx);
#endif
}

#if UAES_STORE_ROUND_KEY_IN_CTX
// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(const UAES_AES_Ctx_t *ctx, uint8_t round, State_t state)
{
    uint8_t key_start = (uint8_t)(round * 4u);
    for (uint8_t i = 0u; i < 4u; ++i) {
        uint32_t ki = ctx->key[key_start + i];
        // The round key save in context is already transposed.
        state[i] ^= ki;
    }
}

// Expand the round key. This is only called at the initialization.
static void ExpandRoundKey(UAES_AES_Ctx_t *ctx)
{
    // The round constant word array, RCON[i], contains the values given by
    // x power i in the field GF(2^8).
    static const uint8_t RCON[10] = { 0x01, 0x02, 0x04, 0x08, 0x10,
                                      0x20, 0x40, 0x80, 0x1b, 0x36 };
    uint8_t round_key_len = (uint8_t)((ctx->keysize_word + 7u) * 4u);
    uint8_t rcon_idx = 0u;
    for (uint8_t i = ctx->keysize_word; i < round_key_len; ++i) {
        uint32_t tmp; // Store the intermediate results
        tmp = ctx->key[i - 1u];
        if ((i % ctx->keysize_word) == 0u) {
            tmp = (tmp >> 8u) | (tmp << 24u);
            tmp = SubWord(tmp);
            tmp = tmp ^ (uint32_t)RCON[rcon_idx];
            rcon_idx++;
        }
#if UAES_ENABLE_256
        if ((ctx->keysize_word == 8u) && ((i % 8u) == 4u)) {
            tmp = SubWord(tmp);
        }
#endif
        ctx->key[i] = ctx->key[i - ctx->keysize_word] ^ tmp;
    }
    // Do transpose here to make the best use of 32-bit CPU.
    for (uint8_t i = 0u; i < round_key_len; i += 4u) {
        uint8_t tmp[16];
        for (uint8_t j = 0u; j < 4u; ++j) {
            for (uint8_t k = 0u; k < 4u; ++k) {
                tmp[(j * 4u) + k] = (uint8_t)(ctx->key[i + j] >> (k * 8u));
            }
        }
        DataToState(tmp, &(ctx->key[i]));
    }
}
#else

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(const UAES_AES_Ctx_t *ctx,
                        uint8_t round,
                        State_t state,
                        RoundKey_t *round_key)
{
    uint8_t key_start = (uint8_t)(round * 4u);
    for (uint8_t i = 0u; i < 4u; ++i) {
        uint32_t ki = GetRoundKey(ctx, round_key, key_start + i);
        uint32_t shift = (uint32_t)i * 8u;
        for (uint8_t j = 0u; j < 4u; ++j) {
            uint32_t shift2 = (uint32_t)j * 8u;
            state[j] ^= ((ki >> shift2) & 0xFFu) << shift;
        }
    }
}

// Initializing the round key struct by storing the key to the buffer.
// Refer to https://en.wikipedia.org/wiki/AES_key_schedule for more details.
static void InitRoundKey(const UAES_AES_Ctx_t *ctx, RoundKey_t *round_key)
{
    round_key->iter_num = 0u;
    (void)memcpy(round_key->buf, ctx->key, sizeof(round_key->buf));
}

// Get the specific word of the round keys. Do key expansion when necessary.
static uint32_t GetRoundKey(const UAES_AES_Ctx_t *ctx,
                            RoundKey_t *round_key,
                            uint8_t word_idx)
{
    // Iterate until
    // iter_num * NUM_KEY_WORDS <= word_idx < (iter_num + 1) * NUM_KEY_WORDS
    while (((round_key->iter_num + 1u) * ctx->keysize_word) <= word_idx) {
        for (uint8_t i = 0u; i < ctx->keysize_word; ++i) {
            ExpandRoundKey(ctx->keysize_word,
                           round_key->buf,
                           i,
                           round_key->iter_num);
        }
        round_key->iter_num++;
    }
    // When invert cipher is disabled, word_idx will always be increasing, so
    // there is no need to iterate back.
#if ENABLE_INV_CIPHER
    while ((round_key->iter_num * ctx->keysize_word) > word_idx) {
        round_key->iter_num--;
        for (uint8_t i = 0u; i < ctx->keysize_word; ++i) {
            ExpandRoundKey(ctx->keysize_word,
                           round_key->buf,
                           (uint8_t)((ctx->keysize_word - i) - 1u),
                           round_key->iter_num);
        }
    }
#endif
    return round_key->buf[word_idx - (round_key->iter_num * ctx->keysize_word)];
}

// Iterate the round key expansion.
static void ExpandRoundKey(uint8_t key_num_words,
                           uint32_t *round_key_buf,
                           uint8_t step,
                           uint8_t iter_num)
{
    // The round constant word array, RCON[i], contains the values given by
    // x power i in the field GF(2^8).
    static const uint8_t RCON[10] = { 0x01, 0x02, 0x04, 0x08, 0x10,
                                      0x20, 0x40, 0x80, 0x1b, 0x36 };
    uint32_t tmp; // Store the intermediate results
    if (step > 0u) {
        tmp = round_key_buf[step - 1u];
    } else {
        tmp = round_key_buf[key_num_words - 1u];
    }
    if (step == 0u) {
        tmp = (tmp >> 8u) | (tmp << 24u);
        tmp = SubWord(tmp);
        tmp = tmp ^ (uint32_t)RCON[iter_num];
    }
#if UAES_ENABLE_256
    if ((key_num_words == 8u) && (step == 4u)) {
        tmp = SubWord(tmp);
    }
#endif
    round_key_buf[step] = round_key_buf[step] ^ tmp;
}
#endif // UAES_STORE_ROUND_KEY_IN_CTX

#if ENABLE_INV_CIPHER
// The main function that decrypts the CipherText.
static void InvCipher(const UAES_AES_Ctx_t *ctx,
                      const uint8_t input[16u],
                      uint8_t output[16u])
{
    State_t state;
    DataToState(input, state);

#if UAES_STORE_ROUND_KEY_IN_CTX == 0
    RoundKey_t round_key;
    InitRoundKey(ctx, &round_key);
#endif

    // It is 10 for 128-bit key, 12 for 192-bit key, and 14 for 256-bit key.
    uint8_t num_rounds = ctx->keysize_word + 6u;
    // The decryption process is the reverse of encrypting process.
    for (uint8_t round = num_rounds; round > 0u; --round) {
#if UAES_STORE_ROUND_KEY_IN_CTX
        AddRoundKey(ctx, round, state);
#else
        AddRoundKey(ctx, round, state, &round_key);
#endif
        if (round < num_rounds) {
            InvMixColumns(state);
        }
        InvShiftRows(state);
        InvSubBytes(state);
    }
#if UAES_STORE_ROUND_KEY_IN_CTX
    AddRoundKey(ctx, 0, state);
#else
    // Add the First round key as the last step
    AddRoundKey(ctx, 0, state, &round_key);
#endif
    StateToData(state, output);
}

// Reverses the MixColumns step in the Cipher.
static void InvMixColumns(State_t state)
{
    uint32_t a[4u];
    for (uint8_t i = 0u; i < 4u; ++i) {
        a[i] = state[i];
    }
    for (uint8_t i = 0u; i < 4u; ++i) {
        state[i] = Multiply(a[i], 0x0e);
        state[i] ^= Multiply(a[(i + 1u) & 3u], 0x0b);
        state[i] ^= Multiply(a[(i + 2u) & 3u], 0x0d);
        state[i] ^= Multiply(a[(i + 3u) & 3u], 0x09);
    }
}

// Reverses the SubBytes step in the Cipher.
static void InvSubBytes(State_t state)
{
    state[0] = InvSubWord(state[0]);
    state[1] = InvSubWord(state[1]);
    state[2] = InvSubWord(state[2]);
    state[3] = InvSubWord(state[3]);
}

// Reverses the SubWord step in the Cipher.
static uint32_t InvSubWord(uint32_t x)
{
    uint32_t tmp = 0u;
    for (uint8_t i = 0u; i <= 24u; i += 8u) {
        tmp |= (uint32_t)InvSubByte((uint8_t)(x >> i)) << i;
    }
    return tmp;
}

// Reverses the ShiftRows step in the Cipher.
static void InvShiftRows(State_t state)
{
    // No change on first row
    state[1] = (state[1] << 8u) | (state[1] >> 24u);
    state[2] = (state[2] << 16u) | (state[2] >> 16u);
    state[3] = (state[3] << 24u) | (state[3] >> 8u);
}

#endif

#endif // UAES_32BIT_MODE == 0

// Substitute the byte with the value in the S-box.
static uint8_t SubByte(uint8_t x)
{
#if UAES_SBOX_MODE == 0
    uint8_t inv;
    if (x == 0u) {
        inv = 0u;
    } else {
        inv = Gf28Inv(x);
    }
    return SboxAffineTransform(inv);
#elif UAES_SBOX_MODE == 1
    static const uint8_t SBOX[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
        0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
        0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
        0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
        0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
        0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
        0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
        0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
        0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
        0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
        0xb0, 0x54, 0xbb, 0x16
    };
    return SBOX[x];
#elif UAES_SBOX_MODE == 2
    return s_sbox[x];
#else
#error "Invalid UAES_SBOX_MODE"
#endif // UAES_SBOX_MODE
}

#if ENABLE_INV_CIPHER
// Reverse of SubByte()
static uint8_t InvSubByte(uint8_t x)
{
#if UAES_SBOX_MODE == 0
    uint8_t ret;
    if (x == 0x63u) {
        ret = 0u;
    } else {
        ret = Gf28Inv(RSboxAffineTransform(x));
    }
    return ret;
#elif UAES_SBOX_MODE == 1
    static const uint8_t RSBOX[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
        0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
        0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
        0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
        0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
        0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
        0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
        0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
        0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
        0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
        0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
        0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
        0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
        0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
        0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
        0x55, 0x21, 0x0c, 0x7d
    };
    return RSBOX[x];
#elif UAES_SBOX_MODE == 2
    return s_rsbox[x];
#else
#error "Invalid UAES_SBOX_MODE"
#endif // UAES_SBOX_MODE
}
#endif // ENABLE_INV_CIPHER

#if UAES_SBOX_MODE == 0
// Compute a / b in GF(2^8), and return the quotient and remainder.
static uint8_t Gf28Div(uint16_t a, uint16_t b, uint16_t *p_remain)
{
    uint16_t quotient = 0u;
    uint16_t remain = a;
    for (uint16_t i = 8u; i > 0u; --i) {
        if (remain < b) {
            break;
        }
        uint16_t bi = b << (i - 1u);
        if ((bi ^ remain) < remain) {
            quotient |= (1u << (i - 1u));
            remain = bi ^ remain;
        }
    }
    *p_remain = remain;
    return quotient;
}

// Compute the inverse of x in GF(2^8) with the Extended Euclidean Algorithm.
static uint8_t Gf28Inv(uint8_t x)
{
    uint16_t ri = 0x11bu;
    uint16_t si = 0u;
    uint16_t rii = x;
    uint16_t sii = 1u;
    while (rii > 1u) {
        uint16_t remain;
        uint16_t qi = Gf28Div(ri, rii, &remain);
        ri = rii;
        rii = remain;
        uint16_t tsi = si;
        si = sii;
        sii = tsi ^ (uint16_t)Multiply((uint32_t)qi, sii);
    }
    return sii;
}
#endif // UAES_STATIC_SBOX == 0

#if (UAES_SBOX_MODE == 0) || (UAES_SBOX_MODE == 2)
// The affine transformation in the S-box.
static uint8_t SboxAffineTransform(uint8_t x)
{
    uint16_t xx = (uint16_t)x;
    uint16_t r12 = (xx << 1u) ^ (xx << 2u);
    uint16_t r34 = r12 << 2;
    uint16_t sum = xx ^ r12 ^ r34;
    return (uint8_t)sum ^ (uint8_t)(sum >> 8u) ^ 0x63u;
}
#endif

#if UAES_SBOX_MODE == 2
// Initialize the S-box if it is not initialized.
static void EnsureSboxInitialized(void)
{
    if (s_sbox[0] == 0u) {
        uint8_t p = 1u;
        uint8_t q = 1u;
        // Loop invariant: p * q == 1 in the Galois field
        do {
            // Multiply p by 3
            p = p ^ (uint8_t)Times2(p);
            // Divide q by 3 (equals multiplication by 0xf6)
            q ^= (uint8_t)(q << 1u);
            q ^= (uint8_t)(q << 2u);
            q ^= (uint8_t)(q << 4u);
            q ^= ((q >> 7u) == 0u) ? 0u : 0x09u;
            s_sbox[p] = SboxAffineTransform(q);
#if ENABLE_INV_CIPHER
            s_rsbox[s_sbox[p]] = p;
#endif
        } while (p != 1u);
        s_sbox[0] = 0x63u;
#if ENABLE_INV_CIPHER
        s_rsbox[0x63u] = 0u;
#endif
    }
}
#endif

#if (ENABLE_INV_CIPHER == 1) || (UAES_SBOX_MODE == 0)
// Multiply each byte in the word in the field GF(2^8).
static uint32_t Multiply(uint32_t x, uint8_t y)
{
    uint32_t result = 0u;
    uint32_t xx = x;
    uint8_t yy = y;
    while (yy != 0u) {
        if ((yy & 1u) != 0u) {
            result ^= xx;
        }
        xx = Times2(xx);
        yy >>= 1u;
    }
    return result;
}
#endif

#if (ENABLE_INV_CIPHER == 1) && (UAES_SBOX_MODE == 0)
// Reverse of SboxAffineTransform()
static uint8_t RSboxAffineTransform(uint8_t x)
{
    uint16_t xx = (uint16_t)x;
    uint16_t r1 = xx << 1u;
    uint16_t r3 = xx << 3u;
    uint16_t r6 = xx << 6u;
    uint16_t sum = r1 ^ r3 ^ r6;
    return (uint8_t)sum ^ (uint8_t)(sum >> 8u) ^ 0x05u;
}
#endif

#if (UAES_ENABLE_CTR != 0) || (UAES_ENABLE_CCM != 0) || (UAES_ENABLE_GCM != 0)
// Increase the counter by 1 and compute the next block of key stream.
static void IterateKeyStream(const UAES_AES_Ctx_t *ctx,
                             uint8_t *counter,
                             uint8_t *key_stream)
{
    for (uint8_t i = 16u; i > 0u; --i) {
        counter[i - 1u]++;
        if (counter[i - 1u] != 0u) {
            break;
        }
    }
    Cipher(ctx, counter, key_stream);
}
#endif

#if (UAES_ENABLE_CBC != 0) || (UAES_ENABLE_CCM != 0)
// Xor all bytes in b1 and b2, and store the result in output.
static void XorBlocks(const uint8_t *b1, const uint8_t *b2, uint8_t *output)
{
    for (uint8_t i = 0u; i < 16u; ++i) {
        output[i] = b1[i] ^ b2[i];
    }
}
#endif // (UAES_ENABLE_CBC != 0) || (UAES_ENABLE_CCM != 0)

#if UAES_ENABLE_CCM
static void CCM_Xcrypt(UAES_CCM_Ctx_t *ctx,
                       const uint8_t *input,
                       uint8_t *output,
                       size_t len,
                       bool encrypt)
{
    uint8_t key_stream[16u];
    // Generate the key stream as it is not stored in the context.
    Cipher(&ctx->aes_ctx, ctx->counter, key_stream);
    for (size_t i = 0u; i < len; ++i) {
        if (ctx->byte_pos >= 16u) {
            ctx->byte_pos = 0u;
            IterateKeyStream(&ctx->aes_ctx, ctx->counter, key_stream);
            Cipher(&ctx->aes_ctx, ctx->cbc_buf, ctx->cbc_buf);
        }
        if (encrypt) {
            ctx->cbc_buf[ctx->byte_pos] ^= input[i];
            output[i] = input[i] ^ key_stream[ctx->byte_pos];
        } else {
            output[i] = input[i] ^ key_stream[ctx->byte_pos];
            ctx->cbc_buf[ctx->byte_pos] ^= output[i];
        }
        ctx->byte_pos++;
    }
}
#endif // UAES_ENABLE_CCM

#if UAES_ENABLE_GCM
// Convert 16 uint8_t to 4 uint32_t as big endian.
static void DataToGhashState(const uint8_t data[16u], uint32_t u32[4u])
{
    for (uint8_t i = 0u; i < 4u; ++i) {
        u32[i] = 0u;
        for (uint8_t j = 0u; j < 4u; ++j) {
            uint8_t shift = (uint8_t)((3u - j) * 8u);
            u32[i] |= ((uint32_t)data[(i * 4u) + j]) << shift;
        }
    }
}

// Reverse of DataToGhashState()
static void GhashStateToData(const uint32_t u32[4u], uint8_t data[16u])
{
    for (uint8_t i = 0u; i < 4u; ++i) {
        for (uint8_t j = 0u; j < 4u; ++j) {
            uint8_t shift = (uint8_t)((3u - j) * 8u);
            data[(i * 4u) + j] = (uint8_t)((u32[i] >> shift) & 0xFFu);
        }
    }
}
#endif // UAES_ENABLE_GCM
