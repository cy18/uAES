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

#include <string.h>

#if UAES_ECB_DECRYPT
#define ENABLE_INV_CIPHER 1
#endif

#if UAES_KEY_SIZE == 128u
#define NUM_KEY_WORDS 4u // The number of 32 bit words in a key.
#define NUM_ROUNDS    10u // The number of rounds in AES Cipher.
#elif UAES_KEY_SIZE == 192u
#define NUM_KEY_WORDS 6u
#define NUM_ROUNDS    12u
#elif UAES_KEY_SIZE == 256u
#define NUM_KEY_WORDS 8u
#define NUM_ROUNDS    14u
#else
#error "UAES_KEY_SIZE must be 128, 192, or 256"
#endif

// Store the 4x4 bytes AES cipher matrix by 4 uint32.
// Each uint32 represents a row in the matrix.
// In each uint32, the LSB is the first element in the row, and the MSB is the
// last. In other words, the bytes are stored in little endian order in uint32.
typedef struct {
    uint32_t data[4];
} State_t;

// Store the necessary information for generating round key.
// By generating round key dynamically, the memory usage could be reduced.
typedef struct {
    uint8_t iter_num;
    uint32_t buf[NUM_KEY_WORDS];
} RoundKey_t;

// Declare the static functions.
static void Cipher(const uint8_t *key,
                   const uint8_t input[16u],
                   uint8_t output[16u]);
static void DataToState(const uint8_t data[16u], State_t *state);
static void StateToData(const State_t *state, uint8_t data[16u]);
static void AddRoundKey(uint8_t round, State_t *state, RoundKey_t *round_key);
static void InitRoundKey(const uint8_t *key, RoundKey_t *round_key);
static uint32_t GetRoundKey(RoundKey_t *round_key, uint8_t word_idx);
static void ExpandRoundKey(RoundKey_t *round_key, uint8_t step);
static void SubBytes(State_t *state);
static uint32_t SubWord(uint32_t x);
static void ShiftRows(State_t *state);
static void MixColumns(State_t *state);
static uint32_t Times2(uint32_t x);
#if ENABLE_INV_CIPHER
static void InvCipher(const uint8_t *key,
                      const uint8_t input[16u],
                      uint8_t output[16u]);
static void InvMixColumns(State_t *state);
static void InvSubBytes(State_t *state);
static uint32_t InvSubWord(uint32_t x);
static void InvShiftRows(State_t *state);
static uint32_t Multiply(uint32_t x, uint8_t y);
#endif

#if (UAES_ECB_ENCRYPT != 0) || (UAES_ECB_DECRYPT != 0)
void UAES_ECB_Init(UAES_ECB_Ctx_t *ctx, const uint8_t *key)
{
    (void)memcpy(ctx->key, key, sizeof(ctx->key));
}
#endif

#if UAES_ECB_ENCRYPT
void UAES_ECB_Encrypt(const UAES_ECB_Ctx_t *ctx,
                      const uint8_t *input,
                      uint8_t *output)
{
    Cipher(ctx->key, input, output);
}
#endif
#if UAES_ECB_DECRYPT
void UAES_ECB_Decrypt(const UAES_ECB_Ctx_t *ctx,
                      const uint8_t *input,
                      uint8_t *output)
{
    InvCipher(ctx->key, input, output);
}
#endif

#if UAES_CTR
void UAES_CTR_Init(UAES_CTR_Ctx_t *ctx,
                   const uint8_t *key,
                   const uint8_t *nonce,
                   size_t nonce_len)
{
    (void)memcpy(ctx->key, key, sizeof(ctx->key));
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
                      size_t length)
{
    uint8_t buf[16u];
    // Generate the block as it is not stored in the context.
    Cipher(ctx->key, ctx->counter, buf);
    for (size_t i = 0u; i < length; ++i) {
        // If all the 16 bytes are used, generate the next block.
        if (ctx->byte_pos >= 16u) {
            ctx->byte_pos = 0u;
            // Increment the counter.
            for (size_t j = sizeof(ctx->counter); j > 0u; --j) {
                ctx->counter[j - 1u]++;
                if (ctx->counter[j - 1u] != 0u) {
                    break;
                }
            }
            Cipher(ctx->key, ctx->counter, buf);
        }
        output[i] = input[i] ^ buf[ctx->byte_pos];
        ctx->byte_pos++;
    }
}

void UAES_CTR_Decrypt(UAES_CTR_Ctx_t *ctx,
                      const uint8_t *input,
                      uint8_t *output,
                      size_t length)
{
    UAES_CTR_Encrypt(ctx, input, output, length);
}

#endif

// Cipher is the main function that encrypts the PlainText.
static void Cipher(const uint8_t *key,
                   const uint8_t input[16u],
                   uint8_t output[16u])
{
    RoundKey_t round_key;

    State_t state;
    DataToState(input, &state);
    InitRoundKey(key, &round_key);

    // Add the First round key to the state before starting the rounds.
    AddRoundKey(0, &state, &round_key);
    // There are NUM_ROUNDS rounds.
    // The first NUM_ROUNDS-1 rounds are identical.
    // Last one without MixColumns()
    for (uint8_t round = 1u; round <= NUM_ROUNDS; ++round) {
        SubBytes(&state);
        ShiftRows(&state);
        if (round < NUM_ROUNDS) {
            MixColumns(&state);
        }
        AddRoundKey(round, &state, &round_key);
    }
    StateToData(&state, output);
}

// Store the 4x4 bytes AES cipher matrix by 4 uint32.
// To make the best use of 32-bit CPU, each uint32 represents a row in the
// matrix.
static void DataToState(const uint8_t data[16u], State_t *state)
{
    for (uint8_t i = 0u; i < 4u; ++i) {
        state->data[i] = 0u;
        for (uint8_t j = 0u; j < 4u; ++j) {
            uint32_t shift = (uint32_t)j * 8u;
            state->data[i] |= ((uint32_t)data[i + (j * 4u)]) << shift;
        }
    }
}

// Reverse of DataToState()
static void StateToData(const State_t *state, uint8_t data[16u])
{
    for (uint8_t i = 0u; i < 4u; ++i) {
        for (uint8_t j = 0u; j < 4u; ++j) {
            uint32_t shift = (uint32_t)j * 8u;
            data[i + (j * 4u)] = (uint8_t)((state->data[i] >> shift) & 0xFFu);
        }
    }
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, State_t *state, RoundKey_t *round_key)
{
    uint8_t key_start = (uint8_t)(round * 4u);
    for (uint8_t i = 0u; i < 4u; ++i) {
        uint32_t key = GetRoundKey(round_key, key_start + i);
        uint32_t shift = (uint32_t)i * 8u;
        for (uint8_t j = 0u; j < 4u; ++j) {
            uint32_t shift2 = (uint32_t)j * 8u;
            state->data[j] ^= ((key >> shift2) & 0xFFu) << shift;
        }
    }
}

// Initializing the round key struct by storing the key to the buffer.
// Refer to https://en.wikipedia.org/wiki/AES_key_schedule for more details.
static void InitRoundKey(const uint8_t *key, RoundKey_t *round_key)
{
    round_key->iter_num = 0u;
    for (uint8_t i = 0u; i < NUM_KEY_WORDS; ++i) {
        round_key->buf[i] = 0u;
        for (uint8_t j = 0u; j < 4u; ++j) {
            uint32_t shift = (uint32_t)j * 8u;
            round_key->buf[i] |= ((uint32_t)key[(i * 4u) + j]) << shift;
        }
    }
}

// Get the specific word of the round keys. Do key expansion when necessary.
static uint32_t GetRoundKey(RoundKey_t *round_key, uint8_t word_idx)
{
    // Iterate until
    // iter_num * NUM_KEY_WORDS <= word_idx < (iter_num + 1) * NUM_KEY_WORDS
    while (((round_key->iter_num + 1u) * NUM_KEY_WORDS) <= word_idx) {
        for (uint8_t i = 0u; i < NUM_KEY_WORDS; ++i) {
            ExpandRoundKey(round_key, i);
        }
        round_key->iter_num++;
    }
    // When invert cipher is disabled, word_idx will always be increasing, so
    // there is no need to iterate back.
#if ENABLE_INV_CIPHER
    while ((round_key->iter_num * NUM_KEY_WORDS) > word_idx) {
        round_key->iter_num--;
        for (uint8_t i = 0u; i < NUM_KEY_WORDS; ++i) {
            ExpandRoundKey(round_key, ((NUM_KEY_WORDS - i) - 1u));
        }
    }
#endif
    return round_key->buf[word_idx - (round_key->iter_num * NUM_KEY_WORDS)];
}

// Iterate the round key expansion.
static void ExpandRoundKey(RoundKey_t *round_key, uint8_t step)
{
// The round constant word array, RCON[i], contains the values given by
// x power i in the field GF(2^8).
#if UAES_KEY_SIZE == 128u
    static const uint8_t RCON[10] = { 0x01, 0x02, 0x04, 0x08, 0x10,
                                      0x20, 0x40, 0x80, 0x1b, 0x36 };
#elif UAES_KEY_SIZE == 192u
    static const uint8_t RCON[8] = { 0x01, 0x02, 0x04, 0x08,
                                     0x10, 0x20, 0x40, 0x80 };
#elif UAES_KEY_SIZE == 256u
    static const uint8_t RCON[7] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40 };
#else
#error "UAES_KEY_SIZE must be 128, 192, or 256"
#endif
    uint32_t tmp; // Store the intermediate results
    if (step > 0u) {
        tmp = round_key->buf[step - 1u];
    } else {
        tmp = round_key->buf[NUM_KEY_WORDS - 1u];
    }
    if (step == 0u) {
        tmp = (tmp >> 8u) | (tmp << 24u);
        tmp = SubWord(tmp);
        tmp = tmp ^ (uint32_t)RCON[round_key->iter_num];
    }
#if UAES_KEY_SIZE == 256u
    if (step == 4u) {
        tmp = SubWord(tmp);
    }
#endif
    round_key->buf[step] = round_key->buf[step] ^ tmp;
}

// Substitutes the whole matrix with values in the S-box.
static void SubBytes(State_t *state)
{
    state->data[0] = SubWord(state->data[0]);
    state->data[1] = SubWord(state->data[1]);
    state->data[2] = SubWord(state->data[2]);
    state->data[3] = SubWord(state->data[3]);
}

// Substitutes each byte in the word with values in the S-box.
static uint32_t SubWord(uint32_t x)
{
    // Lookup table and constants
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

    uint32_t tmp = 0u;
    for (uint8_t i = 0u; i <= 24u; i += 8u) {
        tmp |= (uint32_t)SBOX[(x >> i) & 0xffu] << i;
    }
    return tmp;
}

// Shifts the rows in the state to the left. Each row is shifted with different
// offset. Offset = Row number. So the first row is not shifted.
// Since the data is stored in little endian order, the shift direction is
// reversed.
static void ShiftRows(State_t *state)
{
    // No change on first row
    state->data[1] = (state->data[1] >> 8u) | (state->data[1] << 24u);
    state->data[2] = (state->data[2] >> 16u) | (state->data[2] << 16u);
    state->data[3] = (state->data[3] >> 24u) | (state->data[3] << 8u);
}

// Mixes the columns of the state matrix.
// Since most operations are bitwise, the four columns are mixed at the same
// time to make the best use of 32-bit CPU.
static void MixColumns(State_t *state)
{
    uint32_t a[4];
    uint32_t b[4];
    a[0] = state->data[0];
    a[1] = state->data[1];
    a[2] = state->data[2];
    a[3] = state->data[3];
    b[0] = Times2(a[0]);
    b[1] = Times2(a[1]);
    b[2] = Times2(a[2]);
    b[3] = Times2(a[3]);
    state->data[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
    state->data[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
    state->data[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
    state->data[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
}

// Multiply each byte in the word by 2 in the field GF(2^8).
static uint32_t Times2(uint32_t x)
{
    uint32_t p1 = (x << 1u) & 0xFEFEFEFEu;
    uint32_t p2 = ((x >> 7u) & 0x01010101u) * 0x1Bu;
    return p1 ^ p2;
}

#if ENABLE_INV_CIPHER
// The main function that decrypts the CipherText.
static void InvCipher(const uint8_t *key,
                      const uint8_t input[16u],
                      uint8_t output[16u])
{
    RoundKey_t round_key;
    InitRoundKey(key, &round_key);

    State_t state;
    DataToState(input, &state);

    // The decryption process is the reverse of encrypting process.
    for (uint8_t round = NUM_ROUNDS; round > 0u; --round) {
        AddRoundKey(round, &state, &round_key);
        if (round < NUM_ROUNDS) {
            InvMixColumns(&state);
        }
        InvShiftRows(&state);
        InvSubBytes(&state);
    }
    // Add the First round key as the last step
    AddRoundKey(0, &state, &round_key);
    StateToData(&state, output);
}

// Reverses the MixColumns step in the Cipher.
static void InvMixColumns(State_t *state)
{
    uint32_t a[4u];
    for (uint8_t i = 0u; i < 4u; ++i) {
        a[i] = state->data[i];
    }
    for (uint8_t i = 0u; i < 4u; ++i) {
        state->data[i] = Multiply(a[i], 0x0e);
        state->data[i] ^= Multiply(a[(i + 1u) & 3u], 0x0b);
        state->data[i] ^= Multiply(a[(i + 2u) & 3u], 0x0d);
        state->data[i] ^= Multiply(a[(i + 3u) & 3u], 0x09);
    }
}

// Reverses the SubBytes step in the Cipher.
static void InvSubBytes(State_t *state)
{
    state->data[0] = InvSubWord(state->data[0]);
    state->data[1] = InvSubWord(state->data[1]);
    state->data[2] = InvSubWord(state->data[2]);
    state->data[3] = InvSubWord(state->data[3]);
}

// Reverses the SubWord step in the Cipher.
static uint32_t InvSubWord(uint32_t x)
{
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
    uint32_t tmp = 0u;
    for (uint8_t i = 0u; i <= 24u; i += 8u) {
        tmp |= (uint32_t)RSBOX[(x >> i) & 0xffu] << i;
    }
    return tmp;
}

// Reverses the ShiftRows step in the Cipher.
static void InvShiftRows(State_t *state)
{
    // No change on first row
    state->data[1] = (state->data[1] << 8u) | (state->data[1] >> 24u);
    state->data[2] = (state->data[2] << 16u) | (state->data[2] >> 16u);
    state->data[3] = (state->data[3] << 24u) | (state->data[3] >> 8u);
}

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
