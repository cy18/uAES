/* MIT License. Copyright (c) 2026 Yu Chen. See ../LICENSE. */
#include "uaes.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if UAES_ENABLE_CCM || UAES_ENABLE_GCM
typedef union {
#if UAES_ENABLE_CCM
    UAES_CCM_Ctx_t ccm;
#endif
#if UAES_ENABLE_GCM
    UAES_GCM_Ctx_t gcm;
#endif
} TestContext;

static void Require(bool condition, const char *reason)
{
    if (!condition) {
        (void)fprintf(stderr, "AEAD invariant failed: %s\n", reason);
        abort();
    }
}

static void *Allocate(size_t size)
{
    void *result = malloc(size);
    Require(result != NULL, "test allocation");
    return result;
}

static void Equal(const uint8_t *a, const uint8_t *b, size_t len, const char *reason)
{
    Require((len == 0u) || (memcmp(a, b, len) == 0), reason);
}

static uint8_t Byte(const uint8_t *data, size_t size, size_t pos)
{
    return (pos < size) ? data[pos] : 0u;
}

static void Init(TestContext *ctx, bool ccm, const uint8_t *key, size_t key_len,
                 const uint8_t *nonce, uint8_t nonce_len, size_t aad_len,
                 size_t data_len, uint8_t tag_len)
{
    (void)ccm; (void)aad_len; (void)data_len; (void)tag_len;
#if UAES_ENABLE_CCM
    if (ccm) {
        UAES_CCM_Init(&ctx->ccm, key, key_len, nonce, nonce_len,
                      aad_len, data_len, tag_len);
        return;
    }
#endif
#if UAES_ENABLE_GCM
    UAES_GCM_Init(&ctx->gcm, key, key_len, nonce, nonce_len);
#endif
}

static void AddAad(TestContext *ctx, bool ccm, const uint8_t *aad, size_t len)
{
    (void)ccm;
#if UAES_ENABLE_CCM
    if (ccm) { UAES_CCM_AddAad(&ctx->ccm, aad, len); return; }
#endif
#if UAES_ENABLE_GCM
    UAES_GCM_AddAad(&ctx->gcm, aad, len);
#endif
}

static void Xcrypt(TestContext *ctx, bool ccm, bool encrypt,
                   const uint8_t *input, uint8_t *output, size_t len)
{
    (void)ccm;
#if UAES_ENABLE_CCM
    if (ccm) {
        if (encrypt) { UAES_CCM_Encrypt(&ctx->ccm, input, output, len); }
        else { UAES_CCM_Decrypt(&ctx->ccm, input, output, len); }
        return;
    }
#endif
#if UAES_ENABLE_GCM
    if (encrypt) { UAES_GCM_Encrypt(&ctx->gcm, input, output, len); }
    else { UAES_GCM_Decrypt(&ctx->gcm, input, output, len); }
#endif
}

static void Tag(const TestContext *ctx, bool ccm, uint8_t *tag, uint8_t len)
{
    (void)ccm;
#if UAES_ENABLE_CCM
    if (ccm) { UAES_CCM_GenerateTag(&ctx->ccm, tag, len); return; }
#endif
#if UAES_ENABLE_GCM
    UAES_GCM_GenerateTag(&ctx->gcm, tag, len);
#endif
}

static bool Verify(const TestContext *ctx, bool ccm, const uint8_t *tag, uint8_t len)
{
    (void)ccm;
#if UAES_ENABLE_CCM
    if (ccm) { return UAES_CCM_VerifyTag(&ctx->ccm, tag, len); }
#endif
#if UAES_ENABLE_GCM
    return UAES_GCM_VerifyTag(&ctx->gcm, tag, len);
#else
    return false;
#endif
}

static bool SimpleDecrypt(bool ccm, const uint8_t *key, size_t key_len,
                          const uint8_t *nonce, uint8_t nonce_len,
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *input, uint8_t *output, size_t len,
                          const uint8_t *tag, uint8_t tag_len)
{
    (void)ccm;
#if UAES_ENABLE_CCM
    if (ccm) {
        return UAES_CCM_SimpleDecrypt(key, key_len, nonce, nonce_len, aad,
                                     aad_len, input, output, len, tag, tag_len);
    }
#endif
#if UAES_ENABLE_GCM
    return UAES_GCM_SimpleDecrypt(key, key_len, nonce, nonce_len, aad,
                                 aad_len, input, output, len, tag, tag_len);
#else
    return false;
#endif
}

#if UAES_ENABLE_GCM && UAES_ENABLE_128
static void TestWrap(size_t len)
{
    // Constructed 16-byte IV maps to J0 = 0^96 || fffffffe. Ciphertext and
    // full-message tag were independently generated with cryptography48.0.0
    // AESGCM. inc32 must wrap without carrying into the upper96bits.
    const uint8_t iv[16u] = {
        0xb7u, 0x46u, 0xb3u, 0x38u, 0xfdu, 0x43u, 0xe4u, 0x01u,
        0x5eu, 0x31u, 0x4cu, 0xd5u, 0x2du, 0xc6u, 0xeau, 0xc9u
    };
    const uint8_t expected[48u] = {
        0x28u, 0xc1u, 0x63u, 0x80u, 0xc4u, 0x91u, 0x08u, 0x8cu,
        0xa0u, 0x19u, 0xf8u, 0xa7u, 0x68u, 0x53u, 0xb1u, 0xe8u,
        0x66u, 0xe9u, 0x4bu, 0xd4u, 0xefu, 0x8au, 0x2cu, 0x3bu,
        0x88u, 0x4cu, 0xfau, 0x59u, 0xcau, 0x34u, 0x2bu, 0x2eu,
        0x58u, 0xe2u, 0xfcu, 0xceu, 0xfau, 0x7eu, 0x30u, 0x61u,
        0x36u, 0x7fu, 0x1du, 0x57u, 0xa4u, 0xe7u, 0x45u, 0x5au
    };
    const uint8_t expected_tag[16u] = {
        0xafu, 0xc4u, 0x64u, 0x6bu, 0xf1u, 0x98u, 0xdau, 0xa3u,
        0xcfu, 0x94u, 0xfdu, 0x49u, 0xe9u, 0xd1u, 0xafu, 0x2du
    };
    const uint8_t key[16u] = { 0u };
    const uint8_t plain[48u] = { 0u };
    uint8_t output[48u];
    uint8_t tag[16u];
    UAES_GCM_SimpleEncrypt(key, sizeof(key), iv, sizeof(iv), NULL, 0u,
                          plain, output, len, tag, sizeof(tag));
    Equal(expected, output, len, "GCM inc32 ciphertext");
    if (len == sizeof(plain)) {
        Equal(expected_tag, tag, sizeof(tag), "GCM inc32 tag / J0 recovery");
    }
    Require(UAES_GCM_SimpleDecrypt(key, sizeof(key), iv, sizeof(iv), NULL, 0u,
                                  output, output, len, tag, sizeof(tag)),
            "GCM inc32 decryption tag");
    Equal(plain, output, len, "GCM inc32 plaintext");
}
#endif

static void TestCase(const uint8_t *data, size_t size)
{
#if UAES_ENABLE_GCM && UAES_ENABLE_128
    if ((Byte(data, size, 0u) & 0x80u) != 0u) {
        TestWrap(Byte(data, size, 1u) % 49u);
        return;
    }
#endif
    bool ccm = (Byte(data, size, 0u) & 1u) != 0u;
#if !UAES_ENABLE_CCM
    ccm = false;
#elif !UAES_ENABLE_GCM
    ccm = true;
#endif
    const uint8_t keys[] = {
#if UAES_ENABLE_128
        16u,
#endif
#if UAES_ENABLE_192
        24u,
#endif
#if UAES_ENABLE_256
        32u,
#endif
    };
    const uint8_t ccm_tags[7u] = { 4u, 6u, 8u, 10u, 12u, 14u, 16u };
    const uint8_t gcm_tags[7u] = { 4u, 8u, 12u, 13u, 14u, 15u, 16u };
    const uint8_t iv_lengths[7u] = { 1u, 8u, 12u, 13u, 16u, 17u, 32u };
    const uint8_t boundaries[9u] = { 0u, 1u, 15u, 16u, 17u, 31u, 32u, 33u, 255u };
    size_t key_len = keys[Byte(data, size, 1u) % sizeof(keys)];
    uint8_t tag_len = (ccm ? ccm_tags : gcm_tags)[Byte(data, size, 2u) % 7u];
    uint8_t nonce_len = ccm ? (uint8_t)(7u + (Byte(data, size, 3u) % 7u))
                            : iv_lengths[Byte(data, size, 3u) % 7u];
    size_t len = ((Byte(data, size, 0u) & 2u) != 0u)
                 ? Byte(data, size, 4u) : boundaries[Byte(data, size, 4u) % 9u];
    size_t aad_len = ((Byte(data, size, 0u) & 4u) != 0u)
                     ? Byte(data, size, 5u) : boundaries[Byte(data, size, 5u) % 9u];
    size_t chunk = 1u + (Byte(data, size, 6u) % 32u);
    uint8_t *key = Allocate(key_len);
    uint8_t *nonce = Allocate(nonce_len);
    uint8_t *aad = (aad_len != 0u) ? Allocate(aad_len) : NULL;
    uint8_t *plain = (len != 0u) ? Allocate(len) : NULL;
    uint8_t *cipher = (len != 0u) ? Allocate(len) : NULL;
    uint8_t *tag = Allocate(tag_len);
    uint8_t *out = Allocate(len + 2u);
    uint8_t tag_stream[16u];
    for (size_t i = 0u; i < key_len; ++i) { key[i] = Byte(data, size, 8u + i); }
    for (size_t i = 0u; i < nonce_len; ++i) { nonce[i] = Byte(data, size, 40u + i); }
    for (size_t i = 0u; i < aad_len; ++i) { aad[i] = Byte(data, size, 72u + i); }
    for (size_t i = 0u; i < len; ++i) { plain[i] = Byte(data, size, 328u + i); }
    TestContext ctx;
    Init(&ctx, ccm, key, key_len, nonce, nonce_len, aad_len, len, tag_len);
    AddAad(&ctx, ccm, aad, aad_len);
    Xcrypt(&ctx, ccm, true, plain, cipher, len);
    Tag(&ctx, ccm, tag, tag_len);
    Require(Verify(&ctx, ccm, tag, tag_len), "generated tag verifies");
    Require(!Verify(&ctx, ccm, NULL, 0u), "empty tag rejected");
    Require(!Verify(&ctx, ccm, NULL, 17u), "oversized tag rejected");
    uint8_t untouched = 0xa5u;
    Tag(&ctx, ccm, &untouched, 17u);
    Require(untouched == 0xa5u, "rejected generation writes nothing");
    Init(&ctx, ccm, key, key_len, nonce, nonce_len, aad_len, len, tag_len);
    AddAad(&ctx, ccm, NULL, 0u);
    for (size_t pos = 0u; pos < aad_len;) {
        size_t part = (aad_len - pos < chunk) ? aad_len - pos : chunk;
        AddAad(&ctx, ccm, &aad[pos], part);
        pos += part;
    }
    (void)memset(out, 0xa5, len + 2u);
    Xcrypt(&ctx, ccm, true, NULL, &out[1u], 0u);
    for (size_t pos = 0u; pos < len;) {
        size_t part = (len - pos < chunk) ? len - pos : chunk;
        Xcrypt(&ctx, ccm, true, &plain[pos], &out[pos + 1u], part);
        pos += part;
    }
    Tag(&ctx, ccm, tag_stream, tag_len);
    Equal(cipher, &out[1u], len, "encryption chunk invariant");
    Equal(tag, tag_stream, tag_len, "tag chunk invariant");
    Require((out[0u] == 0xa5u) && (out[len + 1u] == 0xa5u), "output guards");
    Require(SimpleDecrypt(ccm, key, key_len, nonce, nonce_len, aad, aad_len,
                          cipher, &out[1u], len, tag, tag_len), "one-shot round trip");
    Equal(plain, &out[1u], len, "one-shot plaintext");
    Init(&ctx, ccm, key, key_len, nonce, nonce_len, aad_len, len, tag_len);
    AddAad(&ctx, ccm, aad, aad_len);
    if (len > 0u) { (void)memcpy(&out[1u], cipher, len); }
    for (size_t pos = 0u; pos < len;) {
        size_t part = (len - pos < chunk) ? len - pos : chunk;
        Xcrypt(&ctx, ccm, false, &out[pos + 1u], &out[pos + 1u], part);
        pos += part;
    }
    Require(Verify(&ctx, ccm, tag, tag_len), "chunked in-place decryption tag");
    Equal(plain, &out[1u], len, "chunked in-place plaintext");
    tag[Byte(data, size, 7u) % tag_len] ^= 1u;
    Require(!SimpleDecrypt(ccm, key, key_len, nonce, nonce_len, aad, aad_len,
                           cipher, &out[1u], len, tag, tag_len), "tampered tag rejected");
    for (size_t i = 1u; i <= len; ++i) { Require(out[i] == 0u, "failed output cleared"); }
    Require((out[0u] == 0xa5u) && (out[len + 1u] == 0xa5u), "failure guards");
    free(key); free(nonce); free(aad); free(plain); free(cipher); free(tag); free(out);
}
#endif

// Same input contract for deterministic CTest runs, replay and libFuzzer.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
#if UAES_ENABLE_CCM || UAES_ENABLE_GCM
    TestCase(data, size);
#else
    (void)data; (void)size;
#endif
    return 0;
}

#ifndef UAES_LIBFUZZER
int main(int argc, char **argv)
{
    if (argc == 2) {
        uint8_t data[1024u];
        FILE *file = fopen(argv[1], "rb");
        if (file == NULL) { return 2; }
        size_t size = fread(data, 1u, sizeof(data), file);
        bool invalid = ferror(file) || (fgetc(file) != EOF);
        (void)fclose(file);
        if (invalid) { return 2; }
        return LLVMFuzzerTestOneInput(data, size);
    }
    uint32_t state = UINT32_C(0x800038cd);
    (void)printf("AEAD seed=0x800038cd, cases=256, payload/AAD=0..255\n");
    for (size_t test = 0u; test < 256u; ++test) {
        uint8_t data[583u];
        for (size_t i = 0u; i < sizeof(data); ++i) {
            state ^= state << 13u; state ^= state >> 17u; state ^= state << 5u;
            data[i] = (uint8_t)state;
        }
        (void)printf("case=%zu\r", test);
        (void)fflush(stdout);
        (void)LLVMFuzzerTestOneInput(data, sizeof(data));
    }
#if UAES_ENABLE_GCM && UAES_ENABLE_128
    TestWrap(48u);
#endif
    (void)printf("\nAEAD invariants passed\n");
    return 0;
}
#endif
