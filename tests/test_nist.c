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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef enum {
    TYPE_UNSPECIFIED = 0,
    TYPE_ENCRYPT = 1,
    TYPE_DECRYPT = 2,
} TestType_t;

typedef struct TestCaseStruct {
    TestType_t type;
    size_t key_len;
    uint8_t key[256u];
    size_t iv_len;
    uint8_t iv[256u];
    size_t aad_len;
    uint8_t aad[256u];
    size_t plain_text_len;
    uint8_t plain_text[256u];
    size_t cipher_text_len;
    uint8_t cipher_text[256u];
    size_t tag_len;
    uint8_t tag[256u];
    size_t result_len;
    uint8_t result[256u];
    size_t force_tag_len;
    size_t force_pt_len;
    size_t force_aad_len;
    bool expect_verify_failure;
    const char *error_msg;
    size_t count;
} TestCase_t;

typedef void (*FuncDoTest_t)(TestCase_t *p_test);

static size_t s_num_pass = 0u;
static size_t s_num_fail = 0u;

static bool ProcessLine(char *line, TestCase_t *p_test);
static void ProcessEntry(char *entry, TestCase_t *p_test);
static bool IsEmptyLine(const char *line);
static bool IsCommentLine(const char *line);
static char *TryProcessSection(char *line);
static char *SplitSection(char **remaining);
static bool TrySplitKeyValue(char *line, char **key, char **value);
static bool TryProcessSizeValue(const char *expected_key,
                                const char *actual_key,
                                const char *value_str,
                                size_t *p_size);
static bool TryProcessBytesValue(const char *expected_key,
                                 const char *actual_key,
                                 const char *value_str,
                                 uint8_t *p_bytes,
                                 size_t *len);
static void PrintCase(const TestCase_t *p_test);
static void DoTests(FuncDoTest_t func, const char *name, const char *rsp_file);
static bool CheckResult(TestCase_t *p_test,
                        const uint8_t *expected,
                        const uint8_t *result,
                        const size_t result_len,
                        const char *error_msg);
static bool CheckPlainText(TestCase_t *p_test, const uint8_t *result);
static bool CheckCipherText(TestCase_t *p_test, const uint8_t *result);
static bool CheckTag(TestCase_t *p_test, const uint8_t *result);
static bool CheckReturnValue(TestCase_t *p_test, bool expect, bool ret);
static void TestEcb(TestCase_t *p_test);
static void TestEcbMct(TestCase_t *p_test);
static void TestCbc(TestCase_t *p_test);
static void TestCbcMct(TestCase_t *p_test);
static void TestGcmEncrypt(TestCase_t *p_test);
static void TestGcmDecrypt(TestCase_t *p_test);
static void TestCcmEncrypt(TestCase_t *p_test);
static void TestCcmDecrypt(TestCase_t *p_test);

// Process the next line of rsp file, return true if a new case is updated
static bool ProcessLine(char *line, TestCase_t *p_test)
{
    bool test_ready = false;
    do {
        // Remove the trailing '\n'
        for (size_t i = 0; i < strlen(line); i++) {
            if ((line[i] == '\r') || (line[i] == '\n')) {
                line[i] = '\0';
            }
        }
        if (IsCommentLine(line)) {
            continue;
        }
        if (IsEmptyLine(line)) {
            if (p_test->count != SIZE_MAX) {
                test_ready = true;
            }
            continue;
        }
        char *section = TryProcessSection(line);
        if (section == NULL) {
            ProcessEntry(line, p_test);
        } else {
            // A section may contain multiple entries
            while (section != NULL) {
                char *entry = SplitSection(&section);
                ProcessEntry(entry, p_test);
            }
            continue;
        }
    } while (false);
    return test_ready;
}

// Process an entry and save the result to p_test
static void ProcessEntry(char *entry, TestCase_t *p_test)
{
    do {
        if (strcmp(entry, "ENCRYPT") == 0) {
            p_test->type = TYPE_ENCRYPT;
            continue;
        }
        if (strcmp(entry, "DECRYPT") == 0) {
            p_test->type = TYPE_DECRYPT;
            continue;
        }
        if (strcmp(entry, "FAIL") == 0) {
            p_test->expect_verify_failure = true;
            continue;
        }
        if (0 == strcmp(entry, "Result = Fail")) {
            p_test->expect_verify_failure = true;
            continue;
        }
        if (0 == strcmp(entry, "Result = Pass")) {
            p_test->expect_verify_failure = false;
            continue;
        }
        char *key;
        char *value;
        if (!TrySplitKeyValue(entry, &key, &value)) {
            printf("Failed to parse entry %s\n", entry);
            continue;
        }
        bool ignore_key = false;
        static const char *IGNORE_KEYS[] = { "Nlen",   "IVlen",  "PTlen",
                                             "AADlen", "Keylen", "Taglen",
                                             "Nlen" };
        for (size_t i = 0; i < sizeof(IGNORE_KEYS) / sizeof(char *); ++i) {
            if (0 == strcmp(key, IGNORE_KEYS[i])) {
                ignore_key = true;
                break;
            }
        }
        if (ignore_key) {
            continue;
        }
        if (TryProcessSizeValue("COUNT", key, value, &p_test->count)) {
            continue;
        }
        if (TryProcessSizeValue("Count", key, value, &p_test->count)) {
            continue;
        }
        if (TryProcessSizeValue("Tlen", key, value, &p_test->force_tag_len)) {
            continue;
        }
        if (TryProcessSizeValue("Plen", key, value, &p_test->force_pt_len)) {
            continue;
        }
        if (TryProcessSizeValue("Alen", key, value, &p_test->force_aad_len)) {
            continue;
        }
        if (TryProcessBytesValue("KEY",
                                 key,
                                 value,
                                 p_test->key,
                                 &p_test->key_len)) {
            continue;
        }
        if (TryProcessBytesValue("Key",
                                 key,
                                 value,
                                 p_test->key,
                                 &p_test->key_len)) {
            continue;
        }
        if (TryProcessBytesValue("IV", key, value, p_test->iv, &p_test->iv_len)) {
            continue;
        }
        if (TryProcessBytesValue("Nonce",
                                 key,
                                 value,
                                 p_test->iv,
                                 &p_test->iv_len)) {
            continue;
        }
        if (TryProcessBytesValue("AAD",
                                 key,
                                 value,
                                 p_test->aad,
                                 &p_test->aad_len)) {
            continue;
        }
        if (TryProcessBytesValue("Adata",
                                 key,
                                 value,
                                 p_test->aad,
                                 &p_test->aad_len)) {
            continue;
        }
        if (TryProcessBytesValue("PLAINTEXT",
                                 key,
                                 value,
                                 p_test->plain_text,
                                 &p_test->plain_text_len)) {
            continue;
        }
        if (TryProcessBytesValue("PT",
                                 key,
                                 value,
                                 p_test->plain_text,
                                 &p_test->plain_text_len)) {
            continue;
        }
        if (TryProcessBytesValue("Payload",
                                 key,
                                 value,
                                 p_test->plain_text,
                                 &p_test->plain_text_len)) {
            continue;
        }
        if (TryProcessBytesValue("CIPHERTEXT",
                                 key,
                                 value,
                                 p_test->cipher_text,
                                 &p_test->cipher_text_len)) {
            continue;
        }
        if (TryProcessBytesValue("CT",
                                 key,
                                 value,
                                 p_test->cipher_text,
                                 &p_test->cipher_text_len)) {
            continue;
        }
        if (TryProcessBytesValue("Tag",
                                 key,
                                 value,
                                 p_test->tag,
                                 &p_test->tag_len)) {
            continue;
        }
        printf("Unknown key %s\n", key);
    } while (false);
}

// Return true if the line is empty
static bool IsEmptyLine(const char *line)
{
    bool is_empty = true;
    size_t pos = 0u;
    while (line[pos] != '\0') {
        if (line[pos] != '\n' && line[pos] != '\r' && line[pos] != ' ') {
            is_empty = false;
            break;
        }
        pos++;
    }
    return is_empty;
}

// Return true if the line starts with "#"
static bool IsCommentLine(const char *line)
{
    return line[0] == '#';
}

// Removing surrounding '[' and ']' and return the point to string without
// "[]". If do not contain '[', return NULL
static char *TryProcessSection(char *line)
{
    char *ret = NULL;
    if (line[0] == '[') {
        ret = &line[1];
        for (size_t i = strlen(line); i > 0; --i) {
            if (line[i] == ']') {
                line[i] = '\0';
                break;
            }
        }
    }
    return ret;
}

// Split the section by ',' and return the remaining part
static char *SplitSection(char **remaining)
{
    char *section = *remaining;
    if (section[0] == '\0') {
        *remaining = NULL;
        section = NULL;
    } else {
        size_t split_pos = 0u;
        for (split_pos = 0; split_pos < strlen(section); ++split_pos) {
            if (section[split_pos] == ',') {
                split_pos = split_pos;
                break;
            }
        }
        if (section[split_pos] == ',') {
            section[split_pos] = '\0';
            split_pos++;
            if (section[split_pos] == ' ') {
                section[split_pos] = '\0';
                split_pos++;
            }
        }
        *remaining = &section[split_pos];
        if ((*remaining)[0] == '\0') {
            *remaining = NULL;
        }
    }
    return section;
}

// Try splitting the line by " = ", true if success
static bool TrySplitKeyValue(char *line, char **key, char **value)
{
    char *split_pos = strstr(line, " = ");
    if (strstr(line, " = ") == NULL) {
        return false;
    }
    *split_pos = '\0';
    *key = line;
    *value = split_pos + 3;
    return true;
}

// If the key matches, save the value as size_t
static bool TryProcessSizeValue(const char *expected_key,
                                const char *actual_key,
                                const char *value_str,
                                size_t *p_size)
{
    if (strcmp(expected_key, actual_key) != 0) {
        return false;
    }
    sscanf(value_str, "%zu", p_size);
    return true;
}

// If the key matches, save the value as bytes
static bool TryProcessBytesValue(const char *expected_key,
                                 const char *actual_key,
                                 const char *value_str,
                                 uint8_t *p_bytes,
                                 size_t *p_len)
{
    if (strcmp(expected_key, actual_key) != 0) {
        return false;
    }
    *p_len = strlen(value_str) / 2;
    for (size_t i = 0; i < *p_len; i++) {
        sscanf(&value_str[i * 2], "%02hhx", &p_bytes[i]);
    }
    return true;
}

// Print the testing case, usually for debug
static void PrintCase(const TestCase_t *p_test)
{
    printf("Count: %zu\n", p_test->count);
    printf("Type: %d\n", p_test->type);
    if (p_test->error_msg != NULL) {
        printf("Failed, error msg: %s\n", p_test->error_msg);
    }
    printf("Key: ");
    for (size_t i = 0; i < p_test->key_len; i++) {
        printf("%02x", p_test->key[i]);
    }
    printf("\n");
    printf("IV: ");
    for (size_t i = 0; i < p_test->iv_len; i++) {
        printf("%02x", p_test->iv[i]);
    }
    printf("\n");
    printf("AAD: ");
    for (size_t i = 0; i < p_test->aad_len; i++) {
        printf("%02x", p_test->aad[i]);
    }
    printf("\n");
    printf("PlainText: ");
    for (size_t i = 0; i < p_test->plain_text_len; i++) {
        printf("%02x", p_test->plain_text[i]);
    }
    printf("\n");
    printf("CipherTest: ");
    for (size_t i = 0; i < p_test->cipher_text_len; i++) {
        printf("%02x", p_test->cipher_text[i]);
    }
    printf("\n");
    printf("Tag: ");
    for (size_t i = 0; i < p_test->tag_len; i++) {
        printf("%02x", p_test->tag[i]);
    }
    printf("\nResult: ");
    for (size_t i = 0; i < p_test->result_len; i++) {
        printf("%02x", p_test->result[i]);
    }
    printf("\n");
    printf("force_tag_len: %zu\n", p_test->force_tag_len);
    printf("force_pt_len: %zu\n", p_test->force_pt_len);
    printf("force_aad_len: %zu\n", p_test->force_aad_len);
    if (p_test->expect_verify_failure) {
        printf("Expect tag fail: True\n");
    }
    printf("Press Enter to continue...");
    (void)getchar();
}

// Process the .rsp file and do tests
// By replacing file reading with other data source such as UART, it is possible
// to do tests on platforms without file capability.
static void DoTests(FuncDoTest_t func, const char *name, const char *rsp_file)
{
    size_t begin_num_pass = s_num_pass;
    size_t begin_num_fail = s_num_fail;

    printf("Testing %s in %s\n", name, rsp_file);
    static TestCase_t test;
    static char line_buf[512u];
    memset(&test, 0, sizeof(test));
    test.count = SIZE_MAX; // We use count to detect tests
    FILE *file = fopen(rsp_file, "r");
    if (file == NULL) {
        printf("Failed to open file %s\n", rsp_file);
    }
    bool last_line = false;
    while (!last_line) {
        if (!feof(file)) {
            (void)fgets(line_buf, sizeof(line_buf), file);
        } else {
            last_line = true;
            // Feed an empty line to trigger the last test case
            line_buf[0] = '\0';
        }
        if (ProcessLine(line_buf, &test)) {
            func(&test);
            if (test.error_msg != NULL) {
                s_num_fail++;
                PrintCase(&test);
            } else {
                s_num_pass++;
            }
            // Clear these sections for new test case.
            // Keep other sections unchanged as they may be reused.
            test.count = SIZE_MAX; // The count is used to detect new test
            test.error_msg = NULL;
            test.result_len = 0u;
            test.expect_verify_failure = false;
        }
    }
    printf("Pass: %zu, fail: %zu\n",
           s_num_pass - begin_num_pass,
           s_num_fail - begin_num_fail);
    fclose(file);
}

// Check if the result is as expected
static bool CheckResult(TestCase_t *p_test,
                        const uint8_t *expected,
                        const uint8_t *result,
                        const size_t result_len,
                        const char *error_msg)
{
    if (memcmp(expected, result, result_len) != 0) {
        if (p_test->error_msg == NULL) {
            p_test->error_msg = error_msg;
        }
        if (p_test->result_len == 0) {
            memcpy(p_test->result, result, result_len);
            p_test->result_len = result_len;
        }
        return false;
    } else {
        return true;
    }
}

static bool CheckPlainText(TestCase_t *p_test, const uint8_t *result)
{
    return CheckResult(p_test,
                       p_test->plain_text,
                       result,
                       p_test->plain_text_len,
                       "Plain text mismatch");
}

static bool CheckCipherText(TestCase_t *p_test, const uint8_t *result)
{
    return CheckResult(p_test,
                       p_test->cipher_text,
                       result,
                       p_test->cipher_text_len,
                       "Cipher text mismatch");
}

static bool CheckTag(TestCase_t *p_test, const uint8_t *result)
{
    if (memcmp(p_test->tag, result, p_test->tag_len) != 0) {
        if (p_test->error_msg == NULL) {
            p_test->error_msg = "Unexpected tag checking result";
        }
        if (p_test->result_len == 0u) {
            memcpy(p_test->result, result, p_test->tag_len);
            p_test->result_len = p_test->tag_len;
        }
        return false;
    } else {
        return true;
    }
}

static bool CheckReturnValue(TestCase_t *p_test, bool expect, bool ret)
{
    if (expect != ret) {
        if (p_test->error_msg == NULL) {
            if (expect) {
                p_test->error_msg = "Expect true but got false";
            } else {
                p_test->error_msg = "Expect false but got true";
            }
        }
    }
    return ret;
}

static bool CheckInput(TestCase_t *p_test,
                       bool key,
                       bool iv,
                       bool plain_text,
                       bool ptm16,
                       bool cipher_text,
                       bool tag)
{
    if (key && ((p_test->key_len == 0u))) {
        if (p_test->error_msg == NULL) {
            p_test->error_msg = "Key is empty";
        }
        return false;
    }
    if (iv && (p_test->iv_len == 0u)) {
        if (p_test->error_msg == NULL) {
            p_test->error_msg = "IV is empty";
        }
        return false;
    }
    if (plain_text && (p_test->plain_text_len == 0u)) {
        if (p_test->error_msg == NULL) {
            p_test->error_msg = "Plain text is empty";
        }
        return false;
    }
    if (ptm16 && (p_test->plain_text_len % 16u != 0u)) {
        if (p_test->error_msg == NULL) {
            p_test->error_msg = "Plain text length is not multiple of 16";
        }
        return false;
    }
    if (cipher_text && (p_test->cipher_text_len == 0u)) {
        if (p_test->error_msg == NULL) {
            p_test->error_msg = "Cipher text is empty";
        }
        return false;
    }
    if (tag && (p_test->tag_len == 0u)) {
        if (p_test->error_msg == NULL) {
            p_test->error_msg = "Tag is empty";
        }
        return false;
    }
    return true;
}

static void TestEcb(TestCase_t *p_test)
{
    uint8_t result[1024u];
    if (!CheckInput(p_test, true, false, true, true, true, false)) {
        return;
    }
    UAES_ECB_SimpleEncrypt(p_test->key,
                           p_test->key_len,
                           p_test->plain_text,
                           result,
                           p_test->plain_text_len);
    (void)CheckCipherText(p_test, result);
    UAES_ECB_SimpleDecrypt(p_test->key,
                           p_test->key_len,
                           p_test->cipher_text,
                           result,
                           p_test->cipher_text_len);
    (void)CheckPlainText(p_test, result);
}

static void TestEcbMct(TestCase_t *p_test)
{
    uint8_t result[1024u];
    if (!CheckInput(p_test, true, false, true, true, true, false)) {
        return;
    }
    memcpy(result, p_test->plain_text, p_test->plain_text_len);
    for (size_t i = 0; i < 1000; ++i) {
        UAES_ECB_SimpleEncrypt(p_test->key,
                               p_test->key_len,
                               result,
                               result,
                               p_test->plain_text_len);
    }
    CheckCipherText(p_test, result);
    memcpy(result, p_test->cipher_text, p_test->cipher_text_len);
    for (size_t i = 0; i < 1000; ++i) {
        UAES_ECB_SimpleDecrypt(p_test->key,
                               p_test->key_len,
                               result,
                               result,
                               p_test->cipher_text_len);
    }
    CheckPlainText(p_test, result);
}

static void TestCbc(TestCase_t *p_test)
{
    uint8_t result[1024u];
    if (!CheckInput(p_test, true, true, true, true, true, false)) {
        return;
    }
    UAES_CBC_SimpleEncrypt(p_test->key,
                           p_test->key_len,
                           p_test->iv,
                           p_test->plain_text,
                           result,
                           p_test->plain_text_len);
    (void)CheckCipherText(p_test, result);
    UAES_CBC_SimpleDecrypt(p_test->key,
                           p_test->key_len,
                           p_test->iv,
                           p_test->cipher_text,
                           result,
                           p_test->cipher_text_len);
    (void)CheckPlainText(p_test, result);
}

static void TestCbcMct(TestCase_t *p_test)
{
    if (!CheckInput(p_test, true, true, true, true, true, false)) {
        return;
    }
    if ((p_test->plain_text_len != 16u) || (p_test->cipher_text_len != 16u)) {
        p_test->error_msg = "data length must be 16 for CBC MCT";
    }
    if (p_test->type == TYPE_ENCRYPT) {
        UAES_CBC_Ctx_t ctx;
        uint8_t ct[16u];
        uint8_t pt[16u];
        uint8_t pt_new[16u];
        for (size_t i = 0u; i < 1000u; ++i) {
            if (i == 0u) {
                UAES_CBC_Init(&ctx, p_test->key, p_test->key_len, p_test->iv);
                UAES_CBC_Encrypt(&ctx, p_test->plain_text, ct, 16u);
                memcpy(pt, p_test->iv, 16u);
            } else {
                memcpy(pt_new, ct, 16u);
                UAES_CBC_Encrypt(&ctx, pt, ct, 16u);
                memcpy(pt, pt_new, 16u);
            }
        }
        CheckCipherText(p_test, ct);
    } else if (p_test->type == TYPE_DECRYPT) {
        UAES_CBC_Ctx_t ctx;
        uint8_t ct[16u];
        uint8_t pt[16u];
        uint8_t ct_new[16u];
        for (size_t i = 0u; i < 1000u; ++i) {
            if (i == 0u) {
                UAES_CBC_Init(&ctx, p_test->key, p_test->key_len, p_test->iv);
                UAES_CBC_Decrypt(&ctx, p_test->cipher_text, pt, 16u);
                memcpy(ct, p_test->iv, 16u);
            } else {
                memcpy(ct_new, pt, 16u);
                UAES_CBC_Decrypt(&ctx, ct, pt, 16u);
                memcpy(ct, ct_new, 16u);
            }
        }
        CheckPlainText(p_test, pt);
    } else {
        p_test->error_msg = "Test type unspecified for CBC MCT";
    }
}

static void TestGcmEncrypt(TestCase_t *p_test)
{
    uint8_t result[1024u];
    uint8_t tag[16u];
    if (!CheckInput(p_test, true, true, false, false, false, true)) {
        return;
    }
    UAES_GCM_SimpleEncrypt(p_test->key,
                           p_test->key_len,
                           p_test->iv,
                           p_test->iv_len,
                           p_test->aad,
                           p_test->aad_len,
                           p_test->plain_text,
                           result,
                           p_test->plain_text_len,
                           tag,
                           p_test->tag_len);
    (void)CheckCipherText(p_test, result);
    (void)CheckTag(p_test, tag);
}

static void TestGcmDecrypt(TestCase_t *p_test)
{
    uint8_t result[1024u];
    if (!CheckInput(p_test, true, true, false, false, false, true)) {
        return;
    }
    bool ret = UAES_GCM_SimpleDecrypt(p_test->key,
                                      p_test->key_len,
                                      p_test->iv,
                                      p_test->iv_len,
                                      p_test->aad,
                                      p_test->aad_len,
                                      p_test->cipher_text,
                                      result,
                                      p_test->cipher_text_len,
                                      p_test->tag,
                                      p_test->tag_len);
    (void)CheckReturnValue(p_test, !p_test->expect_verify_failure, ret);
    if (!p_test->expect_verify_failure) {
        if ((p_test->cipher_text_len > 0) && (p_test->plain_text_len == 0u)) {
            p_test->error_msg = "Plain text expected but not provided 1";
        }
        (void)CheckPlainText(p_test, result);
    }
}

static void TestCcmEncrypt(TestCase_t *p_test)
{
    uint8_t result[1024u];
    if (!CheckInput(p_test, true, true, false, false, false, false)) {
        return;
    }
    // In some cases, Plen = 0 but "Payload = 00" is given
    if (p_test->force_pt_len == 0) {
        p_test->plain_text_len = 0;
    }
    // In some cases, Alen = 0 but "Adata = 00" is given
    if (p_test->force_aad_len == 0) {
        p_test->aad_len = 0;
    }
    // When encrypting, the tag are appended to cipher_text
    UAES_CCM_SimpleEncrypt(p_test->key,
                           p_test->key_len,
                           p_test->iv,
                           p_test->iv_len,
                           p_test->aad,
                           p_test->aad_len,
                           p_test->plain_text,
                           result,
                           p_test->plain_text_len,
                           &result[p_test->plain_text_len],
                           p_test->force_tag_len);
    (void)CheckCipherText(p_test, result);
}

static void TestCcmDecrypt(TestCase_t *p_test)
{
    uint8_t result[1024u];
    if (!CheckInput(p_test, true, true, false, false, true, false)) {
        return;
    }
    // In some cases, Plen = 0 but "Payload = 00" is given
    if (p_test->force_pt_len == 0) {
        p_test->plain_text_len = 0;
    }
    // In some cases, Alen = 0 but "Adata = 00" is given
    if (p_test->force_aad_len == 0) {
        p_test->aad_len = 0;
    }
    bool ret = UAES_CCM_SimpleDecrypt(
            p_test->key,
            p_test->key_len,
            p_test->iv,
            p_test->iv_len,
            p_test->aad,
            p_test->aad_len,
            p_test->cipher_text,
            result,
            p_test->cipher_text_len - p_test->force_tag_len,
            &p_test->cipher_text[p_test->plain_text_len],
            p_test->force_tag_len);
    (void)CheckReturnValue(p_test, !p_test->expect_verify_failure, ret);
    if (!p_test->expect_verify_failure) {
        if (((p_test->cipher_text_len - p_test->force_tag_len) > 0)
            && (p_test->plain_text_len == 0u)) {
            p_test->error_msg = "Plain text expected but not provided 2";
        }
        (void)CheckPlainText(p_test, result);
    }
}

int main(void)
{
    FuncDoTest_t test_func;
    const char *test_name;
    // ECB
    test_func = TestEcb;
    test_name = "ECB";
    const char *RSP_LIST_ECB[] = {
        "./nist_data/aesmmt/ECBMMT128.rsp",
        "./nist_data/aesmmt/ECBMMT192.rsp",
        "./nist_data/aesmmt/ECBMMT256.rsp",
        "./nist_data/KAT_AES/ECBGFSbox128.rsp",
        "./nist_data/KAT_AES/ECBGFSbox192.rsp",
        "./nist_data/KAT_AES/ECBGFSbox256.rsp",
        "./nist_data/KAT_AES/ECBKeySbox128.rsp",
        "./nist_data/KAT_AES/ECBKeySbox192.rsp",
        "./nist_data/KAT_AES/ECBKeySbox256.rsp",
        "./nist_data/KAT_AES/ECBVarKey128.rsp",
        "./nist_data/KAT_AES/ECBVarKey192.rsp",
        "./nist_data/KAT_AES/ECBVarKey256.rsp",
        "./nist_data/KAT_AES/ECBVarTxt128.rsp",
        "./nist_data/KAT_AES/ECBVarTxt192.rsp",
        "./nist_data/KAT_AES/ECBVarTxt256.rsp",
    };
    for (size_t i = 0; i < sizeof(RSP_LIST_ECB) / sizeof(RSP_LIST_ECB[0]);
         i++) {
        DoTests(test_func, test_name, RSP_LIST_ECB[i]);
    }
    // ECB MCT
    test_func = TestEcbMct;
    test_name = "ECB MCT";
    const char *RSP_LIST_ECB_MCT[] = {
        "./nist_data/aesmct/ECBMCT128.rsp",
        "./nist_data/aesmct/ECBMCT192.rsp",
        "./nist_data/aesmct/ECBMCT256.rsp",
    };
    for (size_t i = 0;
         i < sizeof(RSP_LIST_ECB_MCT) / sizeof(RSP_LIST_ECB_MCT[0]);
         i++) {
        DoTests(test_func, test_name, RSP_LIST_ECB_MCT[i]);
    }
    // CBC
    test_func = TestCbc;
    test_name = "CBC";
    const char *RSP_LIST_CBC[] = {
        "./nist_data/aesmmt/CBCMMT128.rsp",
        "./nist_data/aesmmt/CBCMMT192.rsp",
        "./nist_data/aesmmt/CBCMMT256.rsp",
        "./nist_data/KAT_AES/CBCGFSbox128.rsp",
        "./nist_data/KAT_AES/CBCGFSbox192.rsp",
        "./nist_data/KAT_AES/CBCGFSbox256.rsp",
        "./nist_data/KAT_AES/CBCKeySbox128.rsp",
        "./nist_data/KAT_AES/CBCKeySbox192.rsp",
        "./nist_data/KAT_AES/CBCKeySbox256.rsp",
        "./nist_data/KAT_AES/CBCVarKey128.rsp",
        "./nist_data/KAT_AES/CBCVarKey192.rsp",
        "./nist_data/KAT_AES/CBCVarKey256.rsp",
        "./nist_data/KAT_AES/CBCVarTxt128.rsp",
        "./nist_data/KAT_AES/CBCVarTxt192.rsp",
        "./nist_data/KAT_AES/CBCVarTxt256.rsp",
    };
    for (size_t i = 0; i < sizeof(RSP_LIST_CBC) / sizeof(RSP_LIST_CBC[0]);
         i++) {
        DoTests(test_func, test_name, RSP_LIST_CBC[i]);
    }
    // CBC MCT
    test_func = TestCbcMct;
    test_name = "CBC";
    const char *RSP_LIST_CBC_MCT[] = {
        "./nist_data/aesmct/CBCMCT128.rsp",
        "./nist_data/aesmct/CBCMCT192.rsp",
        "./nist_data/aesmct/CBCMCT256.rsp",
    };
    for (size_t i = 0;
         i < sizeof(RSP_LIST_CBC_MCT) / sizeof(RSP_LIST_CBC_MCT[0]);
         i++) {
        DoTests(test_func, test_name, RSP_LIST_CBC_MCT[i]);
    }
    // GCM Encrypt
    test_func = TestGcmEncrypt;
    test_name = "GCM Encrypt";
    const char *RSP_LIST_GCM_ENC[] = {
        "./nist_data/gcmtestvectors/gcmEncryptExtIV128.rsp",
        "./nist_data/gcmtestvectors/gcmEncryptExtIV192.rsp",
        "./nist_data/gcmtestvectors/gcmEncryptExtIV256.rsp",
    };
    for (size_t i = 0;
         i < sizeof(RSP_LIST_GCM_ENC) / sizeof(RSP_LIST_GCM_ENC[0]);
         i++) {
        DoTests(test_func, test_name, RSP_LIST_GCM_ENC[i]);
    }
    // GCM Decrypt
    test_func = TestGcmDecrypt;
    test_name = "GCM Decrypt";
    const char *RSP_LIST_GCM_DEC[] = {
        "./nist_data/gcmtestvectors/gcmDecrypt128.rsp",
        "./nist_data/gcmtestvectors/gcmDecrypt192.rsp",
        "./nist_data/gcmtestvectors/gcmDecrypt256.rsp",
    };
    for (size_t i = 0;
         i < sizeof(RSP_LIST_GCM_DEC) / sizeof(RSP_LIST_GCM_DEC[0]);
         i++) {
        DoTests(test_func, test_name, RSP_LIST_GCM_DEC[i]);
    }
    // Test CCM Encrypt
    test_func = TestCcmEncrypt;
    test_name = "CCM Encrypt";
    const char *RSP_LIST_CCM_ENC[] = {
        "./nist_data/ccmtestvectors/VADT128.rsp",
        "./nist_data/ccmtestvectors/VADT192.rsp",
        "./nist_data/ccmtestvectors/VADT256.rsp",
        "./nist_data/ccmtestvectors/VNT128.rsp",
        "./nist_data/ccmtestvectors/VNT192.rsp",
        "./nist_data/ccmtestvectors/VNT256.rsp",
        "./nist_data/ccmtestvectors/VPT128.rsp",
        "./nist_data/ccmtestvectors/VPT192.rsp",
        "./nist_data/ccmtestvectors/VPT256.rsp",
        "./nist_data/ccmtestvectors/VTT128.rsp",
        "./nist_data/ccmtestvectors/VTT192.rsp",
        "./nist_data/ccmtestvectors/VTT256.rsp",
    };
    for (size_t i = 0u;
         i < sizeof(RSP_LIST_CCM_ENC) / sizeof(RSP_LIST_CCM_ENC[0]);
         i++) {
        DoTests(test_func, test_name, RSP_LIST_CCM_ENC[i]);
    }
    // Test CCM Decrypt
    test_func = TestCcmDecrypt;
    test_name = "CCM Decrypt";
    const char *RSP_LIST_CCM_DEC[] = {
        "./nist_data/ccmtestvectors/DVPT128.rsp",
        "./nist_data/ccmtestvectors/DVPT192.rsp",
        "./nist_data/ccmtestvectors/DVPT256.rsp",
    };
    for (size_t i = 0u;
         i < sizeof(RSP_LIST_CCM_DEC) / sizeof(RSP_LIST_CCM_DEC[0]);
         i++) {
        DoTests(test_func, test_name, RSP_LIST_CCM_DEC[i]);
    }
    // The total number of tests can be found by counting all "Count" keywords
    // in all .rsp files. Since CFB and OFB are not supported, files with name
    // containing them are filtered out.
    // For example:
    // find . -name "*.rsp" | grep -v "CFB" | grep -v "OFB" | xargs cat | grep
    // -i "count" | wc -l
    printf("Total pass: %zu, total fail:%zu\n", s_num_pass, s_num_fail);

    return s_num_fail;
}
