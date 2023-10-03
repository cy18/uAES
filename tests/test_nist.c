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

#define KEEP_TYPE           1u
#define KEEP_KEY            2u
#define KEEP_IV             4u
#define KEEP_PT             8u
#define KEEP_CT             16u
#define KEEP_TAG            32u
#define KEEP_APPEND_TAG_LEN 64u
#define KEEP_ACTUAL_PT_LEN  128u
#define KEEP_ACTUAL_AAD_LEN 256u

typedef enum {
    TYPE_UNSPECIFIED = 0,
    TYPE_ENCRYPT = 1,
    TYPE_DECRYPT = 2,
} TestType_t;

typedef struct TestCaseStruct {
    TestType_t type;
    size_t key_len;
    uint8_t *key;
    size_t iv_len;
    uint8_t *iv;
    size_t aad_len;
    uint8_t *aad;
    size_t plain_text_len;
    uint8_t *plain_text;
    size_t cipher_text_len;
    uint8_t *cipher_text;
    size_t tag_len;
    uint8_t *tag;
    size_t result_len;
    uint8_t *result;
    size_t actual_tag_len;
    size_t actual_pt_len;
    size_t actual_aad_len;
    bool expect_tag_fail;
    const char *error_msg;
    struct TestCaseStruct *next;
} TestCase_t;

typedef void (*FuncDoTest_t)(TestCase_t *p_case);

static size_t s_num_success = 0u;
static size_t s_num_failure = 0u;

static TestCase_t *ProcessRspFile(uint32_t keep, const char *filename);
static void FreeTestCases(TestCase_t *first);
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
                                 uint8_t **bytes,
                                 size_t *len);
static void PrintCase(const TestCase_t *p_case);
static void DoTests(FuncDoTest_t func,
                    const char *name,
                    uint32_t keep,
                    const char *rsp_file);
static bool CheckResult(TestCase_t *p_case,
                        const uint8_t *expected,
                        const uint8_t *result,
                        const size_t result_len,
                        const char *error_msg);
static bool CheckPlainText(TestCase_t *p_case, const uint8_t *result);
static bool CheckCipherText(TestCase_t *p_case, const uint8_t *result);
static bool CheckTag(TestCase_t *p_case, const uint8_t *result);
static bool CheckReturnValue(TestCase_t *p_case, bool expect, bool ret);
static void TestEcb(TestCase_t *p_case);
static void TestEcbMct(TestCase_t *p_case);
static void TestCbc(TestCase_t *p_case);
static void TestCbcMct(TestCase_t *p_case);
static void TestGcmEncrypt(TestCase_t *p_case);
static void TestGcmDecrypt(TestCase_t *p_case);
static void TestCcmEncrypt(TestCase_t *p_case);
static void TestCcmDecrypt(TestCase_t *p_case);

static TestCase_t *ProcessRspFile(uint32_t keep, const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Failed to open file %s\n", filename);
        return NULL;
    }
    static char line[1024 * 16u];
    TestCase_t test_case_handle;
    memset(&test_case_handle, 0, sizeof(TestCase_t));
    TestCase_t *last = &test_case_handle;
    TestCase_t *test_case = (TestCase_t *)malloc(sizeof(TestCase_t));
    memset(test_case, 0, sizeof(TestCase_t));
    while (!feof(file)) {
        fgets(line, sizeof(line), file);
        // Remove the trailing '\n'
        for (size_t i = 0; i < strlen(line); i++) {
            if ((line[i] == '\r') || (line[i] == '\n')) {
                line[i] = '\0';
            }
        }
        if (IsCommentLine(line)) {
            continue;
        }
        char *section = TryProcessSection(line);
        if (section != NULL) {
            char *remaining = section;
            while (remaining != NULL) {
                section = SplitSection(&remaining);
                if (strcmp(section, "ENCRYPT") == 0) {
                    test_case->type = TYPE_ENCRYPT;
                    continue;
                }
                if (strcmp(section, "DECRYPT") == 0) {
                    test_case->type = TYPE_DECRYPT;
                    continue;
                }
                char *key;
                char *value;
                if (!TrySplitKeyValue(section, &key, &value)) {
                    printf("Failed to parse section %s", section);
                    continue;
                }
                if (TryProcessSizeValue("Tlen",
                                        key,
                                        value,
                                        &test_case->actual_tag_len)) {
                    continue;
                }
                if (TryProcessSizeValue("Plen",
                                        key,
                                        value,
                                        &test_case->actual_pt_len)) {
                    continue;
                }
                if (TryProcessSizeValue("Alen",
                                        key,
                                        value,
                                        &test_case->actual_aad_len)) {
                    continue;
                }
                size_t dummy;
                static const char *IGNORE_KEYS[] = { "Nlen",   "IVlen",
                                                     "PTlen",  "AADlen",
                                                     "Keylen", "Taglen" };
                bool ignored = false;
                for (size_t i = 0; i < sizeof(IGNORE_KEYS) / sizeof(char *);
                     ++i) {
                    if (TryProcessSizeValue(IGNORE_KEYS[i],
                                            key,
                                            value,
                                            &dummy)) {
                        ignored = true;
                        break;
                    }
                }
                if (ignored) {
                    continue;
                }
                printf("Section %s = %s ignored\n", key, value);
            }
            continue;
        }
        if (IsEmptyLine(line)) {
            bool key_ready = test_case->key_len != 0u;
            bool data_ready = ((test_case->plain_text_len != 0u)
                               || (test_case->cipher_text_len != 0u));
            bool tag_ready = (test_case->tag_len != 0u);
            if (key_ready && (data_ready || tag_ready)) {
                // case ready
                last->next = test_case;
                last = test_case;
                test_case = (TestCase_t *)malloc(sizeof(TestCase_t));
                memset(test_case, 0, sizeof(TestCase_t));
                if ((keep & KEEP_TYPE) != 0u) {
                    test_case->type = last->type;
                }
                if ((keep & KEEP_KEY) != 0u) {
                    test_case->key_len = last->key_len;
                    test_case->key = (uint8_t *)malloc(test_case->key_len);
                    memcpy(test_case->key, last->key, test_case->key_len);
                }
                if ((keep & KEEP_IV) != 0u) {
                    test_case->iv_len = last->iv_len;
                    test_case->iv = (uint8_t *)malloc(test_case->iv_len);
                    memcpy(test_case->iv, last->iv, test_case->iv_len);
                }
                if ((keep & KEEP_PT) != 0u) {
                    test_case->plain_text_len = last->plain_text_len;
                    test_case->plain_text =
                            (uint8_t *)malloc(test_case->plain_text_len);
                    memcpy(test_case->plain_text,
                           last->plain_text,
                           test_case->plain_text_len);
                }
                if ((keep & KEEP_CT) != 0u) {
                    test_case->cipher_text_len = last->cipher_text_len;
                    test_case->cipher_text =
                            (uint8_t *)malloc(test_case->cipher_text_len);
                    memcpy(test_case->cipher_text,
                           last->cipher_text,
                           test_case->cipher_text_len);
                }
                if ((keep & KEEP_TAG) != 0u) {
                    test_case->tag_len = last->tag_len;
                    test_case->tag = (uint8_t *)malloc(test_case->tag_len);
                    memcpy(test_case->tag, last->tag, test_case->tag_len);
                }
                if ((keep & KEEP_APPEND_TAG_LEN) != 0u) {
                    test_case->actual_tag_len = last->actual_tag_len;
                }
                if ((keep & KEEP_ACTUAL_PT_LEN) != 0u) {
                    test_case->actual_pt_len = last->actual_pt_len;
                }
                if ((keep & KEEP_ACTUAL_AAD_LEN) != 0u) {
                    test_case->actual_aad_len = last->actual_aad_len;
                }
            }
            continue;
        }
        if (strcmp(line, "FAIL") == 0) {
            test_case->expect_tag_fail = true;
            continue;
        }
        if (0 == strcmp(line, "Result = Fail")) {
            test_case->expect_tag_fail = true;
            continue;
        }
        if (0 == strcmp(line, "Result = Pass")) {
            test_case->expect_tag_fail = false;
            continue;
        }
        char *key = NULL;
        char *value = NULL;
        if (!TrySplitKeyValue(line, &key, &value)) {
            continue;
        }
        size_t dummy_size;
        if (TryProcessSizeValue("COUNT", key, value, &dummy_size)) {
            continue;
        }
        if (TryProcessSizeValue("Count", key, value, &dummy_size)) {
            continue;
        }
        if (TryProcessSizeValue("Tlen",
                                key,
                                value,
                                &test_case->actual_tag_len)) {
            continue;
        }
        if (TryProcessSizeValue("Plen", key, value, &test_case->actual_pt_len)) {
            continue;
        }
        if (TryProcessSizeValue("Alen",
                                key,
                                value,
                                &test_case->actual_aad_len)) {
            continue;
        }
        // Ignore Nlen
        if (TryProcessSizeValue("Nlen", key, value, &dummy_size)) {
            continue;
        }
        if (TryProcessBytesValue("KEY",
                                 key,
                                 value,
                                 &test_case->key,
                                 &test_case->key_len)) {
            continue;
        }
        if (TryProcessBytesValue("Key",
                                 key,
                                 value,
                                 &test_case->key,
                                 &test_case->key_len)) {
            continue;
        }
        if (TryProcessBytesValue("IV",
                                 key,
                                 value,
                                 &test_case->iv,
                                 &test_case->iv_len)) {
            continue;
        }
        if (TryProcessBytesValue("Nonce",
                                 key,
                                 value,
                                 &test_case->iv,
                                 &test_case->iv_len)) {
            continue;
        }
        if (TryProcessBytesValue("AAD",
                                 key,
                                 value,
                                 &test_case->aad,
                                 &test_case->aad_len)) {
            continue;
        }
        if (TryProcessBytesValue("Adata",
                                 key,
                                 value,
                                 &test_case->aad,
                                 &test_case->aad_len)) {
            continue;
        }
        if (TryProcessBytesValue("PLAINTEXT",
                                 key,
                                 value,
                                 &test_case->plain_text,
                                 &test_case->plain_text_len)) {
            continue;
        }
        if (TryProcessBytesValue("PT",
                                 key,
                                 value,
                                 &test_case->plain_text,
                                 &test_case->plain_text_len)) {
            continue;
        }
        if (TryProcessBytesValue("Payload",
                                 key,
                                 value,
                                 &test_case->plain_text,
                                 &test_case->plain_text_len)) {
            continue;
        }
        if (TryProcessBytesValue("CIPHERTEXT",
                                 key,
                                 value,
                                 &test_case->cipher_text,
                                 &test_case->cipher_text_len)) {
            continue;
        }
        if (TryProcessBytesValue("CT",
                                 key,
                                 value,
                                 &test_case->cipher_text,
                                 &test_case->cipher_text_len)) {
            continue;
        }
        if (TryProcessBytesValue("Tag",
                                 key,
                                 value,
                                 &test_case->tag,
                                 &test_case->tag_len)) {
            continue;
        }
        printf("Unknown key %s\n", key);
    }
    free(test_case); // The last test case is not used
    return test_case_handle.next;
}

static void FreeTestCases(TestCase_t *first)
{
    TestCase_t *next = first;
    while (next != NULL) {
        TestCase_t *current = next;
        next = current->next;
        if (current->key != NULL) {
            free(current->key);
        }
        if (current->iv != NULL) {
            free(current->iv);
        }
        if (current->aad != NULL) {
            free(current->aad);
        }
        if (current->plain_text != NULL) {
            free(current->plain_text);
        }
        if (current->cipher_text != NULL) {
            free(current->cipher_text);
        }
        if (current->tag != NULL) {
            free(current->tag);
        }
        if (current->result != NULL) {
            free(current->result);
        }
        free(current);
    }
}

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

static bool IsCommentLine(const char *line)
{
    return line[0] == '#';
}

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

static bool TryProcessBytesValue(const char *expected_key,
                                 const char *actual_key,
                                 const char *value_str,
                                 uint8_t **p_bytes,
                                 size_t *p_len)
{
    if (strcmp(expected_key, actual_key) != 0) {
        return false;
    }
    if ((*p_bytes) != NULL) {
        free(*p_bytes);
    }
    *p_len = strlen(value_str) / 2;
    *p_bytes = (uint8_t *)malloc(*p_len);
    for (size_t i = 0; i < *p_len; i++) {
        sscanf(&value_str[i * 2], "%02hhx", &(*p_bytes)[i]);
    }
    return true;
}

static void PrintCase(const TestCase_t *p_case)
{
    printf("Type: %d\n", p_case->type);
    if (p_case->error_msg != NULL) {
        printf("Failed, error msg: %s\n", p_case->error_msg);
    }
    printf("Key: ");
    for (size_t i = 0; i < p_case->key_len; i++) {
        printf("%02x", p_case->key[i]);
    }
    printf("\n");
    printf("IV: ");
    for (size_t i = 0; i < p_case->iv_len; i++) {
        printf("%02x", p_case->iv[i]);
    }
    printf("\n");
    printf("AAD: ");
    for (size_t i = 0; i < p_case->aad_len; i++) {
        printf("%02x", p_case->aad[i]);
    }
    printf("\n");
    printf("PlainText: ");
    for (size_t i = 0; i < p_case->plain_text_len; i++) {
        printf("%02x", p_case->plain_text[i]);
    }
    printf("\n");
    printf("CipherTest: ");
    for (size_t i = 0; i < p_case->cipher_text_len; i++) {
        printf("%02x", p_case->cipher_text[i]);
    }
    printf("\n");
    printf("Tag: ");
    for (size_t i = 0; i < p_case->tag_len; i++) {
        printf("%02x", p_case->tag[i]);
    }
    printf("\nResult: ");
    for (size_t i = 0; i < p_case->result_len; i++) {
        printf("%02x", p_case->result[i]);
    }
    printf("\n");
    if (p_case->expect_tag_fail) {
        printf("Expect tag fail: True\n");
    }
    printf("Press Enter to continue...");
    (void)getchar();
}

static void DoTests(FuncDoTest_t func,
                    const char *name,
                    uint32_t keep,
                    const char *rsp_file)
{
    static size_t m_begin_num_success = 0u;
    static size_t m_begin_num_failure = 0u;

    printf("Testing %s in %s\n", name, rsp_file);
    TestCase_t *cases = ProcessRspFile(keep, rsp_file);
    TestCase_t *p_case = cases;
    while (p_case != NULL) {
        func(p_case);
        if (p_case->error_msg != NULL) {
            s_num_failure++;
            PrintCase(p_case);
        } else {
            s_num_success++;
        }
        p_case = p_case->next;
    }
    FreeTestCases(p_case);
    printf("Success: %zu, failure: %zu\n",
           s_num_success - m_begin_num_success,
           s_num_failure - m_begin_num_failure);
}

static bool CheckResult(TestCase_t *p_case,
                        const uint8_t *expected,
                        const uint8_t *result,
                        const size_t result_len,
                        const char *error_msg)
{
    if (memcmp(expected, result, result_len) != 0) {
        if (p_case->error_msg == NULL) {
            p_case->error_msg = error_msg;
        }
        if (p_case->result == NULL) {
            p_case->result = (uint8_t *)malloc(result_len);
            memcpy(p_case->result, result, result_len);
            p_case->result_len = result_len;
        }
        return false;
    } else {
        return true;
    }
}

static bool CheckPlainText(TestCase_t *p_case, const uint8_t *result)
{
    return CheckResult(p_case,
                       p_case->plain_text,
                       result,
                       p_case->plain_text_len,
                       "Plain text mismatch");
}

static bool CheckCipherText(TestCase_t *p_case, const uint8_t *result)
{
    return CheckResult(p_case,
                       p_case->cipher_text,
                       result,
                       p_case->cipher_text_len,
                       "Cipher text mismatch");
}

static bool CheckTag(TestCase_t *p_case, const uint8_t *result)
{
    if (memcmp(p_case->tag, result, p_case->tag_len) != 0) {
        if (p_case->error_msg == NULL) {
            p_case->error_msg = "Unexpected tag checking result";
        }
        if (p_case->result == NULL) {
            p_case->result = (uint8_t *)malloc(p_case->tag_len);
            memcpy(p_case->result, result, p_case->tag_len);
            p_case->result_len = p_case->tag_len;
        }
        return false;
    } else {
        return true;
    }
}

static bool CheckReturnValue(TestCase_t *p_case, bool expect, bool ret)
{
    if (expect != ret) {
        if (p_case->error_msg == NULL) {
            if (expect) {
                p_case->error_msg = "Expect true but got false";
            } else {
                p_case->error_msg = "Expect false but got true";
            }
        }
    }
    return ret;
}

static bool CheckInput(TestCase_t *p_case,
                       bool key,
                       bool iv,
                       bool plain_text,
                       bool ptm16,
                       bool cipher_text,
                       bool tag)
{
    if (key && ((p_case->key == NULL) || (p_case->key_len == 0u))) {
        if (p_case->error_msg == NULL) {
            p_case->error_msg = "Key is empty";
        }
        return false;
    }
    if (iv && ((p_case->iv == NULL) || (p_case->iv_len == 0u))) {
        if (p_case->error_msg == NULL) {
            p_case->error_msg = "IV is empty";
        }
        return false;
    }
    if (plain_text
        && ((p_case->plain_text == NULL) || (p_case->plain_text_len == 0u))) {
        if (p_case->error_msg == NULL) {
            p_case->error_msg = "Plain text is empty";
        }
        return false;
    }
    if (ptm16 && (p_case->plain_text_len % 16u != 0u)) {
        if (p_case->error_msg == NULL) {
            p_case->error_msg = "Plain text length is not multiple of 16";
        }
        return false;
    }
    if (cipher_text
        && ((p_case->cipher_text == NULL) || (p_case->cipher_text_len == 0u))) {
        if (p_case->error_msg == NULL) {
            p_case->error_msg = "Cipher text is empty";
        }
        return false;
    }
    if (tag && ((p_case->tag == NULL) || (p_case->tag_len == 0u))) {
        if (p_case->error_msg == NULL) {
            p_case->error_msg = "Tag is empty";
        }
        return false;
    }
    return true;
}

static void TestEcb(TestCase_t *p_case)
{
    uint8_t result[1024u];
    if (!CheckInput(p_case, true, false, true, true, true, false)) {
        return;
    }
    UAES_ECB_SimpleEncrypt(p_case->key,
                           p_case->key_len,
                           p_case->plain_text,
                           result,
                           p_case->plain_text_len);
    (void)CheckCipherText(p_case, result);
    UAES_ECB_SimpleDecrypt(p_case->key,
                           p_case->key_len,
                           p_case->cipher_text,
                           result,
                           p_case->cipher_text_len);
    (void)CheckPlainText(p_case, result);
}

static void TestEcbMct(TestCase_t *p_case)
{
    uint8_t result[1024u];
    if (!CheckInput(p_case, true, false, true, true, true, false)) {
        return;
    }
    memcpy(result, p_case->plain_text, p_case->plain_text_len);
    for (size_t i = 0; i < 1000; ++i) {
        UAES_ECB_SimpleEncrypt(p_case->key,
                               p_case->key_len,
                               result,
                               result,
                               p_case->plain_text_len);
    }
    CheckCipherText(p_case, result);
    memcpy(result, p_case->cipher_text, p_case->cipher_text_len);
    for (size_t i = 0; i < 1000; ++i) {
        UAES_ECB_SimpleDecrypt(p_case->key,
                               p_case->key_len,
                               result,
                               result,
                               p_case->cipher_text_len);
    }
    CheckPlainText(p_case, result);
}

static void TestCbc(TestCase_t *p_case)
{
    uint8_t result[1024u];
    if (!CheckInput(p_case, true, true, true, true, true, false)) {
        return;
    }
    UAES_CBC_SimpleEncrypt(p_case->key,
                           p_case->key_len,
                           p_case->iv,
                           p_case->plain_text,
                           result,
                           p_case->plain_text_len);
    (void)CheckCipherText(p_case, result);
    UAES_CBC_SimpleDecrypt(p_case->key,
                           p_case->key_len,
                           p_case->iv,
                           p_case->cipher_text,
                           result,
                           p_case->cipher_text_len);
    (void)CheckPlainText(p_case, result);
}

static void TestCbcMct(TestCase_t *p_case)
{
    if (!CheckInput(p_case, true, true, true, true, true, false)) {
        return;
    }
    if ((p_case->plain_text_len != 16u) || (p_case->cipher_text_len != 16u)) {
        p_case->error_msg = "data length must be 16 for CBC MCT";
    }
    if (p_case->type == TYPE_ENCRYPT) {
        UAES_CBC_Ctx_t ctx;
        uint8_t ct[16u];
        uint8_t pt[16u];
        uint8_t pt_new[16u];
        for (size_t i = 0u; i < 1000u; ++i) {
            if (i == 0u) {
                UAES_CBC_Init(&ctx, p_case->key, p_case->key_len, p_case->iv);
                UAES_CBC_Encrypt(&ctx, p_case->plain_text, ct, 16u);
                memcpy(pt, p_case->iv, 16u);
            } else {
                memcpy(pt_new, ct, 16u);
                UAES_CBC_Encrypt(&ctx, pt, ct, 16u);
                memcpy(pt, pt_new, 16u);
            }
        }
        CheckCipherText(p_case, ct);
    } else if (p_case->type == TYPE_DECRYPT) {
        UAES_CBC_Ctx_t ctx;
        uint8_t ct[16u];
        uint8_t pt[16u];
        uint8_t ct_new[16u];
        for (size_t i = 0u; i < 1000u; ++i) {
            if (i == 0u) {
                UAES_CBC_Init(&ctx, p_case->key, p_case->key_len, p_case->iv);
                UAES_CBC_Decrypt(&ctx, p_case->cipher_text, pt, 16u);
                memcpy(ct, p_case->iv, 16u);
            } else {
                memcpy(ct_new, pt, 16u);
                UAES_CBC_Decrypt(&ctx, ct, pt, 16u);
                memcpy(ct, ct_new, 16u);
            }
        }
        CheckPlainText(p_case, pt);
    } else {
        p_case->error_msg = "Test type unspecified for CBC MCT";
    }
}

static void TestGcmEncrypt(TestCase_t *p_case)
{
    uint8_t result[1024u];
    uint8_t tag[16u];
    if (!CheckInput(p_case, true, true, false, false, false, true)) {
        return;
    }
    UAES_GCM_SimpleEncrypt(p_case->key,
                           p_case->key_len,
                           p_case->iv,
                           p_case->iv_len,
                           p_case->aad,
                           p_case->aad_len,
                           p_case->plain_text,
                           result,
                           p_case->plain_text_len,
                           tag,
                           p_case->tag_len);
    (void)CheckCipherText(p_case, result);
    (void)CheckTag(p_case, tag);
}

static void TestGcmDecrypt(TestCase_t *p_case)
{
    uint8_t result[1024u];
    if (!CheckInput(p_case, true, true, false, false, false, true)) {
        return;
    }
    bool ret = UAES_GCM_SimpleDecrypt(p_case->key,
                                      p_case->key_len,
                                      p_case->iv,
                                      p_case->iv_len,
                                      p_case->aad,
                                      p_case->aad_len,
                                      p_case->cipher_text,
                                      result,
                                      p_case->cipher_text_len,
                                      p_case->tag,
                                      p_case->tag_len);
    (void)CheckReturnValue(p_case, !p_case->expect_tag_fail, ret);
    if (!p_case->expect_tag_fail) {
        if ((p_case->cipher_text_len > 0) && (p_case->plain_text_len == 0u)) {
            p_case->error_msg = "Plain text expected but not provided";
        }
        (void)CheckPlainText(p_case, result);
    }
}

static void TestCcmEncrypt(TestCase_t *p_case)
{
    uint8_t result[1024u];
    if (!CheckInput(p_case, true, true, false, false, false, false)) {
        return;
    }
    // In some cases, Plen = 0 but "Payload = 00" is given
    if (p_case->actual_pt_len == 0) {
        p_case->plain_text_len = 0;
    }
    // In some cases, Alen = 0 but "Adata = 00" is given
    if (p_case->actual_aad_len == 0) {
        p_case->aad_len = 0;
    }
    // When encrypting, the tag are appended to cipher_text
    UAES_CCM_SimpleEncrypt(p_case->key,
                           p_case->key_len,
                           p_case->iv,
                           p_case->iv_len,
                           p_case->aad,
                           p_case->aad_len,
                           p_case->plain_text,
                           result,
                           p_case->plain_text_len,
                           &result[p_case->plain_text_len],
                           p_case->actual_tag_len);
    (void)CheckCipherText(p_case, result);
}

static void TestCcmDecrypt(TestCase_t *p_case)
{
    uint8_t result[1024u];
    if (!CheckInput(p_case, true, true, false, false, true, false)) {
        return;
    }
    // In some cases, Plen = 0 but "Payload = 00" is given
    if (p_case->actual_pt_len == 0) {
        p_case->plain_text_len = 0;
    }
    // In some cases, Alen = 0 but "Adata = 00" is given
    if (p_case->actual_aad_len == 0) {
        p_case->aad_len = 0;
    }
    bool ret = UAES_CCM_SimpleDecrypt(
            p_case->key,
            p_case->key_len,
            p_case->iv,
            p_case->iv_len,
            p_case->aad,
            p_case->aad_len,
            p_case->cipher_text,
            result,
            p_case->cipher_text_len - p_case->actual_tag_len,
            &p_case->cipher_text[p_case->plain_text_len],
            p_case->actual_tag_len);
    (void)CheckReturnValue(p_case, !p_case->expect_tag_fail, ret);
    if (!p_case->expect_tag_fail) {
        if (((p_case->cipher_text_len - p_case->actual_tag_len) > 0)
            && (p_case->plain_text_len == 0u)) {
            p_case->error_msg = "Plain text expected but not provided";
        }
        (void)CheckPlainText(p_case, result);
    }
}

int main(void)
{
    FuncDoTest_t test_func;
    const char *test_name;
    uint32_t keep;
    // ECB
    test_func = TestEcb;
    test_name = "ECB";
    keep = KEEP_TYPE;
    const char *RSP_LIST_ECB[] = {
        "./tests/nist_data/aesmmt/ECBMMT128.rsp",
        "./tests/nist_data/aesmmt/ECBMMT192.rsp",
        "./tests/nist_data/aesmmt/ECBMMT256.rsp",
        "./tests/nist_data/KAT_AES/ECBGFSbox128.rsp",
        "./tests/nist_data/KAT_AES/ECBGFSbox192.rsp",
        "./tests/nist_data/KAT_AES/ECBGFSbox256.rsp",
        "./tests/nist_data/KAT_AES/ECBKeySbox128.rsp",
        "./tests/nist_data/KAT_AES/ECBKeySbox192.rsp",
        "./tests/nist_data/KAT_AES/ECBKeySbox256.rsp",
        "./tests/nist_data/KAT_AES/ECBVarKey128.rsp",
        "./tests/nist_data/KAT_AES/ECBVarKey192.rsp",
        "./tests/nist_data/KAT_AES/ECBVarKey256.rsp",
        "./tests/nist_data/KAT_AES/ECBVarTxt128.rsp",
        "./tests/nist_data/KAT_AES/ECBVarTxt192.rsp",
        "./tests/nist_data/KAT_AES/ECBVarTxt256.rsp",
    };
    for (size_t i = 0; i < sizeof(RSP_LIST_ECB) / sizeof(RSP_LIST_ECB[0]);
         i++) {
        DoTests(test_func, test_name, keep, RSP_LIST_ECB[i]);
    }
    // ECB MCT
    test_func = TestEcbMct;
    test_name = "ECB MCT";
    keep = KEEP_TYPE;
    const char *RSP_LIST_ECB_MCT[] = {
        "./tests/nist_data/aesmct/ECBMCT128.rsp",
        "./tests/nist_data/aesmct/ECBMCT192.rsp",
        "./tests/nist_data/aesmct/ECBMCT256.rsp",
    };
    for (size_t i = 0;
         i < sizeof(RSP_LIST_ECB_MCT) / sizeof(RSP_LIST_ECB_MCT[0]);
         i++) {
        DoTests(test_func, test_name, keep, RSP_LIST_ECB_MCT[i]);
    }
    // CBC
    test_func = TestCbc;
    test_name = "CBC";
    keep = KEEP_TYPE;
    const char *RSP_LIST_CBC[] = {
        "./tests/nist_data/aesmmt/CBCMMT128.rsp",
        "./tests/nist_data/aesmmt/CBCMMT192.rsp",
        "./tests/nist_data/aesmmt/CBCMMT256.rsp",
        "./tests/nist_data/KAT_AES/CBCGFSbox128.rsp",
        "./tests/nist_data/KAT_AES/CBCGFSbox192.rsp",
        "./tests/nist_data/KAT_AES/CBCGFSbox256.rsp",
        "./tests/nist_data/KAT_AES/CBCKeySbox128.rsp",
        "./tests/nist_data/KAT_AES/CBCKeySbox192.rsp",
        "./tests/nist_data/KAT_AES/CBCKeySbox256.rsp",
        "./tests/nist_data/KAT_AES/CBCVarKey128.rsp",
        "./tests/nist_data/KAT_AES/CBCVarKey192.rsp",
        "./tests/nist_data/KAT_AES/CBCVarKey256.rsp",
        "./tests/nist_data/KAT_AES/CBCVarTxt128.rsp",
        "./tests/nist_data/KAT_AES/CBCVarTxt192.rsp",
        "./tests/nist_data/KAT_AES/CBCVarTxt256.rsp",
    };
    for (size_t i = 0; i < sizeof(RSP_LIST_CBC) / sizeof(RSP_LIST_CBC[0]);
         i++) {
        DoTests(test_func, test_name, keep, RSP_LIST_CBC[i]);
    }
    // CBC MCT
    test_func = TestCbcMct;
    test_name = "CBC";
    keep = KEEP_TYPE;
    const char *RSP_LIST_CBC_MCT[] = {
        "./tests/nist_data/aesmct/CBCMCT128.rsp",
        "./tests/nist_data/aesmct/CBCMCT192.rsp",
        "./tests/nist_data/aesmct/CBCMCT256.rsp",
    };
    for (size_t i = 0;
         i < sizeof(RSP_LIST_CBC_MCT) / sizeof(RSP_LIST_CBC_MCT[0]);
         i++) {
        DoTests(test_func, test_name, keep, RSP_LIST_CBC_MCT[i]);
    }
    // GCM Encrypt
    test_func = TestGcmEncrypt;
    test_name = "GCM Encrypt";
    keep = 0u;
    const char *RSP_LIST_GCM_ENC[] = {
        "./tests/nist_data/gcmtestvectors/gcmEncryptExtIV128.rsp",
        "./tests/nist_data/gcmtestvectors/gcmEncryptExtIV192.rsp",
        "./tests/nist_data/gcmtestvectors/gcmEncryptExtIV256.rsp",
    };
    for (size_t i = 0;
         i < sizeof(RSP_LIST_GCM_ENC) / sizeof(RSP_LIST_GCM_ENC[0]);
         i++) {
        DoTests(test_func, test_name, keep, RSP_LIST_GCM_ENC[i]);
    }
    // GCM Decrypt
    test_func = TestGcmDecrypt;
    test_name = "GCM Decrypt";
    keep = 0u;
    const char *RSP_LIST_GCM_DEC[] = {
        "./tests/nist_data/gcmtestvectors/gcmDecrypt128.rsp",
        "./tests/nist_data/gcmtestvectors/gcmDecrypt192.rsp",
        "./tests/nist_data/gcmtestvectors/gcmDecrypt256.rsp",
    };
    for (size_t i = 0;
         i < sizeof(RSP_LIST_GCM_DEC) / sizeof(RSP_LIST_GCM_DEC[0]);
         i++) {
        DoTests(test_func, test_name, keep, RSP_LIST_GCM_DEC[i]);
    }
    // Test CCM Encrypt
    test_func = TestCcmEncrypt;
    test_name = "CCM Encrypt";
    keep = KEEP_KEY | KEEP_IV | KEEP_APPEND_TAG_LEN | KEEP_ACTUAL_PT_LEN
         | KEEP_ACTUAL_AAD_LEN;
    const char *RSP_LIST_CCM_ENC[] = {
        "./tests/nist_data/ccmtestvectors/VADT128.rsp",
        "./tests/nist_data/ccmtestvectors/VADT192.rsp",
        "./tests/nist_data/ccmtestvectors/VADT256.rsp",
        "./tests/nist_data/ccmtestvectors/VNT128.rsp",
        "./tests/nist_data/ccmtestvectors/VNT192.rsp",
        "./tests/nist_data/ccmtestvectors/VNT256.rsp",
        "./tests/nist_data/ccmtestvectors/VPT128.rsp",
        "./tests/nist_data/ccmtestvectors/VPT192.rsp",
        "./tests/nist_data/ccmtestvectors/VPT256.rsp",
        "./tests/nist_data/ccmtestvectors/VTT128.rsp",
        "./tests/nist_data/ccmtestvectors/VTT192.rsp",
        "./tests/nist_data/ccmtestvectors/VTT256.rsp",
    };
    for (size_t i = 0;
         i < sizeof(RSP_LIST_CCM_ENC) / sizeof(RSP_LIST_CCM_ENC[0]);
         i++) {
        DoTests(test_func, test_name, keep, RSP_LIST_CCM_ENC[i]);
    }
    // Test CCM Decrypt
    test_func = TestCcmDecrypt;
    test_name = "CCM Decrypt";
    keep = KEEP_KEY | KEEP_IV | KEEP_APPEND_TAG_LEN | KEEP_ACTUAL_PT_LEN
         | KEEP_ACTUAL_AAD_LEN;
    const char *RSP_LIST_CCM_DEC[] = {
        "./tests/nist_data/ccmtestvectors/DVPT128.rsp",
        "./tests/nist_data/ccmtestvectors/DVPT192.rsp",
        "./tests/nist_data/ccmtestvectors/DVPT256.rsp",
    };
    for (size_t i = 0;
         i < sizeof(RSP_LIST_CCM_DEC) / sizeof(RSP_LIST_CCM_DEC[0]);
         i++) {
        DoTests(test_func, test_name, keep, RSP_LIST_CCM_DEC[i]);
    }

    printf("Total success: %zu, failure:%zu\n", s_num_success, s_num_failure);
}
