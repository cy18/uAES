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

#include "uaes_benchmark.h"

#include <stdio.h>

int main(void)
{
    const char MODE_STR[][8] = {
        [UAES_BM_MODE_ECB_ENC] = "ECB_ENC", [UAES_BM_MODE_ECB_DEC] = "ECB_DEC",
        [UAES_BM_MODE_CBC_ENC] = "CBC_ENC", [UAES_BM_MODE_CBC_DEC] = "CBC_DEC",
        [UAES_BM_MODE_CTR] = "CTR",         [UAES_BM_MODE_CCM] = "CCM",
        [UAES_BM_MODE_GCM] = "GCM",
    };
    for (UAES_BM_Mode_t mode = (UAES_BM_Mode_t)0; mode < UAES_BM_END; mode++) {
        for (size_t key_len = 16u; key_len <= 32u; key_len += 8u) {
            printf("%s %zu speed(Bps): %u\n",
                   MODE_STR[mode],
                   key_len * 8u,
                   UAES_Benchmark(mode, key_len));
        }
    }
    return 0u;
}
