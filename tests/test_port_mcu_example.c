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

#include "test_port.h"
#include "uaes.h"

#include "FreeRTOS.h"
#include "semphr.h"
#include "task.h"

#include "SEGGER_RTT.h"

void UAES_TP_Init(void)
{
    (void)0;
}

void UAES_TP_LogString(const char *prompt, const char *str)
{
    SEGGER_RTT_printf(0, "%s %s\n", prompt, str);
}

void UAES_TP_LogNumber(const char *prompt, int32_t num)
{
    SEGGER_RTT_printf(0, "%s %d\n", prompt, num);
}

void UAES_TP_LogBytes(const char *prompt, const uint8_t *bytes, size_t len)
{
    SEGGER_RTT_printf(0, "%s ", prompt);
    for (size_t i = 0; i < len; i++) {
        SEGGER_RTT_printf(0, "%02x", bytes[i]);
    }
    SEGGER_RTT_printf(0, "\n");
}

void UAES_TP_LogBenchmarkTitle(void)
{
    SEGGER_RTT_printf(
            0,
            "mode\tRKMode\t32BIT\tSBox\tKey_len\tCTX\tW_NONE\tW_INIT\tW_PROC\tW_FULL\tW_SMP\tStack1\tStack2\tSpeed\t\n");
}

// Print the benchmark result
void UAES_TP_LogBenchmarkInfo(const UAES_BM_Info_t *bm_info)
{
    SEGGER_RTT_printf(
            0,
            "%s\t%d\t%d\t%d\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t\n",
            UAES_BM_MODE_STR[bm_info->mode],
            UAES_KEY_CONFIG,
            UAES_32BIT_CONFIG,
            UAES_SBOX_CONFIG,
            bm_info->key_len * 8u,
            bm_info->size_of_ctx,
            bm_info->watermark_none,
            bm_info->watermark_init,
            bm_info->watermark_process,
            bm_info->watermark_full_process,
            bm_info->watermark_simple_process,
            bm_info->stack_usage1,
            bm_info->stack_usage2,
            bm_info->speed);
}

uint32_t UAES_TP_GetTimeMs(void)
{
    return xTaskGetTickCount() * portTICK_PERIOD_MS;
}

size_t UAES_TP_GetStackWaterMark(void)
{
    return (size_t)uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t);
}

static SemaphoreHandle_t s_mutex_handle;
static void (*s_benchmark_func)(UAES_BM_Info_t *);

static void DoBenchmark(void *params)
{
    s_benchmark_func((UAES_BM_Info_t *)params);
    xSemaphoreGive(s_mutex_handle);
    while (1) {
        vTaskDelay(1000u);
    }
}

void UAES_TP_RunBenchmark(void (*func)(UAES_BM_Info_t *),
                          UAES_BM_Info_t *bm_info)
{
    // Initialize the mutex
    static StaticSemaphore_t m_mutex_storage;
    s_mutex_handle = xSemaphoreCreateBinaryStatic(&m_mutex_storage);
    (void)xSemaphoreTake(s_mutex_handle, 0u);
    // Start the benchmark task
    s_benchmark_func = func;
    static StaticTask_t m_task_storage;
    static StackType_t m_task_stack[configMINIMAL_STACK_SIZE + 1024u];
    TaskHandle_t handle =
            xTaskCreateStatic(DoBenchmark,
                              "uaes_bm",
                              sizeof(m_task_stack) / sizeof(m_task_stack[0]),
                              bm_info,
                              configMAX_PRIORITIES - 1u,
                              m_task_stack,
                              &m_task_storage);
    // Wait for the benchmark task to finish
    (void)xSemaphoreTake(s_mutex_handle, portMAX_DELAY);
    // Delete the benchmark task
    vTaskDelete(handle);
}
