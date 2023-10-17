# uAES (Micro AES)

uAES (Micro AES) is a compact yet fully-featured AES library. It is primarily designed for Micro Controllers (MCUs), but can also be used on other platforms.

## Table of Contents
- [uAES (Micro AES)](#uaes-micro-aes)
  - [Table of Contents](#table-of-contents)
  - [Highlights](#highlights)
  - [Usage](#usage)
  - [Mode Selection](#mode-selection)
  - [Configuration](#configuration)
  - [Tests](#tests)
    - [Test sets](#test-sets)
    - [How to run the tests on PC](#how-to-run-the-tests-on-pc)
    - [How to run the tests on MCU](#how-to-run-the-tests-on-mcu)
  - [Benchmark](#benchmark)
    - [Benchmark of code size](#benchmark-of-code-size)
    - [Benchmark of speed and RAM usage](#benchmark-of-speed-and-ram-usage)


## Highlights

1. Distributed under the MIT license.
2. ANSI C99 compatible.
3. MISRA-C:2012 compliant (validated with Cppcheck).
4. Consists of just one header file and one source file.
5. Supports most AES modes: ECB, CBC, CFB, CFB1, OFB, CTR, CCM, GCM, with all three key sizes (128, 192, and 256).
6. Consistent API across all modes.
7. Offers both context-free APIs and context-based APIs:
   - The context-free APIs are simple one-function API intended for encrypting/decrypting data in one go.
   - The context-based APIs are more flexible, facilitating the encryption/decryption of data in chunks.
8. Thread-safe as long as each thread uses its own context.
9.  All modes and key sizes can be turned on/off individually.
10. Offers 8-bit mode and 32-bit mode:
   - 8-bit mode suits 8-bit CPUs.
   - 32-bit mode is optimized for 32-bit CPUs. Depending on the compiler and other options, it can be 30%~220% faster. Refer to tests/benchmark_result.md for details.
   - Using 8-bit mode on 32-bit CPUs can reduce code size.
11. Offers options to trade between CPU time, RAM usage, and code size. The code size can be reduced to as low as 738 bytes, and the RAM usage of the context can be reduced to as low as 34 bytes. Refer to the [Configuration](#configuration) section, [test_size_result](tests/test_size_result.md), and [benchmark_result](tests/benchmark_result.md) for details.
12. Thoroughly tested with test vectors from [NIST](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) using GitHub Actions.

## Usage

1. For CMake projects, include this repository as a submodule and add the following lines to your CMakeLists.txt:
```cmake
add_subdirectory(uAES)
target_link_libraries(your_target uaes)
```
2. For other build systems, add `uaes.h` and `uaes.c` to your build system.
3. All the APIs are prefixed with `UAES_XXX`, where `XXX` are one of the following:
   - ECB: Electronic Codebook Mode
   - CBC: Cipher Block Chaining Mode
   - CFB: Cipher Feedback Mode (segment size must be a multiple of 8)
   - CFB1: Cipher Feedback Mode with 1-bit segment size
   - OFB: Output Feedback Mode
   - CTR: Counter Mode
   - CCM: Counter with CBC-MAC Mode
   - GCM: Galois/Counter Mode
4. For context-free APIs, the function names are `UAES_XXX_SimpleEncrypt` or `UAES_XXX_SimpleDecrypt`.
5. For context-based APIs, the steps are:
   - Initialize the context `UAES_XXX_Ctx_t` with the function `UAES_XXX_Init`.
   - For CCM and GCM modes, use `UAES_XXX_AddAad` to add optionally AAD data.
   - Use `UAES_XXX_Encrypt` or `UAES_XXX_Decrypt` to encrypt/decrypt data in chunks.
   - For CCM and GCM, use `UAES_XXX_GenerateTag` to generate the authentication tag or use `UAES_XXX_VerifyTag` to verify the authentication tag.
6. Example (using AES-128-CTR mode):

```c
    const uint8_t KEY[16] = { /* Key bytes */ };
    const uint8_t NONCE[11] = { /* Nonce bytes */ };
    const uint8_t DATA[64] = { /* Data bytes */ };

    // Use the context-free API to encrypt data in one shot.
    uint8_t result[64];
    UAES_CTR_SimpleEncrypt(KEY, 16u, NONCE, 11u, DATA, result, sizeof(DATA));

    // Use the context-based API to decrypt data in chunks.
    uint8_t chunk[16u];
    UAES_CTR_Ctx_t ctx;
    UAES_CTR_Init(&ctx, KEY, 16u, NONCE, 11u);
    for (size_t i = 0; i < sizeof(DATA); i += 16u) {
        UAES_CTR_Decrypt(&ctx, DATA + i, chunk, 16u);
        // Do something with the encrypted data, such as sending it over the UART.
    }

```

## Mode Selection

Here are some recommendations if you are not sure which mode to use:

- If you need to communicate with other devices, use the mode that the other device supports.
- If you just need to encrypt/decrypt data, use CTR mode or OFB mode.
  - CTR mode is more popular than OFB mode.
  - CTR mode supports random access, which means you can decrypt any part of the data without decrypting the previous parts. It also supports parallel encryption/decryption (not implemented in this library).
  - The OFB mode is simpler. In this library, the OFB mode cost slightly less RAM, Flash, and CPU time. If you just hit the RAM or Flash limit, you can consider using the OFB mode.
- If you need an AEAD algorithm (Authenticated Encryption with Associated Data), use CCM mode or GCM mode.
  - GCM mode seems more popular than CCM.
  - CCM mode uses AES for both encryption and authentication, which means the code size is smaller.
  - GCM mode employs another hash algorithm for authentication. This hash algorithm is faster and supports parallel processing (not implemented in this library). However, it costs more Flash.

## Configuration

- Try to use the default configuration first. It usually works for most cases.
- The options can be configured by passing the corresponding macros to the compiler. They can also be configured by adding corresponding definitions at the beginning of `uaes.h`.
- Most compilers are able to remove unused functions automatically, so it is usually unnecessary to turn unused modes off. Just leave them on and let the compiler do the dirty work.
- The default configuration is already optimized for RAM usage. However, the RAM usage can be further reduced by disabling AES-192 and AES-256, i.e., setting UAES_ENABLE_AES_192=0 and UAES_ENABLE_AES_256=0.
- Setting UAES_32BIT_CONFIG=1 will improve the performance on 32-bit CPUs. The code size and RAM may increase slightly, depending on the compiler.
- Setting UAES_KEY_CONFIG=1 will improve the performance effectively. It will increase the RAM usage by about 200 bytes. If the context is allocated as a global variable or static variable, the worst result is a failure at linking, which is not a big deal. However, if the context is allocated as a local variable, or you are using the context-free APIs (which allocate the context as a local variable internally), this may cause a stack overflow if the stack size is limited. This is very DANGEROUS. Please make sure you know what you are doing before using this option.
- If the speed is still not fast enough, you can try using different compiler optimization levels. With arm-none-eabi-gcc, the -O3 is almost 2 times faster than -Os.
- Setting UAES_SBOX_CONFIG=1 will store the 256-byte S-Box in RAM. It saves about 160 bytes of Flash but costs 256 bytes of RAM. Use this option if you have enough RAM but very limited Flash. One such situation is a bootloader.
- Setting UAES_SBOX_CONFIG=2 will compute the S-Box on the fly. It saves about 100 bytes of Flash without additional RAM usage. However, it costs a lot of CPU time, making it 30~50 times slower than the default configuration. Use this option if both the Flash and RAM are very limited, while you don't care about the performance.
- Refer to benchmarks in the [Benchmark](#benchmark) section for details.

## Tests

### Test sets
- There are two test sets to verify the correctness of the library:
  - test_simple is a set of simple tests that can be run on any platform. All APIs are tested with test_simple. However, most of the tests only include one test vector. In most cases, it is enough to verify the correctness of the library.
  - test_nist is a set of tests that use test vectors from NIST. It is more comprehensive, but it needs the capability to do file I/O and costs much more time to run. It is worth noting that though the CTR mode is mentioned on the webpage https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers, there is no test data for CTR mode.
- Both two test sets are run automatically with GitHub Actions.
  - For test_simple, the combination of all options/key sizes/modes is tested individually. I.e., there are 2 (key options) * 3 (Sbox options) * 2 (32bit options) * 3 (key sizes) * 8 (AES modes) = 288 (combinations) tested. The Cppcheck is also run for these combinations.
  - For test_nist, all options are tested individually with all the key sizes and modes. I.e., there are 2 (key options) * 3 (Sbox options) * 2 (32bit options) = 12 (combinations) of tests for test_nist. The Cppcheck is also run for these combinations.
  - Refer to tests/CMakeLists.txt for details.

### How to run the tests on PC

Since the tests are already run automatically with GitHub Actions, it is usually unnecessary to run the tests on PC. However, if you want to run the tests on PC, you can follow the steps below:

  1. Install CMake, GCC, and Cppcheck.
  2. Configure the project: cmake -B build -DTEST_ALL_OPTIONS=1 -S tests
  3. Build the project: cmake --build build
  4. Run the tests: cmake --build -t test

Note that it takes 36 minutes on the GitHub Action server to run all the test cases. If you just made some modifications and want to check the correctness, removing -DTEST_ALL_OPTIONS=1 in step 2 will run test_simple and test_nist with just default options, which is much faster.

### How to run the tests on MCU

To run test_simple on an MCU, you can follow the steps below:

  1. Add uaes.h, uaes.c, tests/test_simple.c, tests/test_simple.h, tests/test_port.h to your project.
  2. Implement the functions in tests/test_port.h. tests/test_port_mcu_example.c would be a good start for porting. It is worth noting that if there is no failure in the tests, most UAES_TP_LogXxx functions will not be called. So you can just leave them empty.
  3. Call function UAES_TestSimple() to run the tests.

## Benchmark

### Benchmark of code size

There is a script tests/test_size.sh available to measure the code size of all modes. This script compiles uaes.c with the following options:

```
arm-none-eabi-gcc -mcpu=cortex-m0 -Os -c -DUAES_ENABLE_ALL=0 -DUAES_ENABLE_XXX -DUAES_ENABLE_YYY
```
then measures the test section size with arm-none-eabi-size. All AES modes are measured individually with different combinations of options. The key size is tested with two situations: 1. Enable only AES-128; 2. Enable all key sizes.

The command to run the script is:
```
bash tests/test_size.sh
```

The result varies with different compilers, different versions of uAES, and the MCUs. Refer to [tests/test_size_result.md](tests/test_size_result.md) for a reference result.

### Benchmark of speed and RAM usage

The source file tests/benchmark.c tests the speed and RAM usage of all modes. The steps to run the benchmark on PC are simple:

  1. Configure the project: cmake -B build -DENABLE_BENCHMARK=1 -S tests
  2. Build the project: cmake --build build
  3. Run the benchmark: build/uaes_benchmark

To run the benchmark on MCUs, there are some extra steps:
  1. Add uaes.h, uaes.c, tests/benchmark.c, tests/benchmark.h, tests/test_port.h to your project.
  2. Implement the functions in tests/test_port.h. You can take test_port_mcu_example.c as an example. Among the port functions, UAES_TP_RunBenchmark, UAES_TP_GetTimeMs, and UAES_TP_LogBenchmarkInfo are necessary. To measure the stack usage, UAES_TP_RunBenchmark must clean up the stack before each test, and UAES_TP_GetStackWaterMark should be able to return the stack watermark during tests. The implementation in test_port_mcu_example.c is based on FreeRTOS. It creates a new task for each test and gets the stack usage by calling uxTaskGetStackHighWaterMark.
  3. Call UAES_BenchmarkAll() to run the benchmark for all modes.

The result depends on a lot of factors, such as the versions of compilers, the versions of uAES, the MCUs, the compiler options, etc. Refer to [tests/benchmark_result.md](tests/benchmark_result.md) for a reference result.
