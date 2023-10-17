# uAES (Micro AES)

uAES (Micro AES) is a compact yet fully-featured AES library. It is primarily designed for Micro Controllers (MCUs), but can also be used on other platforms.

## Highlights

1. ANSI C99 compatible.
2. MISRA-C:2012 compliant (validated with Cppcheck).
3. Consists of just one header file and one source file.
4. Supports most AES modes: ECB, CBC, CFB, CFB1, OFB, CTR, CCM, GCM, with all three key sizes (128, 192, and 256).
5. Consistent API across all modes.
6. Offers both context-free APIs and context-based APIs:
   - The context-free API is simple one-function API intending for encrypting/decrypting data in one go.
   - The context-based API is more flexible, facilitating the encryption/decryption of data in chunks.
7. Thread-safe as long as each thread uses its own context.
8. All modes and key sizes can be turned on/off individually.
9. Provide 8-bit mode and 32-bit mode for different platforms:
   - 8-bit mode suits 8-bit CPUs.
   - 32-bit mode can be up to 180% faster on 32-bit CPUs.
   - Using 8-bit mode on 32-bit CPUs can reduce code size.
10. Offers options to trade between CPU time, RAM usage and code size. The code size can be reduced to under 800 bytes, and the RAM usage can be reduced to under 34 bytes. Refer to the [Configuration](#configuration) section for details.
11. Thoroughly tested with test vectors from [NIST](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program) using GitHub Actions.

## Usage

1. For CMake projects, include this repository as a submodule and add the following lines to your CMakeLists.txt::
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
   - Initialize the context `UAES_XXX_Ctx_t` with function `UAES_XXX_Init`.
   - For CCM and GCM modes, use `UAES_XXX_AddAad` to add optionally AAD data.
   - Use `UAES_XXX_Encrypt` or `UAES_XXX_Decrypt` to encrypt/decrypt data in chunks.
   - For CCM and GCM, use `UAES_XXX_GenerateTag` to generate the authentication tag, or use `UAES_XXX_VerifyTag` to verify the authentication tag.
6. Example (using AES-128-CTR mode):

```c
    const uint8_t KEY[16] = { /* Key bytes */ };
    const uint8_t NONCE[11] = { /* Nonce bytes */ };
    const uint8_t DATA[64] = { /* Data bytes */ };

    // Use context-free API to encrypt data in one shot.
    uint8_t result[64];
    UAES_CTR_SimpleEncrypt(KEY, 16u, NONCE, 11u, DATA, result, sizeof(DATA));

    // Use context-based API to decrypt data in chunks.
    uint8_t chunk[16u];
    UAES_CTR_Ctx_t ctx;
    UAES_CTR_Init(&ctx, KEY, 16u, NONCE, 11u);
    for (size_t i = 0; i < sizeof(DATA); i += 16u) {
        UAES_CTR_Decrypt(&ctx, DATA + i, chunk, 16u);
        // Do something with the encrypted data, such as send it over the UART.
    }

```

## Mode Selection

Here are some recommendations if you are not sure which mode to use:

- If you need to communicate with other devices, use the mode that the other device supports.
- If you just need to encrypt/decrypt data, use CTR mode or OFB mode.
  - CTR mode is more popular than OFB mode.
  - CTR mode supports random access, which means you can decrypt any part of the data without decrypting the previous parts. It also supports parallel encryption/decryption (not implemented in this library).
  - The OFB mode is simpler. In this library, the OFB mode cost slightly less RAM, Flash and CPU time. If you just hit the RAM or Flash limit, you can consider using OFB mode.
- If you need an AEAD algorithm (Authenticated Encryption with Associated Data), use CCM mode or GCM mode.
  - GCM mode seems more popular than CCM.
  - CCM mode use AES for both encryption and authentication, which means the code size is smaller.
  - GCM mode employ another hash algorithm for authentication. This hash algorithm is faster and support parallel processing(not implemented in this library). However, it costs more Flash.

## Configuration

- Try to use the default configuration first. It usually works for most cases.
- The options can be configured by passing the corresponding macros to the compiler. They can also be configured by adding corresponding definitions at the beginning of `uaes.h`.
- Most compilers are able to remove unused functions automatically, so it is usually unnecessary to turn unused modes off. Just leave them on and let the compiler do the dirty work.
- The default configuration is already optimized for RAM usage. However, the RAM usage can be further reduced by disabling AES-192 and AES-256, i.e., setting UAES_ENABLE_AES_192=0 and UAES_ENABLE_AES_256=0.
- Set UAES_32BIT_CONFIG=1 will improve the performance on 32-bit CPUs. The code size and RAM may increase slightly, depending on the compiler.
- Setting UAES_KEY_CONFIG=1 will improve the performance effectively. It will increase the RAM usage by about 200 bytes. If the context is allocated as a global variable or static variable, the worst result is a failure at linking, which is not a big deal. However, if the context is allocated as a local variable, or you are using the context-free APIs (which allocate the context as a local variable internally), this may cause a stack overflow if the stack size is limited. This is very DANGEROUS. Please make sure you know what you are doing before using this option.
- If the speed is still not fast enough, you can try using different compiler optimization levels. With arm-none-eabi-gcc, the -O3 is almost 2 times faster than -Os.
- Setting UAES_SBOX_CONFIG=1 will store the 256-byte S-Box in RAM. It saves about 160 bytes of Flash, but costs 256 bytes of RAM. Use this option if you have enough of RAM but very limited Flash. One of such situations is a bootloader.
- Setting UAES_SBOX_CONFIG=2 will compute the S-Box on the fly. It saves about 100 bytes of Flash without additional RAM usage. However, it costs a lot of CPU time, making it 30~50 times slower than the default configuration. Use this option if both the Flash and RAM are very limited, while you don't care about the performance.
