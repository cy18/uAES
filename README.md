# uAES (Micro AES)

This is a small 32-bit optimized MISRA-C:2012 compliant AES library supporting 128, 192 and 256 bit keys in ECB, CBC, CRT, CCM and GCM modes. The highlights are:

1. ANSI C99 compatible.
2. MISRA-C:2012 compliant (checked with Cppcheck).
3. Support for 128, 192 and 256 bit keys at the same time.
4. Support for ECB, CBC, CRT, CCM and GCM modes.
5. Optimized for 32-bit CPUs.
6. Configurable to only include the modes you need.
7. Small code size and memory footprint.
8. Tested with test vectors from NIST (https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program).

This project took [tiny-AES-c](https://github.com/kokke/tiny-AES-c) as a startup. However, most of the code has been rewritten and the API has been changed. Some more features have been added, such as CCM/GCM modes and a more flexible API. Further more, both RAM and FLASH usage have been reduced.
