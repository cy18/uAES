#!/usr/bin/bash
# Run this script from the root of the repository to test the code size of different configurations.

for key in 0 1; do
    for u32 in 0 1; do
        for sbox in 0 1 2; do
            for mode in ECB CBC CFB CFB1 OFB CTR CCM GCM; do
                echo -e -n "$key\t$sbox\t$u32\t$mode\t128\t"
                arm-none-eabi-gcc -mcpu=cortex-m0 -Os \
                    -DUAES_ENABLE_ALL=0 \
                    -DUAES_ENABLE_$mode=1 \
                    -DUAES_KEY_CONFIG=$key \
                    -DUAES_32BIT_CONFIG=$u32 \
                    -DUAES_SBOX_CONFIG=$sbox \
                    -DUAES_ENABLE_128=1 \
                    -c uaes.c &&
                    arm-none-eabi-size uaes.o -B | grep -o "[0-9]\+" | head -1 &&
                    rm uaes.o
                echo -e -n "$key\t$u32\t$sbox\t$mode\tAll\t"
                arm-none-eabi-gcc -mcpu=cortex-m0 -Os \
                    -DUAES_ENABLE_ALL=0 \
                    -DUAES_ENABLE_$mode=1 \
                    -DUAES_KEY_CONFIG=$key \
                    -DUAES_32BIT_CONFIG=$u32 \
                    -DUAES_SBOX_CONFIG=$sbox \
                    -DUAES_ENABLE_128=1 \
                    -DUAES_ENABLE_192=1 \
                    -DUAES_ENABLE_256=1 \
                    -c uaes.c &&
                    arm-none-eabi-size uaes.o -B | grep -o "[0-9]\+" | head -1 &&
                    rm uaes.o
            done
        done
    done
done
