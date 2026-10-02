# AEAD boundary and randomized testing

`test_simple.c` checks legal/illegal CCM and GCM tag lengths, CCM initialization
consistency, authentication failures and length-field boundaries.
`test_aead.c` adds reproducible chunking, in-place, failure-output and memory-bound
checks. Both run in normal CTest/PR CI; no hardware or new runtime dependency is
required. The extra all-mode AEAD tests use the existing 12 R/S/W combinations.

## Oracles and scope

- Existing NIST response files remain the independent known-answer oracle.
- `TestWrap` contains an independently generated GCM answer for a constructed
  16-byte IV whose J0 is `000000000000000000000000fffffffe`. A 48-byte zero
  plaintext crosses the low-32-bit counter wrap. Ciphertext prefixes check the
  increment; the complete tag checks J0 recovery. The reference was generated
  with Python `cryptography` 48.0.0 AESGCM, not with uAES:

  ```python
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM
  print(AESGCM(bytes(16)).encrypt(
      bytes.fromhex('b746b338fd43e4015e314cd52dc6eac9'), bytes(48), b'').hex())
  ```

  The IV follows `J0 = IV * H^2 XOR (0^64 || 128) * H` in GHASH's field,
  where `H = AES_0(0) = 66e94bd4ef8a2c3b884cfa59ca342b2e`.
  [SP800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
  specifies inc32 and non-96-bit IV processing in sections 6.2 and 7.1.
- Random cases compare contiguous and chunked operation, decrypt round trips,
  tampered-tag rejection, cleared failure output and surrounding sentinels.
  These invariants can expose state/memory errors, but agreement between two
  paths in the same implementation is not an independent cryptographic proof.
- Exact-sized heap inputs let ASan detect overreads. UBSan checks executed
  undefined operations. Neither proves unexecuted paths, constant-time behavior,
  physical side-channel resistance or MCU execution.
- Synthetic large length-field tests do not process multi-gigabyte messages.
  Payload/AAD in the randomized harness are bounded to 255 bytes each. This batch
  does not establish all maximum-message or nonce-reuse policy limits.

## Reproduction

Normal CTest uses xorshift32 seed `0x800038cd`, 256 cases with 583-byte encoded
inputs, plus the complete GCM wrap vector when GCM/key128 are enabled:

```sh
cmake -S tests -B build/aead -DCMAKE_BUILD_TYPE=Release
cmake --build build/aead --parallel
ctest --test-dir build/aead --output-on-failure
```

An optional existing Clang/libFuzzer runtime can use the same source. These are
bash-style commands; PowerShell must quote the comma-containing sanitizer flag
and may need Clang's runtime DLL directory on PATH. Put executables, corpus and
crash artifacts in a task-specific temporary directory, not the repository.

```sh
clang -O1 -g -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer \
  -DUAES_LIBFUZZER -I. uaes.c tests/test_aead.c -o "$TMPDIR/fuzz-aead"
"$TMPDIR/fuzz-aead" -seed=2147498189 -runs=10000 -max_len=583 \
  -artifact_prefix="$TMPDIR/"
"$TMPDIR/fuzz-aead" -minimize_crash=1 -runs=2000 -seed=2147498189 \
  -exact_artifact_path="$TMPDIR/minimized" "$TMPDIR/crash-input"
"$TMPDIR/fuzz-aead" "$TMPDIR/minimized" -runs=1
```

Without `UAES_LIBFUZZER`, `test_aead <binary-input>` replays a single input.
Encoding is stable within this harness: byte 0 selects mode/length strategy;
bytes 1..7 select key/tag/nonce sizes, payload/AAD lengths, chunk size and tag
tamper position. Key, nonce, AAD and plaintext start at offsets 8, 40, 72, 328.
Absent bytes are zero. Sizes use the legal tables in `TestCase`. When GCM/key128
are enabled and byte 0 has bit 7 set, the input instead selects `TestWrap` with
`byte1 % 49` plaintext bytes.

## Recorded bounded batch

Authentication-boundary source: `8953f00bb61b87ab2fcbbbbc5f7cc48c22e922a8`.
Counter-wrap correction: the accompanying commit introducing this harness and
record. Tests use the sources from that commit; later revisions must rerun them
before adopting these results.

On the authentication-boundary source, fixed-seed libFuzzer found input `eb11`
(wrap vector, 17-byte plaintext). Automatic minimization with 2000 runs confirmed
the original two-byte input could not be shortened. Replay fails the ciphertext
oracle before the inc32 correction and succeeds after it. This is a real short
message with a non-96-bit IV, not an artificially large payload.

The corrected source passed the following local software checks on Windows:

| Compiler / configuration | Executed checks |
| --- | --- |
| GCC 15.2, all modes/keys, R0/S0/W0 | simple, AEAD, NIST |
| Clang 23.1, all modes/keys, R0/S0/W0 | simple, AEAD, NIST with ASan+UBSan |
| MSVC 19.44, Win32, static runtime, all modes/keys, R0/S0/W0 | simple, AEAD, NIST |
| GCC 15.2, CCM/key192 only, R1/S2/W1 | simple, AEAD |
| GCC 15.2, GCM/key256 only, R0/S1/W0 | simple, AEAD |
| GCC 15.2, CTR/key128 only, R0/S0/W0 | simple; disabled-AEAD compile/link smoke test |

Clang/libFuzzer 23.1 with ASan+UBSan, `-O1 -g`, seed 2147498189 and maximum
encoded length 583 completed 10000 runs for default all-mode/all-key R0/S0/W0,
5000 for CCM/key192 R1/S2/W1 and 5000 for GCM/key256 R0/S1/W0, without a failure.
These runs started from an empty corpus and explored mostly short encoded
inputs: a 583-byte limit is not evidence that all 583-byte combinations were
visited. The separate deterministic cases populate complete 583-byte inputs.
Fuzzer mutation sequences can differ with compiler/runtime versions.

Win32 uses `-A Win32 -DCMAKE_POLICY_DEFAULT_CMP0091=NEW
-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded` to avoid unrelated dynamic-runtime
DLL resolution in the local environment. The default 64-bit MSVC CI remains
independent. PR CI results belong to the actual checked commit, not this record.

## Resource comparison

Baseline `8cf66c36f10d210846d3a9113f82622b3c3905fb` versus the corrected source:
Arm GNU 15.2.1, Cortex-M3/Thumb, `-Os -ffunction-sections -fdata-sections
-fstack-usage`, key128 only, R0/S0/W0, one mode enabled at a time. Link with
`-nostartfiles --specs=nosys.specs -Wl,--gc-sections`, retaining every public API
of that mode with `--undefined=UAES_<mode>_<function>` and setting the entry to
its Init function. Measure with `arm-none-eabi-size -B` and read `.su` files.

| Linked code+RO, bytes | Baseline | Corrected | Delta |
| --- | ---: | ---: | ---: |
| CCM |2082|2086|+4|
| GCM |2150|2106|-44|
| CTR |1022|1022|0|

Static data/BSS are zero for these images; public context layouts are unchanged.
Direct compiler-reported frames change VerifyTag 32→40 bytes in both modes,
SimpleDecrypt CCM 88→96 and GCM 96→112. These are local frames, not worst-case
call-chain stack measurements. The linked library images are not deployable
firmware; no simulator, hardware or throughput measurements were performed.
