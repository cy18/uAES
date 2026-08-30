# uAES Design Goals and Principles

Status: Accepted
Accepted: 2026-08-30
Owner: uAES maintainer

This document defines the design direction for ongoing uAES maintenance. It is
a target for future changes, not a claim that every existing API and
implementation already satisfies every requirement below.

## Scope

uAES is a compact AES library for bare-metal systems, small RTOS applications,
and other resource-constrained targets. The current development phase remains
focused on AES and its modes of operation. Adding non-AES primitives is outside
the current scope.

The library should remain easy to integrate into projects that cannot afford a
general-purpose cryptographic framework or platform runtime.

## Priority Order

The design priorities are:

1. Correct AES behavior, memory safety within the documented memory contract,
   and authentication integrity.
2. Small and predictable Flash and RAM usage.
3. Portability, configurability, and ease of review.
4. CPU performance and latency.

The first item is a correctness boundary, not an optimization trade-off. Within
that boundary, Flash and RAM are the primary optimization targets. CPU
performance is secondary and may be selected through compile-time options when
the application can afford the additional resources.

## Resource Model

Resource cost must be described using separate measurements where applicable:

- Flash or ROM usage;
- static RAM usage;
- RAM used by each context;
- peak stack usage; and
- throughput, latency, or cycles per byte.

Shared Flash and per-context RAM are not interchangeable costs. The default
configuration should avoid large per-context RAM costs because they multiply
when an application keeps several contexts or places contexts on a small stack.
Flash-limited, RAM-limited, and performance-oriented applications may select
different compile-time trade-offs.

Resource claims must identify the target, compiler and version, optimization
flags, enabled modes, key sizes, and relevant configuration macros. A change is
not considered smaller or faster without measurements on a representative
configuration.

## Configuration

Modes, key sizes, and optional implementation strategies should remain
independently removable at compile time. Disabled functionality should not add
material code or data to the final program.

Configuration options should expose a real and measured trade-off. They should
not create different cryptographic results or weaken the mandatory correctness
boundary. The default configuration should remain conservative for small MCUs;
performance optimizations that consume additional Flash or RAM are opt-in.

Valid calls must have the same cryptographic semantics whether optional
diagnostics are enabled or disabled. Supported configuration combinations must
be covered by proportionate automated tests.

## Mandatory Correctness and Security Boundary

The following properties apply to every configuration and must not be compiled
out:

- valid inputs produce results compatible with the applicable AES standard;
- scalar lengths and parameters are handled without out-of-bounds access,
  integer undefined behavior, or authentication bypass;
- an empty, oversized, or otherwise invalid authentication tag cannot be
  accepted;
- authentication tags are compared without an early exit based on secret data;
- authentication failure is reported unambiguously and is never reported as
  success; and
- compile-time resource options do not change the cryptographic meaning of a
  valid operation.

As a C library, uAES cannot validate whether an arbitrary caller-provided
pointer refers to a sufficiently large accessible object. Buffer ownership,
pointer validity, and required buffer sizes therefore remain part of the
documented caller contract. Scalar parameters controlled by the API, such as
data and tag lengths, must still be handled safely before they are used for
indexing or copying.

Streaming authenticated decryption may expose provisional plaintext before the
final tag is available in order to avoid buffering the complete message. Such
plaintext is unauthenticated and must not be consumed, acted upon, or forwarded
until tag verification succeeds. This lifecycle must be explicit in the API
documentation. One-shot APIs should provide a clear authentication result and
should avoid leaving callers with apparently valid output after failure when
that can be achieved without disproportionate resource cost.

## Optional Development Diagnostics

Checks whose purpose is to diagnose violations of the documented caller
contract may be enabled during development and compiled out for production.
Examples include:

- assertions for null pointers when a nonzero length requires a buffer;
- API call-order and context-state checks;
- checks that cumulative AAD and data lengths match declared lengths; and
- diagnostics for unsupported buffer overlap.

Removing these diagnostics must not disable handling required to prevent an
out-of-bounds access, integer undefined behavior, or authentication bypass. It
must not change the result of a valid call.

## Threat Model and High-Cost Hardening

The default portable implementation does not claim resistance to physical
side-channel analysis, electromagnetic or power analysis, fault injection, or
an attacker that can observe target-specific microarchitectural state. Masked
AES, redundant fault detection, secure hardware integration, and comparable
hardening can have substantial Flash, RAM, and performance costs and are not
part of the default design.

Any future hardening option must state its threat model, resource cost,
platform assumptions, and evidence. It must not be presented as general
side-channel resistance without suitable review and target-specific evidence.

## API and Mode Guidance

The library may retain ECB, CBC, CFB, CFB1, OFB, and CTR for interoperability
with existing protocols. Their presence is not a recommendation for new
designs. Documentation for new designs should prefer authenticated encryption,
such as CCM or GCM, and should make key, IV, nonce, tag, and plaintext lifecycle
requirements explicit.

APIs should keep legal use straightforward and make failure visible without
requiring hidden allocation or platform services. New public state, call-order
requirements, or configuration macros need a concrete resource or correctness
benefit.

## Change Acceptance

A proposed feature or optimization should answer the following questions:

1. Does it preserve the mandatory correctness and security boundary?
2. Which representative target configuration benefits from it?
3. What are the measured Flash, static RAM, context RAM, stack, and performance
   effects?
4. Does it add public state, call-order requirements, or misuse opportunities?
5. Can the same benefit be obtained through an existing compile-time control?
6. Is its implementation, test, and long-term maintenance cost proportionate to
   the demonstrated benefit?

Features without a current AES use case or a measurable benefit should remain
out of scope.
