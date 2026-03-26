# SPAKE2+EE for libsodium

`spake2-ee` is a compact C implementation of SPAKE2+EE, a password-authenticated key exchange built on top of libsodium's Ed25519 primitives and Elligator-style public-key masking.

This code is a good fit for projects that need:

- A low-level C PAKE implementation with a small API surface
- Password-based mutual authentication
- Two derived session keys, one for each direction
- An obfuscated elliptic-curve handshake shape suitable for stealth-oriented transports

## What This Project Does

SPAKE2+EE lets a client and a server that share a password:

- Derive matching session keys
- Mutually authenticate each other
- Avoid storing the raw password on the server

The server stores a derived credential blob. During login, the client and server exchange three short protocol messages:

1. `response1`: client to server
2. `response2`: server to client
3. `response3`: client to server

After a successful exchange:

- `client_sk` is intended for client-bound traffic
- `server_sk` is intended for server-bound traffic

## Current Quality Focus

This workspace version was refactored with performance and robustness as top priorities. The implementation now includes:

- Centralized parsing and serialization for stored/public protocol data
- Explicit validation of incoming curve points before use
- Cleaner failure paths with sensitive-memory cleanup
- Expanded deterministic, tamper, and randomized test coverage
- Human-readable test vector and telemetry reporting

## Repository Layout

- `src/crypto_spake.c`: protocol implementation
- `src/crypto_spake.h`: public API
- `test/test.c`: deterministic vectors, randomized telemetry, and tamper tests
- `../libsodium`: bundled libsodium source tree used by this workspace

## Public API

The main API is intentionally small:

- `crypto_spake_server_store()`: derive and serialize the server-side stored credential
- `crypto_spake_step0()`: extract the public password-hash parameters sent to the client
- `crypto_spake_step1()`: client creates the first SPAKE2+EE message
- `crypto_spake_step2()`: server processes `response1` and sends `response2`
- `crypto_spake_step3()`: client validates the server and sends `response3`
- `crypto_spake_step4()`: server validates the client and releases the final keys
- `crypto_spake_validate_public_data()`: verify expected KDF settings
- `crypto_spake_step0_dummy()`: generate deterministic dummy public data for account enumeration resistance

## Usage Example

The example below shows a complete client/server flow using a shared password.

```c
#include <assert.h>
#include <sodium.h>
#include <string.h>

#include "crypto_spake.h"

#define CLIENT_ID "client"
#define SERVER_ID "server"

int
main(void)
{
    unsigned char             stored_data[crypto_spake_STOREDBYTES];
    unsigned char             public_data[crypto_spake_PUBLICDATABYTES];
    unsigned char             response1[crypto_spake_RESPONSE1BYTES];
    unsigned char             response2[crypto_spake_RESPONSE2BYTES];
    unsigned char             response3[crypto_spake_RESPONSE3BYTES];
    crypto_spake_client_state client_st;
    crypto_spake_server_state server_st;
    crypto_spake_shared_keys  shared_keys_from_client;
    crypto_spake_shared_keys  shared_keys_from_server;
    int                       ret;

    if (sodium_init() < 0) {
        return 1;
    }

    ret = crypto_spake_server_store(stored_data, "password", 8,
                                    crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                    crypto_pwhash_MEMLIMIT_INTERACTIVE);
    assert(ret == 0);

    ret = crypto_spake_step0(&server_st, public_data, stored_data);
    assert(ret == 0);

    ret = crypto_spake_validate_public_data(
        public_data, crypto_pwhash_alg_default(),
        crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE);
    assert(ret == 0);

    ret = crypto_spake_step1(&client_st, response1, public_data, "password", 8);
    assert(ret == 0);

    ret = crypto_spake_step2(&server_st, response2, CLIENT_ID,
                             sizeof CLIENT_ID - 1, SERVER_ID,
                             sizeof SERVER_ID - 1, stored_data, response1);
    assert(ret == 0);

    ret = crypto_spake_step3(&client_st, response3, &shared_keys_from_server,
                             CLIENT_ID, sizeof CLIENT_ID - 1, SERVER_ID,
                             sizeof SERVER_ID - 1, response2);
    assert(ret == 0);

    ret = crypto_spake_step4(&server_st, &shared_keys_from_client, response3);
    assert(ret == 0);

    assert(memcmp(&shared_keys_from_client, &shared_keys_from_server,
                  sizeof shared_keys_from_client) == 0);

    return 0;
}
```

## Protocol Flow

### Server setup

The server derives `stored_data` once from the user's password:

```c
crypto_spake_server_store(stored_data, password, password_len,
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE);
```

This blob contains:

- Password hashing parameters
- Salt
- Derived SPAKE2+EE server data

### Login flow

At authentication time:

1. The server calls `crypto_spake_step0()` to send `public_data`
2. The client calls `crypto_spake_step1()` and sends `response1`
3. The server calls `crypto_spake_step2()` and sends `response2`
4. The client calls `crypto_spake_step3()` and sends `response3`
5. The server calls `crypto_spake_step4()` and releases the final shared keys

## Security Notes

- Always call `sodium_init()` before using the API.
- Use authenticated transport framing around the protocol messages if your application layer needs message typing, replay handling, or channel binding.
- Treat `stored_data` as sensitive server credential material.
- Keep `client_id` and `server_id` stable and unambiguous. They are part of key derivation and validation.
- If `crypto_spake_step3()` or `crypto_spake_step4()` fails, authentication must be treated as failed.
- The implementation zeroes sensitive state on failure paths, but your application should still avoid logging protocol secrets or raw buffers.

## Running The Tests

The test harness in `test/test.c` covers:

- Baseline success
- Wrong-password rejection
- Tampered public data
- Tampered `response1`
- Tampered `response2`
- Tampered `response3`
- Corrupted stored server data
- Deterministic dummy public data
- Deterministic human-readable vectors
- Randomized telemetry with generated passwords and identities

In this workspace, the test binary was built directly against the bundled libsodium sources.

### Example compile command used in this workspace

```sh
find ../libsodium/src/libsodium -name '*.c' | sort > /tmp/libsodium_sources.txt

cc -O2 -std=c99 -Wall -Wextra -Wno-unused-function \
  -I../libsodium/src/libsodium/include \
  -I../libsodium/src/libsodium/include/sodium \
  -I../libsodium/src/libsodium \
  -Isrc \
  -D_GNU_SOURCE=1 -DCONFIGURED=1 -DDEV_MODE=1 \
  -DHAVE_ATOMIC_OPS=1 -DHAVE_C11_MEMORY_FENCES=1 -DHAVE_CET_H=1 \
  -DHAVE_GCC_MEMORY_FENCES=1 -DHAVE_INLINE_ASM=1 -DHAVE_INTTYPES_H=1 \
  -DHAVE_STDINT_H=1 -DHAVE_TI_MODE=1 -DNATIVE_LITTLE_ENDIAN=1 \
  -DASM_HIDE_SYMBOL=.private_extern -DTLS=_Thread_local \
  -DHAVE_ARC4RANDOM=1 -DHAVE_ARC4RANDOM_BUF=1 -DHAVE_CATCHABLE_ABRT=1 \
  -DHAVE_CATCHABLE_SEGV=1 -DHAVE_CLOCK_GETTIME=1 -DHAVE_GETENTROPY=1 \
  -DHAVE_GETPID=1 -DHAVE_MADVISE=1 -DHAVE_MEMSET_S=1 -DHAVE_MLOCK=1 \
  -DHAVE_MMAP=1 -DHAVE_MPROTECT=1 -DHAVE_NANOSLEEP=1 \
  -DHAVE_POSIX_MEMALIGN=1 -DHAVE_PTHREAD=1 \
  -DHAVE_PTHREAD_PRIO_INHERIT=1 -DHAVE_RAISE=1 -DHAVE_SYSCONF=1 \
  -DHAVE_SYS_MMAN_H=1 -DHAVE_SYS_PARAM_H=1 -DHAVE_SYS_RANDOM_H=1 \
  -DHAVE_WEAK_SYMBOLS=1 -DHAVE_ARMCRYPTO=1 \
  @/tmp/libsodium_sources.txt \
  src/crypto_spake.c \
  test/test.c \
  -o /tmp/spake_test
```

Then run:

```sh
/tmp/spake_test
```

The output is organized into:

- `Validation Summary`
- `Deterministic Test Vectors`
- `Randomized Telemetry`

## Compatibility Note

This workspace uses the bundled libsodium tree in `../libsodium`. For compatibility with that source snapshot, the implementation uses the local Ed25519 ref10 Elligator mapping entry point internally.

## Limitations

- This is a low-level C API, not a complete application protocol.
- It does not define wire framing, retry logic, replay protection, or transport integration.
- The test harness is strong for correctness and coverage, but it is not a benchmark framework.
- The current repository layout is source-oriented rather than package-oriented; build system integration may need cleanup for production use.
