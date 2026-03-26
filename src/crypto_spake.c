
#include <assert.h>
#include <sodium.h>
#include <sodium/private/ed25519_ref10.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_spake.h"
#include "pushpop.h"

typedef struct spake_keys_ {
    unsigned char M[32];
    unsigned char N[32];
    unsigned char L[32];
    unsigned char h_K[32];
    unsigned char h_L[32];
} spake_keys;

typedef struct spake_validators_ {
    unsigned char client_validator[32];
    unsigned char server_validator[32];
} spake_validators;

typedef struct spake_public_data_ {
    int                alg;
    unsigned long long opslimit;
    size_t             memlimit;
    unsigned char      salt[crypto_pwhash_SALTBYTES];
} spake_public_data;

typedef struct spake_stored_data_ {
    spake_public_data public_data;
    unsigned char     M[32];
    unsigned char     N[32];
    unsigned char     h_K[32];
    unsigned char     L[32];
} spake_stored_data;

#define H_VERSION 0x01
#define SER_VERSION 0x0001

static int
_is_valid_group_element(const unsigned char p[32])
{
    return crypto_core_ed25519_is_valid_point(p) == 1;
}

static int
_validate_limits(uint64_t memlimit_u64, size_t *memlimit)
{
    if (memlimit_u64 > (uint64_t) SIZE_MAX) {
        return -1;
    }
    *memlimit = (size_t) memlimit_u64;

    return 0;
}

static void
_encode_public_data(unsigned char out[crypto_spake_PUBLICDATABYTES],
                    const spake_public_data *pd)
{
    size_t i = 0U;

    _push16(out, &i, SER_VERSION);
    _push16(out, &i, (uint16_t) pd->alg);
    _push64(out, &i, (uint64_t) pd->opslimit);
    _push64(out, &i, (uint64_t) pd->memlimit);
    _push128(out, &i, pd->salt);
    assert(i == crypto_spake_PUBLICDATABYTES);
}

static int
_decode_public_data(spake_public_data *pd,
                    const unsigned char in[crypto_spake_PUBLICDATABYTES])
{
    size_t   i = 0U;
    uint16_t v16;
    uint64_t v64;

    _pop16(&v16, in, &i);
    if (v16 != SER_VERSION) {
        return -1;
    }
    _pop16(&v16, in, &i);
    pd->alg = (int) v16;
    _pop64(&v64, in, &i);
    pd->opslimit = (unsigned long long) v64;
    _pop64(&v64, in, &i);
    if (_validate_limits(v64, &pd->memlimit) != 0) {
        return -1;
    }
    _pop128(pd->salt, in, &i);
    assert(i == crypto_spake_PUBLICDATABYTES);

    return 0;
}

static void
_encode_stored_data(unsigned char out[crypto_spake_STOREDBYTES],
                    const spake_stored_data *sd)
{
    size_t i = 0U;

    _push16(out, &i, SER_VERSION);
    _push16(out, &i, (uint16_t) sd->public_data.alg);
    _push64(out, &i, (uint64_t) sd->public_data.opslimit);
    _push64(out, &i, (uint64_t) sd->public_data.memlimit);
    _push128(out, &i, sd->public_data.salt);
    _push256(out, &i, sd->M);
    _push256(out, &i, sd->N);
    _push256(out, &i, sd->h_K);
    _push256(out, &i, sd->L);
    assert(i == crypto_spake_STOREDBYTES);
}

static int
_decode_stored_data(spake_stored_data *sd,
                    const unsigned char in[crypto_spake_STOREDBYTES])
{
    size_t   i = 0U;
    uint16_t v16;
    uint64_t v64;

    _pop16(&v16, in, &i);
    if (v16 != SER_VERSION) {
        return -1;
    }
    _pop16(&v16, in, &i);
    sd->public_data.alg = (int) v16;
    _pop64(&v64, in, &i);
    sd->public_data.opslimit = (unsigned long long) v64;
    _pop64(&v64, in, &i);
    if (_validate_limits(v64, &sd->public_data.memlimit) != 0) {
        return -1;
    }
    _pop128(sd->public_data.salt, in, &i);
    _pop256(sd->M, in, &i);
    _pop256(sd->N, in, &i);
    _pop256(sd->h_K, in, &i);
    _pop256(sd->L, in, &i);
    assert(i == crypto_spake_STOREDBYTES);

    if (!_is_valid_group_element(sd->M) || !_is_valid_group_element(sd->N) ||
        !_is_valid_group_element(sd->L)) {
        sodium_memzero(sd, sizeof *sd);
        return -1;
    }
    return 0;
}

static int
_masked_share_sub(unsigned char out[32], const unsigned char share[32],
                  const unsigned char mask[32])
{
    if (!_is_valid_group_element(share) || !_is_valid_group_element(mask) ||
        crypto_core_ed25519_sub(out, share, mask) != 0 ||
        !_is_valid_group_element(out)) {
        return -1;
    }
    return 0;
}

static void
_random_scalar(unsigned char n[32])
{
    do {
        randombytes_buf(n, 32);
        n[0] &= 248;
        n[31] &= 127;
    } while (sodium_is_zero(n, 32));
}

static int
_create_keys(spake_keys *keys, unsigned char salt[crypto_pwhash_SALTBYTES],
             const char *const passwd, unsigned long long passwdlen,
             unsigned long long opslimit, size_t memlimit, int alg)
{
    unsigned char  h_MNKL[32 * 4];
    unsigned char *h_M = &h_MNKL[32 * 0];
    unsigned char *h_N = &h_MNKL[32 * 1];
    unsigned char *h_K = &h_MNKL[32 * 2];
    unsigned char *h_L = &h_MNKL[32 * 3];

    if (crypto_pwhash(h_MNKL, sizeof h_MNKL, passwd, passwdlen, salt, opslimit,
                      memlimit, alg) != 0) {
        return -1;
    }
    ge25519_from_uniform(keys->M, h_M);
    ge25519_from_uniform(keys->N, h_N);
    memcpy(keys->h_K, h_K, 32);
    memcpy(keys->h_L, h_L, 32);
    crypto_scalarmult_ed25519_base(keys->L, keys->h_L);

    return 0;
}

static int
_shared_keys_and_validators(crypto_spake_shared_keys *shared_keys,
                            spake_validators *validators, const char *client_id,
                            size_t client_id_len, const char *server_id,
                            size_t server_id_len, const unsigned char X[32],
                            const unsigned char Y[32],
                            const unsigned char Z[32],
                            const unsigned char h_K[32],
                            const unsigned char V[32])
{
    crypto_generichash_state hst;
    unsigned char            k0[crypto_kdf_KEYBYTES];
    unsigned char            len;
    unsigned char            h_version;

    if (client_id_len > 255 || server_id_len > 255) {
        return -1;
    }
    crypto_generichash_init(&hst, NULL, 0, sizeof k0);

    h_version = H_VERSION;
    crypto_generichash_update(&hst, &h_version, 1);

    len = (unsigned char) client_id_len;
    crypto_generichash_update(&hst, &len, 1);
    crypto_generichash_update(&hst, (const unsigned char *) client_id, len);

    len = (unsigned char) server_id_len;
    crypto_generichash_update(&hst, &len, 1);
    crypto_generichash_update(&hst, (const unsigned char *) server_id, len);

    len = 32;
    crypto_generichash_update(&hst, X, len);
    crypto_generichash_update(&hst, Y, len);
    crypto_generichash_update(&hst, Z, len);
    crypto_generichash_update(&hst, h_K, len);
    crypto_generichash_update(&hst, V, len);

    crypto_generichash_final(&hst, k0, sizeof k0);

    crypto_kdf_derive_from_key(shared_keys->client_sk,
                               crypto_spake_SHAREDKEYBYTES, 0, "PAKE2+EE", k0);
    crypto_kdf_derive_from_key(shared_keys->server_sk,
                               crypto_spake_SHAREDKEYBYTES, 1, "PAKE2+EE", k0);
    crypto_kdf_derive_from_key(validators->client_validator, 32, 2, "PAKE2+EE",
                               k0);
    crypto_kdf_derive_from_key(validators->server_validator, 32, 3, "PAKE2+EE",
                               k0);

    sodium_memzero(k0, sizeof k0);

    return 0;
}

int
crypto_spake_server_store(unsigned char stored_data[crypto_spake_STOREDBYTES],
                          const char *const  passwd,
                          unsigned long long passwdlen,
                          unsigned long long opslimit, size_t memlimit)
{
    spake_keys        keys;
    spake_stored_data sd;

    randombytes_buf(sd.public_data.salt, sizeof sd.public_data.salt);
    sd.public_data.alg = crypto_pwhash_alg_default();
    sd.public_data.opslimit = opslimit;
    sd.public_data.memlimit = memlimit;
    if (_create_keys(&keys, sd.public_data.salt, passwd, passwdlen, opslimit,
                     memlimit,
                     crypto_pwhash_alg_default()) != 0) {
        return -1;
    }
    memcpy(sd.M, keys.M, sizeof sd.M);
    memcpy(sd.N, keys.N, sizeof sd.N);
    memcpy(sd.h_K, keys.h_K, sizeof sd.h_K);
    memcpy(sd.L, keys.L, sizeof sd.L);
    _encode_stored_data(stored_data, &sd);

    sodium_memzero(&keys, sizeof keys);
    sodium_memzero(&sd, sizeof sd);

    return 0;
}

int
crypto_spake_validate_public_data(
    const unsigned char public_data[crypto_spake_PUBLICDATABYTES],
    const int expected_alg, unsigned long long expected_opslimit,
    unsigned long long expected_memlimit)
{
    spake_public_data pd;

    if (_decode_public_data(&pd, public_data) != 0) {
        return -1;
    }
    if (pd.alg != expected_alg || pd.opslimit != expected_opslimit ||
        pd.memlimit != expected_memlimit) {
        return -1;
    }
    return 0;
}

int
crypto_spake_step0_dummy(
    crypto_spake_server_state *st,
    unsigned char              public_data[crypto_spake_PUBLICDATABYTES],
    const char *client_id, size_t client_id_len, const char *server_id,
    size_t server_id_len, unsigned long long opslimit, size_t memlimit,
    const unsigned char key[crypto_spake_DUMMYKEYBYTES])
{
    crypto_generichash_state hst;
    spake_public_data        pd;
    unsigned char            len;

    memset(st, 0, sizeof *st);
    if (client_id_len > 255 || server_id_len > 255) {
        return -1;
    }
    crypto_generichash_init(&hst, key, crypto_spake_DUMMYKEYBYTES,
                            sizeof pd.salt);
    len = (unsigned char) client_id_len;
    crypto_generichash_update(&hst, &len, 1);
    crypto_generichash_update(&hst, (const unsigned char *) client_id, len);
    len = (unsigned char) server_id_len;
    crypto_generichash_update(&hst, &len, 1);
    crypto_generichash_update(&hst, (const unsigned char *) server_id, len);

    pd.alg = crypto_pwhash_alg_default();
    pd.opslimit = opslimit;
    pd.memlimit = memlimit;
    _encode_public_data(public_data, &pd);

    crypto_generichash_update(&hst, public_data,
                              crypto_spake_PUBLICDATABYTES -
                                  crypto_pwhash_SALTBYTES);
    crypto_generichash_final(&hst, pd.salt, sizeof pd.salt);
    _encode_public_data(public_data, &pd);
    sodium_memzero(&pd, sizeof pd);

    return 0;
}

int
crypto_spake_step0(crypto_spake_server_state *st,
                   unsigned char public_data[crypto_spake_PUBLICDATABYTES],
                   const unsigned char stored_data[crypto_spake_STOREDBYTES])
{
    spake_stored_data sd;

    memset(st, 0, sizeof *st);
    if (_decode_stored_data(&sd, stored_data) != 0) {
        return -1;
    }
    _encode_public_data(public_data, &sd.public_data);
    sodium_memzero(&sd, sizeof sd);

    return 0;
}

int
crypto_spake_step1(
    crypto_spake_client_state *st,
    unsigned char              response1[crypto_spake_RESPONSE1BYTES],
    const unsigned char        public_data[crypto_spake_PUBLICDATABYTES],
    const char *const passwd, unsigned long long passwdlen)
{
    spake_keys        keys;
    spake_public_data pd;
    unsigned char     gx[32];
    unsigned char     x[32];
    unsigned char    *X = response1;

    memset(st, 0, sizeof *st);
    if (_decode_public_data(&pd, public_data) != 0) {
        return -1;
    }
    if (_create_keys(&keys, pd.salt, passwd, passwdlen, pd.opslimit,
                     pd.memlimit, pd.alg) != 0) {
        sodium_memzero(st, sizeof *st);
        return -1;
    }
    _random_scalar(x);
    crypto_scalarmult_ed25519_base_noclamp(gx, x);
    if (crypto_core_ed25519_add(X, gx, keys.M) != 0 ||
        !_is_valid_group_element(X)) {
        sodium_memzero(&keys, sizeof keys);
        sodium_memzero(gx, sizeof gx);
        sodium_memzero(x, sizeof x);
        sodium_memzero(&pd, sizeof pd);
        sodium_memzero(st, sizeof *st);
        sodium_memzero(response1, crypto_spake_RESPONSE1BYTES);
        return -1;
    }

    memcpy(st->h_K, keys.h_K, 32);
    memcpy(st->h_L, keys.h_L, 32);
    memcpy(st->N, keys.N, 32);
    memcpy(st->x, x, 32);
    memcpy(st->X, X, 32);

    sodium_memzero(&keys, sizeof keys);
    sodium_memzero(x, sizeof x);
    sodium_memzero(gx, sizeof gx);
    sodium_memzero(&pd, sizeof pd);

    return 0;
}

int
crypto_spake_step2(crypto_spake_server_state *st,
                   unsigned char response2[crypto_spake_RESPONSE2BYTES],
                   const char *client_id, size_t client_id_len,
                   const char *server_id, size_t server_id_len,
                   const unsigned char stored_data[crypto_spake_STOREDBYTES],
                   const unsigned char response1[crypto_spake_RESPONSE1BYTES])
{
    spake_validators    validators;
    spake_stored_data   sd;
    unsigned char       V[32];
    unsigned char       Z[32];
    unsigned char       gx[32];
    unsigned char       gy[32];
    unsigned char       y[32];
    unsigned char      *Y                = response2;
    unsigned char      *client_validator = response2 + 32;
    const unsigned char *X               = response1;

    sodium_memzero(response2, crypto_spake_RESPONSE2BYTES);
    if (_decode_stored_data(&sd, stored_data) != 0) {
        return -1;
    }

    _random_scalar(y);
    crypto_scalarmult_ed25519_base_noclamp(gy, y);
    if (crypto_core_ed25519_add(Y, gy, sd.N) != 0 ||
        !_is_valid_group_element(Y) ||
        _masked_share_sub(gx, X, sd.M) != 0 ||
        crypto_scalarmult_ed25519_noclamp(Z, y, gx) != 0 ||
        crypto_scalarmult_ed25519_noclamp(V, y, sd.L) != 0 ||
        _shared_keys_and_validators(&st->shared_keys, &validators, client_id,
                                    client_id_len, server_id, server_id_len, X,
                                    Y, Z, sd.h_K, V) != 0) {
        sodium_memzero(response2, crypto_spake_RESPONSE2BYTES);
        sodium_memzero(st, sizeof *st);
        sodium_memzero(&sd, sizeof sd);
        sodium_memzero(&validators, sizeof validators);
        sodium_memzero(V, sizeof V);
        sodium_memzero(Z, sizeof Z);
        sodium_memzero(gx, sizeof gx);
        sodium_memzero(y, sizeof y);
        sodium_memzero(gy, sizeof gy);
        return -1;
    }
    memcpy(client_validator, validators.client_validator, 32);
    memcpy(st->server_validator, validators.server_validator, 32);

    sodium_memzero(&validators, sizeof validators);
    sodium_memzero(&sd, sizeof sd);
    sodium_memzero(V, sizeof V);
    sodium_memzero(Z, sizeof Z);
    sodium_memzero(gx, sizeof gx);
    sodium_memzero(y, sizeof y);
    sodium_memzero(gy, sizeof gy);

    return 0;
}

/* C -> S */

int
crypto_spake_step3(crypto_spake_client_state *st,
                   unsigned char response3[crypto_spake_RESPONSE3BYTES],
                   crypto_spake_shared_keys *shared_keys, const char *client_id,
                   size_t client_id_len, const char *server_id,
                   size_t              server_id_len,
                   const unsigned char response2[crypto_spake_RESPONSE2BYTES])
{
    spake_validators    validators;
    unsigned char       V[32];
    unsigned char       Z[32];
    unsigned char       gy[32];
    unsigned char      *server_validator = response3;
    const unsigned char *Y               = response2;
    const unsigned char *client_validator = response2 + 32;

    sodium_memzero(response3, crypto_spake_RESPONSE3BYTES);
    if (_masked_share_sub(gy, Y, st->N) != 0 ||
        crypto_scalarmult_ed25519_noclamp(Z, st->x, gy) != 0 ||
        crypto_scalarmult_ed25519(V, st->h_L, gy) != 0 ||
        _shared_keys_and_validators(shared_keys, &validators, client_id,
                                    client_id_len, server_id, server_id_len,
                                    st->X, Y, Z, st->h_K, V) != 0 ||
        sodium_memcmp(client_validator, validators.client_validator, 32) != 0) {
        sodium_memzero(shared_keys, sizeof *shared_keys);
        sodium_memzero(st, sizeof *st);
        return -1;
    }
    memcpy(server_validator, validators.server_validator, 32);

    sodium_memzero(&validators, sizeof validators);
    sodium_memzero(V, sizeof V);
    sodium_memzero(Z, sizeof Z);
    sodium_memzero(gy, sizeof gy);
    sodium_memzero(st, sizeof *st);

    return 0;
}

int
crypto_spake_step4(crypto_spake_server_state *st,
                   crypto_spake_shared_keys  *shared_keys,
                   const unsigned char response3[crypto_spake_RESPONSE3BYTES])
{
    const unsigned char *server_validator = response3;

    if (sodium_memcmp(server_validator, st->server_validator, 32) != 0) {
        sodium_memzero(shared_keys, sizeof *shared_keys);
        sodium_memzero(st, sizeof *st);
        return -1;
    }
    memcpy(shared_keys, &st->shared_keys, sizeof *shared_keys);
    sodium_memzero(st, sizeof *st);

    return 0;
}
