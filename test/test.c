#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <time.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

#include "crypto_spake.h"

/* A client identifier (username, email address, public key...) */
#define CLIENT_ID "client"

/* A server identifier (IP address, host name, public key...) */
#define SERVER_ID "server"

#define RANDOMIZED_ITERATIONS 128

typedef struct handshake_vector_ {
    const char *name;
    const char *description;
    const char *password;
    const char *client_id;
    const char *server_id;
} handshake_vector;

typedef struct telemetry_ {
    uint64_t iterations;
    uint64_t success_count;
    uint64_t client_reject_count;
    uint64_t server_reject_count;
    uint64_t total_ns;
    uint64_t min_ns;
    uint64_t max_ns;
} telemetry;

static uint64_t
now_monotonic_ns(void)
{
    struct timespec ts;

    assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
    return ((uint64_t) ts.tv_sec * 1000000000ULL) + (uint64_t) ts.tv_nsec;
}

static void
random_ascii_string(char *out, size_t len)
{
    static const char alphabet[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";
    size_t i;

    assert(len > 0U);
    for (i = 0; i + 1U < len; i++) {
        out[i] = alphabet[randombytes_uniform((uint32_t) (sizeof alphabet - 1U))];
    }
    out[len - 1U] = 0;
}

static void
print_hex_prefix(const char *label, const unsigned char *buf, size_t len)
{
    char hex[33];
    size_t prefix_len = len < 16U ? len : 16U;

    sodium_bin2hex(hex, sizeof hex, buf, prefix_len);
    printf("%s%s\n", label, hex);
}

static void
print_rule(void)
{
    printf("------------------------------------------------------------\n");
}

static void
print_section_title(const char *title)
{
    print_rule();
    printf("%s\n", title);
    print_rule();
}

static void
print_vector_result(const handshake_vector *vector, uint64_t elapsed_ns,
                    const crypto_spake_shared_keys *shared_keys)
{
    printf("Case: %s\n", vector->name);
    printf("  Purpose           : %s\n", vector->description);
    printf("  Password length   : %zu\n", strlen(vector->password));
    printf("  Client ID length  : %zu\n", strlen(vector->client_id));
    printf("  Server ID length  : %zu\n", strlen(vector->server_id));
    printf("  Result            : success\n");
    printf("  Handshake time    : %.3f us\n", (double) elapsed_ns / 1000.0);
    print_hex_prefix("  Client key prefix : ", shared_keys->client_sk,
                     sizeof shared_keys->client_sk);
    print_hex_prefix("  Server key prefix : ", shared_keys->server_sk,
                     sizeof shared_keys->server_sk);
}

static void
print_validation_summary(void)
{
    print_section_title("Validation Summary");
    printf("Status: all built-in safety and tamper checks passed.\n");
    printf("Included checks:\n");
    printf("  - baseline success path\n");
    printf("  - wrong password rejection\n");
    printf("  - tampered public data rejection\n");
    printf("  - tampered response1 rejection\n");
    printf("  - tampered response2 rejection\n");
    printf("  - tampered response3 rejection\n");
    printf("  - corrupted stored data rejection\n");
    printf("  - deterministic dummy public-data generation\n");
}

static void
prepare_server(unsigned char stored_data[crypto_spake_STOREDBYTES],
               unsigned char public_data[crypto_spake_PUBLICDATABYTES],
               crypto_spake_server_state *server_st, const char *password,
               unsigned long long password_len)
{
    int ret = crypto_spake_server_store(stored_data, password, password_len,
                                        crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                        crypto_pwhash_MEMLIMIT_INTERACTIVE);

    assert(ret == 0);
    ret = crypto_spake_step0(server_st, public_data, stored_data);
    assert(ret == 0);
}

static void
run_success_case(void)
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

    prepare_server(stored_data, public_data, &server_st, "password", 8);
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
}

static void
run_vector_case(const handshake_vector *vector)
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
    uint64_t                  started_ns;
    uint64_t                  elapsed_ns;
    int                       ret;

    started_ns = now_monotonic_ns();
    prepare_server(stored_data, public_data, &server_st, vector->password,
                   (unsigned long long) strlen(vector->password));
    ret = crypto_spake_step1(&client_st, response1, public_data, vector->password,
                             (unsigned long long) strlen(vector->password));
    assert(ret == 0);
    ret = crypto_spake_step2(&server_st, response2, vector->client_id,
                             strlen(vector->client_id), vector->server_id,
                             strlen(vector->server_id), stored_data, response1);
    assert(ret == 0);
    ret = crypto_spake_step3(&client_st, response3, &shared_keys_from_server,
                             vector->client_id, strlen(vector->client_id),
                             vector->server_id, strlen(vector->server_id),
                             response2);
    assert(ret == 0);
    ret = crypto_spake_step4(&server_st, &shared_keys_from_client, response3);
    assert(ret == 0);
    assert(memcmp(&shared_keys_from_client, &shared_keys_from_server,
                  sizeof shared_keys_from_client) == 0);
    elapsed_ns = now_monotonic_ns() - started_ns;
    print_vector_result(vector, elapsed_ns, &shared_keys_from_client);
}

static void
run_all_vector_cases(void)
{
    static const handshake_vector vectors[] = {
        { "baseline", "Default reference values", "password", "client", "server" },
        { "short", "Shortest practical ASCII inputs", "a", "c", "s" },
        { "mixed_alnum", "Typical mixed alphanumeric identifiers", "P4ssw0rd2026", "device-01", "gateway-01" },
        { "symbols_ascii", "ASCII punctuation inside the password", "A1!b2@C3#d4$", "client.alpha", "server.beta" },
        { "long_password",
          "Long password stress case",
          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "client-long-identity-0001",
          "server-long-identity-0001" },
        { "max_len_ids",
          "Near-maximum identifier lengths supported by the protocol",
          "VectorPassword42",
          "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
          "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
          "ddd",
          "1111111111111111111111111111111111111111111111111111111111111111"
          "2222222222222222222222222222222222222222222222222222222222222222"
          "3333333333333333333333333333333333333333333333333333333333333333"
          "444" },
        { "numeric", "Numeric-only credentials and identities", "3141592653589793", "123456", "654321" },
        { "case_sensitive", "Checks case-sensitive handling", "Password", "ClientA", "ServerA" }
    };
    size_t i;

    print_section_title("Deterministic Test Vectors");
    for (i = 0; i < (sizeof vectors / sizeof vectors[0]); i++) {
        run_vector_case(&vectors[i]);
        if (i + 1U < (sizeof vectors / sizeof vectors[0])) {
            print_rule();
        }
    }
}

static void
run_wrong_password_case(void)
{
    unsigned char             stored_data[crypto_spake_STOREDBYTES];
    unsigned char             public_data[crypto_spake_PUBLICDATABYTES];
    unsigned char             response1[crypto_spake_RESPONSE1BYTES];
    unsigned char             response2[crypto_spake_RESPONSE2BYTES];
    unsigned char             response3[crypto_spake_RESPONSE3BYTES];
    crypto_spake_client_state client_st;
    crypto_spake_server_state server_st;
    crypto_spake_shared_keys  shared_keys;
    int                       ret;

    prepare_server(stored_data, public_data, &server_st, "password", 8);
    ret = crypto_spake_step1(&client_st, response1, public_data, "passw0rd", 8);
    assert(ret == 0);
    ret = crypto_spake_step2(&server_st, response2, CLIENT_ID,
                             sizeof CLIENT_ID - 1, SERVER_ID,
                             sizeof SERVER_ID - 1, stored_data, response1);
    assert(ret == 0);

    memset(&shared_keys, 0xa5, sizeof shared_keys);
    ret = crypto_spake_step3(&client_st, response3, &shared_keys, CLIENT_ID,
                             sizeof CLIENT_ID - 1, SERVER_ID,
                             sizeof SERVER_ID - 1, response2);
    assert(ret == -1);
    assert(sodium_is_zero((const unsigned char *) &shared_keys,
                          sizeof shared_keys) == 1);
}

static void
run_tampered_public_data_case(void)
{
    unsigned char             stored_data[crypto_spake_STOREDBYTES];
    unsigned char             public_data[crypto_spake_PUBLICDATABYTES];
    unsigned char             tampered[crypto_spake_PUBLICDATABYTES];
    unsigned char             response1[crypto_spake_RESPONSE1BYTES];
    crypto_spake_client_state client_st;
    crypto_spake_server_state server_st;
    int                       ret;

    prepare_server(stored_data, public_data, &server_st, "password", 8);
    memcpy(tampered, public_data, sizeof tampered);
    tampered[0] ^= 0x01;

    ret = crypto_spake_validate_public_data(
        tampered, crypto_pwhash_alg_default(),
        crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE);
    assert(ret == -1);
    ret = crypto_spake_step1(&client_st, response1, tampered, "password", 8);
    assert(ret == -1);
}

static void
run_tampered_response1_case(void)
{
    unsigned char             stored_data[crypto_spake_STOREDBYTES];
    unsigned char             public_data[crypto_spake_PUBLICDATABYTES];
    unsigned char             response1[crypto_spake_RESPONSE1BYTES];
    unsigned char             response2[crypto_spake_RESPONSE2BYTES];
    crypto_spake_client_state client_st;
    crypto_spake_server_state server_st;
    int                       ret;

    prepare_server(stored_data, public_data, &server_st, "password", 8);
    ret = crypto_spake_step1(&client_st, response1, public_data, "password", 8);
    assert(ret == 0);

    memset(response1, 0, sizeof response1);
    ret = crypto_spake_step2(&server_st, response2, CLIENT_ID,
                             sizeof CLIENT_ID - 1, SERVER_ID,
                             sizeof SERVER_ID - 1, stored_data, response1);
    assert(ret == -1);
    assert(sodium_is_zero(response2, sizeof response2) == 1);
}

static void
run_tampered_response2_case(void)
{
    unsigned char             stored_data[crypto_spake_STOREDBYTES];
    unsigned char             public_data[crypto_spake_PUBLICDATABYTES];
    unsigned char             response1[crypto_spake_RESPONSE1BYTES];
    unsigned char             response2[crypto_spake_RESPONSE2BYTES];
    unsigned char             response3[crypto_spake_RESPONSE3BYTES];
    crypto_spake_client_state client_st;
    crypto_spake_server_state server_st;
    crypto_spake_shared_keys  shared_keys;
    int                       ret;

    prepare_server(stored_data, public_data, &server_st, "password", 8);
    ret = crypto_spake_step1(&client_st, response1, public_data, "password", 8);
    assert(ret == 0);
    ret = crypto_spake_step2(&server_st, response2, CLIENT_ID,
                             sizeof CLIENT_ID - 1, SERVER_ID,
                             sizeof SERVER_ID - 1, stored_data, response1);
    assert(ret == 0);

    memset(response2, 0, 32);
    memset(&shared_keys, 0x5a, sizeof shared_keys);
    ret = crypto_spake_step3(&client_st, response3, &shared_keys, CLIENT_ID,
                             sizeof CLIENT_ID - 1, SERVER_ID,
                             sizeof SERVER_ID - 1, response2);
    assert(ret == -1);
    assert(sodium_is_zero(response3, sizeof response3) == 1);
    assert(sodium_is_zero((const unsigned char *) &shared_keys,
                          sizeof shared_keys) == 1);
}

static void
run_tampered_response3_case(void)
{
    unsigned char             stored_data[crypto_spake_STOREDBYTES];
    unsigned char             public_data[crypto_spake_PUBLICDATABYTES];
    unsigned char             response1[crypto_spake_RESPONSE1BYTES];
    unsigned char             response2[crypto_spake_RESPONSE2BYTES];
    unsigned char             response3[crypto_spake_RESPONSE3BYTES];
    crypto_spake_client_state client_st;
    crypto_spake_server_state server_st;
    crypto_spake_shared_keys  shared_keys;
    int                       ret;

    prepare_server(stored_data, public_data, &server_st, "password", 8);
    ret = crypto_spake_step1(&client_st, response1, public_data, "password", 8);
    assert(ret == 0);
    ret = crypto_spake_step2(&server_st, response2, CLIENT_ID,
                             sizeof CLIENT_ID - 1, SERVER_ID,
                             sizeof SERVER_ID - 1, stored_data, response1);
    assert(ret == 0);
    ret = crypto_spake_step3(&client_st, response3, &shared_keys, CLIENT_ID,
                             sizeof CLIENT_ID - 1, SERVER_ID,
                             sizeof SERVER_ID - 1, response2);
    assert(ret == 0);

    response3[0] ^= 0x01;
    ret = crypto_spake_step4(&server_st, &shared_keys, response3);
    assert(ret == -1);
}

static void
run_tampered_stored_data_case(void)
{
    unsigned char             stored_data[crypto_spake_STOREDBYTES];
    unsigned char             public_data[crypto_spake_PUBLICDATABYTES];
    unsigned char             response1[crypto_spake_RESPONSE1BYTES];
    unsigned char             response2[crypto_spake_RESPONSE2BYTES];
    crypto_spake_client_state client_st;
    crypto_spake_server_state server_st;
    int                       ret;

    prepare_server(stored_data, public_data, &server_st, "password", 8);
    memset(&stored_data[36], 0, 32);
    ret = crypto_spake_step0(&server_st, public_data, stored_data);
    assert(ret == -1);

    prepare_server(stored_data, public_data, &server_st, "password", 8);
    ret = crypto_spake_step1(&client_st, response1, public_data, "password", 8);
    assert(ret == 0);
    memset(&stored_data[132], 0, 32);
    ret = crypto_spake_step2(&server_st, response2, CLIENT_ID,
                             sizeof CLIENT_ID - 1, SERVER_ID,
                             sizeof SERVER_ID - 1, stored_data, response1);
    assert(ret == -1);
}

static void
run_dummy_public_data_case(void)
{
    unsigned char             public_data1[crypto_spake_PUBLICDATABYTES];
    unsigned char             public_data2[crypto_spake_PUBLICDATABYTES];
    crypto_spake_server_state server_st;
    unsigned char             key[crypto_spake_DUMMYKEYBYTES];
    int                       ret;

    memset(key, 0x42, sizeof key);
    ret = crypto_spake_step0_dummy(&server_st, public_data1, CLIENT_ID,
                                   sizeof CLIENT_ID - 1, SERVER_ID,
                                   sizeof SERVER_ID - 1,
                                   crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                   crypto_pwhash_MEMLIMIT_INTERACTIVE, key);
    assert(ret == 0);
    ret = crypto_spake_step0_dummy(&server_st, public_data2, CLIENT_ID,
                                   sizeof CLIENT_ID - 1, SERVER_ID,
                                   sizeof SERVER_ID - 1,
                                   crypto_pwhash_OPSLIMIT_INTERACTIVE,
                                   crypto_pwhash_MEMLIMIT_INTERACTIVE, key);
    assert(ret == 0);
    assert(memcmp(public_data1, public_data2, sizeof public_data1) == 0);
}

static void
run_randomized_telemetry_case(void)
{
    telemetry                 stats;
    unsigned char             stored_data[crypto_spake_STOREDBYTES];
    unsigned char             public_data[crypto_spake_PUBLICDATABYTES];
    unsigned char             response1[crypto_spake_RESPONSE1BYTES];
    unsigned char             response2[crypto_spake_RESPONSE2BYTES];
    unsigned char             response3[crypto_spake_RESPONSE3BYTES];
    crypto_spake_client_state client_st;
    crypto_spake_server_state server_st;
    crypto_spake_shared_keys  shared_keys_from_client;
    crypto_spake_shared_keys  shared_keys_from_server;
    char                      password[25];
    char                      wrong_password[25];
    char                      client_id[33];
    char                      server_id[33];
    unsigned int              wrong_password_iterations = 0U;
    uint64_t                  started_ns;
    uint64_t                  elapsed_ns;
    size_t                    i;
    int                       ret;

    memset(&stats, 0, sizeof stats);
    stats.min_ns = UINT64_MAX;

    for (i = 0; i < RANDOMIZED_ITERATIONS; i++) {
        random_ascii_string(password, sizeof password);
        memcpy(wrong_password, password, sizeof password);
        wrong_password[0] = wrong_password[0] == 'Z' ? 'Y' : 'Z';
        random_ascii_string(client_id, sizeof client_id);
        random_ascii_string(server_id, sizeof server_id);

        started_ns = now_monotonic_ns();
        prepare_server(stored_data, public_data, &server_st, password,
                       (unsigned long long) strlen(password));
        ret = crypto_spake_step1(&client_st, response1, public_data, password,
                                 (unsigned long long) strlen(password));
        assert(ret == 0);
        ret = crypto_spake_step2(&server_st, response2, client_id,
                                 strlen(client_id), server_id,
                                 strlen(server_id), stored_data, response1);
        assert(ret == 0);
        ret = crypto_spake_step3(&client_st, response3, &shared_keys_from_server,
                                 client_id, strlen(client_id), server_id,
                                 strlen(server_id), response2);
        assert(ret == 0);
        ret = crypto_spake_step4(&server_st, &shared_keys_from_client, response3);
        assert(ret == 0);
        assert(memcmp(&shared_keys_from_client, &shared_keys_from_server,
                      sizeof shared_keys_from_client) == 0);
        elapsed_ns = now_monotonic_ns() - started_ns;

        stats.iterations++;
        stats.success_count++;
        stats.total_ns += elapsed_ns;
        if (elapsed_ns < stats.min_ns) {
            stats.min_ns = elapsed_ns;
        }
        if (elapsed_ns > stats.max_ns) {
            stats.max_ns = elapsed_ns;
        }

        if ((i % 8U) == 0U) {
            wrong_password_iterations++;
            prepare_server(stored_data, public_data, &server_st, password,
                           (unsigned long long) strlen(password));
            ret = crypto_spake_step1(&client_st, response1, public_data,
                                     wrong_password,
                                     (unsigned long long) strlen(wrong_password));
            assert(ret == 0);
            ret = crypto_spake_step2(&server_st, response2, client_id,
                                     strlen(client_id), server_id,
                                     strlen(server_id), stored_data, response1);
            assert(ret == 0);
            ret = crypto_spake_step3(&client_st, response3, &shared_keys_from_server,
                                     client_id, strlen(client_id), server_id,
                                     strlen(server_id), response2);
            assert(ret == -1);
            stats.client_reject_count++;
        }
    }

    print_section_title("Randomized Telemetry");
    printf("Iterations run        : %" PRIu64 "\n", stats.iterations);
    printf("Successful handshakes : %" PRIu64 "\n", stats.success_count);
    printf("Client-side rejects   : %" PRIu64 "\n", stats.client_reject_count);
    printf("Server-side rejects   : %" PRIu64 "\n", stats.server_reject_count);
    printf("Wrong-password tests  : %u\n", wrong_password_iterations);
    printf("Total runtime         : %.3f ms\n",
           (double) stats.total_ns / 1000000.0);
    printf("Average handshake     : %.3f us\n",
           stats.iterations == 0 ? 0.0
                                 : (double) stats.total_ns /
                                       (double) stats.iterations / 1000.0);
    printf("Fastest handshake     : %.3f us\n", (double) stats.min_ns / 1000.0);
    printf("Slowest handshake     : %.3f us\n", (double) stats.max_ns / 1000.0);
    print_hex_prefix("Sample client key     : ", shared_keys_from_client.client_sk,
                     sizeof shared_keys_from_client.client_sk);
    print_hex_prefix("Sample server key     : ", shared_keys_from_client.server_sk,
                     sizeof shared_keys_from_client.server_sk);
}

int
main(void)
{
    if (sodium_init() != 0) {
        return 1;
    }

    run_success_case();
    run_wrong_password_case();
    run_tampered_public_data_case();
    run_tampered_response1_case();
    run_tampered_response2_case();
    run_tampered_response3_case();
    run_tampered_stored_data_case();
    run_dummy_public_data_case();
    print_validation_summary();
    run_all_vector_cases();
    run_randomized_telemetry_case();

    return 0;
}
