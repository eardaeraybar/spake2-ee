#include <assert.h>
#include <sodium.h>
#include <stdio.h>
#include <string.h>

#include "crypto_spake.h"

/* A client identifier (username, email address, public key...) */
#define CLIENT_ID "client"

/* A server identifier (IP address, host name, public key...) */
#define SERVER_ID "server"

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

    return 0;
}
