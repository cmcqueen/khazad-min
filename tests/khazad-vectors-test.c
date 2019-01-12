/*****************************************************************************
 * khazad-vectors-test.c
 *
 * Test Khazad encryption against the published test vectors, provided in the
 * zip file khazad-tweak-test-vectors.zip, containing
 * khazad-tweak-test-vectors.txt.
 ****************************************************************************/

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include "khazad-min.h"
#include "khazad-print-block.h"

#include <string.h>
#include <stdbool.h>

/*****************************************************************************
 * Defines
 ****************************************************************************/

#ifndef dimof
#define dimof(array)    (sizeof(array) / sizeof(array[0]))
#endif

#ifndef ENABLE_LONG_TEST
#define ENABLE_LONG_TEST        0
#endif

/*****************************************************************************
 * Types
 ****************************************************************************/

typedef struct
{
    const uint32_t set_num;
    const uint32_t vector_num;
    const uint8_t * key;
    const uint8_t * plain;
    const uint8_t * cipher;
    const uint8_t * decrypted;
    const uint8_t * iter100;
    const uint8_t * iter1000;
    const uint8_t * iter100000000;
} vector_data_t;

/*****************************************************************************
 * Include generated code
 ****************************************************************************/

#include "khazad-test-vectors.h"    /* Generated by Python parse-vectors.py */

/*****************************************************************************
 * Functions
 ****************************************************************************/

static bool test_khazad_main(const vector_data_t * p_vector_data, bool do_otfks)
{
    size_t  i;
    uint8_t encrypt_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE] = {};
    uint8_t decrypt_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE] = {};
    uint8_t otfks_encrypt_key_start[KHAZAD_KEY_SIZE] = {};
    uint8_t otfks_decrypt_key_start[KHAZAD_KEY_SIZE] = {};
    uint8_t otfks_key_work[KHAZAD_KEY_SIZE] = {};
    uint8_t crypt_block[KHAZAD_BLOCK_SIZE] = {};
    const uint8_t * p_decrypted;

    if (do_otfks)
    {
        /* Start key for encrypt */
        memcpy(otfks_encrypt_key_start, p_vector_data->key, KHAZAD_KEY_SIZE);
        khazad_otfks_encrypt_start_key(otfks_encrypt_key_start);
        /* Start key for decrypt */
#if 1
        memcpy(otfks_decrypt_key_start, p_vector_data->key, KHAZAD_KEY_SIZE);
        khazad_otfks_decrypt_start_key(otfks_decrypt_key_start);
#else
        memcpy(otfks_decrypt_key_start, otfks_encrypt_key_start, KHAZAD_KEY_SIZE);
        khazad_otfks_decrypt_from_encrypt_start_key(otfks_decrypt_key_start);
#endif
    }
    else
    {
        /* Encrypt key schedule */
        khazad_key_schedule(encrypt_key_schedule, p_vector_data->key);
        /* Decrypt key schedule (for the alternative method of decryption) */
        khazad_decrypt_key_schedule(decrypt_key_schedule, p_vector_data->key);
    }

    memcpy(crypt_block, p_vector_data->plain, KHAZAD_BLOCK_SIZE);

    for (i = 0; ; )
    {
        /* Encrypt 1 */
        if (do_otfks)
        {
            memcpy(otfks_key_work, otfks_encrypt_key_start, KHAZAD_KEY_SIZE);
            khazad_otfks_encrypt(crypt_block, otfks_key_work);
        }
        else
        {
            khazad_crypt(crypt_block, encrypt_key_schedule);
        }

        i++;
        if (i == 1u)
        {
            /* Check encrypt 1 */
            if (p_vector_data->cipher &&
                memcmp(crypt_block, p_vector_data->cipher, KHAZAD_BLOCK_SIZE) != 0)
            {
                printf("set %u vector %u encrypt error\n",
                        p_vector_data->set_num, p_vector_data->vector_num);
                return false;
            }
            if (p_vector_data->iter100 == NULL &&
                p_vector_data->iter1000 == NULL &&
                p_vector_data->iter100000000 == NULL)
            {
                break;
            }
        }
        else if (i == 100u)
        {
            /* Check encrypt 100 */
            if (p_vector_data->iter100 &&
                memcmp(crypt_block, p_vector_data->iter100, KHAZAD_BLOCK_SIZE) != 0)
            {
                printf("set %u vector %u encrypt 100 error\n",
                        p_vector_data->set_num, p_vector_data->vector_num);
                return false;
            }
            if (p_vector_data->iter1000 == NULL &&
                p_vector_data->iter100000000 == NULL)
            {
                break;
            }
        }
        else if (i == 1000u)
        {
            /* Check encrypt 1000 */
            if (p_vector_data->iter1000 &&
                memcmp(crypt_block, p_vector_data->iter1000, KHAZAD_BLOCK_SIZE) != 0)
            {
                printf("set %u vector %u encrypt 1000 error\n",
                        p_vector_data->set_num, p_vector_data->vector_num);
                return false;
            }
            if (p_vector_data->iter100000000 == NULL)
            {
                break;
            }

            /* Skip 10^8 test */
            break;
        }
        else if (i == 100000000u)
        {
            /* Check encrypt 100000000 */
            if (p_vector_data->iter100000000 &&
                memcmp(crypt_block, p_vector_data->iter100000000, KHAZAD_BLOCK_SIZE) != 0)
            {
                printf("set %u vector %u encrypt 100000000 error\n",
                        p_vector_data->set_num, p_vector_data->vector_num);
                return false;
            }
            break;
        }
    }

    for (;;)
    {
        /* Decrypt back to plain */
        if (do_otfks)
        {
            memcpy(otfks_key_work, otfks_decrypt_key_start, KHAZAD_KEY_SIZE);
            khazad_otfks_decrypt(crypt_block, otfks_key_work);
        }
        else
        {
            khazad_decrypt(crypt_block, encrypt_key_schedule);
        }

        i--;

        /* Check decrypt */
        if (i == 1000u && p_vector_data->iter1000)
        {
            if (memcmp(crypt_block, p_vector_data->iter1000, KHAZAD_BLOCK_SIZE) != 0)
            {
                printf("set %u vector %u decrypt 1000 error\n",
                        p_vector_data->set_num, p_vector_data->vector_num);
                return false;
            }
        }
        else if (i == 100u && p_vector_data->iter100)
        {
            if (memcmp(crypt_block, p_vector_data->iter100, KHAZAD_BLOCK_SIZE) != 0)
            {
                printf("set %u vector %u decrypt 100 error\n",
                        p_vector_data->set_num, p_vector_data->vector_num);
                return false;
            }
        }
        else if (i == 0)
        {
            if (p_vector_data->decrypted)
                p_decrypted = p_vector_data->decrypted;
            else
                p_decrypted = p_vector_data->plain;
            if (memcmp(crypt_block, p_decrypted, KHAZAD_BLOCK_SIZE) != 0)
            {
                printf("set %u vector %u decrypt error\n",
                        p_vector_data->set_num, p_vector_data->vector_num);
                return false;
            }
            break;
        }
    }

    return true;
}

static bool test_khazad_100000000(const vector_data_t * p_vector_data, bool do_otfks)
{
    size_t  i;
    uint8_t encrypt_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE] = {};
    uint8_t encrypt_key[KHAZAD_KEY_SIZE] = {};
    uint8_t otfks_encrypt_key_start[KHAZAD_KEY_SIZE] = {};
    uint8_t otfks_key_work[KHAZAD_KEY_SIZE] = {};
    uint8_t crypt_block[KHAZAD_BLOCK_SIZE] = {};

    /* Set up initial key schedule */
    if (do_otfks)
    {
        /* Start key for encrypt */
        memcpy(otfks_encrypt_key_start, p_vector_data->key, KHAZAD_KEY_SIZE);
        khazad_otfks_encrypt_start_key(otfks_encrypt_key_start);
    }
    else
    {
        /* Encrypt key schedule */
        khazad_key_schedule(encrypt_key_schedule, p_vector_data->key);
    }

    memcpy(crypt_block, p_vector_data->plain, KHAZAD_BLOCK_SIZE);

    for (i = 0; ; )
    {
        /* Encrypt 1 */
        if (do_otfks)
        {
            memcpy(otfks_key_work, otfks_encrypt_key_start, KHAZAD_KEY_SIZE);
            khazad_otfks_encrypt(crypt_block, otfks_key_work);
        }
        else
        {
            khazad_crypt(crypt_block, encrypt_key_schedule);
        }

        /* Set up next key schedule for next encryption key.
         * Next encryption key is repeats of last byte from last encryption round. */
        if (do_otfks)
        {
            /* Start key for encrypt */
            memset(otfks_encrypt_key_start, crypt_block[KHAZAD_BLOCK_SIZE-1], KHAZAD_KEY_SIZE);
            khazad_otfks_encrypt_start_key(otfks_encrypt_key_start);
        }
        else
        {
            /* Encrypt key schedule */
            memset(encrypt_key, crypt_block[KHAZAD_BLOCK_SIZE-1], KHAZAD_KEY_SIZE);
            khazad_key_schedule(encrypt_key_schedule, encrypt_key);
        }

        i++;

        if (i == 100000000u)
        {
            /* Check encrypt 100000000 */
            if (p_vector_data->iter100000000 &&
                memcmp(crypt_block, p_vector_data->iter100000000, KHAZAD_BLOCK_SIZE) != 0)
            {
                printf("set %u vector %u encrypt 10^8 error\n",
                        p_vector_data->set_num, p_vector_data->vector_num);
                return false;
            }
            break;
        }
    }

    return true;
}

static bool test_khazad(const vector_data_t * p_vector_data, bool do_otfks)
{
    if (p_vector_data->iter100000000 == NULL)
    {
        /* Main tests. */
        return test_khazad_main(p_vector_data, do_otfks);
    }
    else
    {
#if ENABLE_LONG_TEST
        /* Different test for 10^8 iterations. */
        return test_khazad_100000000(p_vector_data, do_otfks);
#else
        /* Skip 10^8 iterations test, since it's long. */
        printf("set %u vector %u %s%sskipped\n",
                p_vector_data->set_num, p_vector_data->vector_num,
                p_vector_data->iter100000000 ? "10^8 " : "",
                do_otfks ? "(OTFKS) " : "");
        return true;
#endif
    }
}

int main(int argc, char **argv)
{
    size_t  i;
    bool    is_okay;
    bool    do_otfks;

    (void)argc;
    (void)argv;

    for (i = 0; i < dimof(test_vectors); ++i)
    {
        /* Do each test twice, once with pre-calculated key schedule, then
         * again with on-the-fly key schedule calculation. */
        do_otfks = false;
        for (;;)
        {
            /* Using pre-calculated key schedule */
            is_okay = test_khazad(test_vectors[i], do_otfks);
            if (is_okay == false ||
                ENABLE_LONG_TEST && test_vectors[i]->iter100000000)
            {
                printf("set %u vector %u %s%s%s\n",
                        test_vectors[i]->set_num, test_vectors[i]->vector_num,
                        test_vectors[i]->iter100000000 ? "10^8 " : "",
                        do_otfks ? "(OTFKS) " : "",
                        is_okay ? "succeeded" : "failed");
            }
            if (!is_okay)
            {
                return 1;
            }
            if (do_otfks == false)
                do_otfks = true;
            else
                break;
        }
    }
    return 0;
}
