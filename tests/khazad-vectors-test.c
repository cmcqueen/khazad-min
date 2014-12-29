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

#include "khazad.h"
#include "khazad-otfks.h"
#include "khazad-print-block.h"

#include <string.h>
#include <stdbool.h>

/*****************************************************************************
 * Defines
 ****************************************************************************/

#ifndef dimof
#define dimof(array)    (sizeof(array) / sizeof(array[0]))
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

bool test_khazad(const vector_data_t * p_vector_data)
{
    size_t  i;
    uint8_t encrypt_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE];
    uint8_t decrypt_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE];
    uint8_t otfks_encrypt_key_start[KHAZAD_KEY_SIZE];
    uint8_t otfks_decrypt_key_start[KHAZAD_KEY_SIZE];
    uint8_t otfks_key_work[KHAZAD_KEY_SIZE];
    uint8_t crypt_block[KHAZAD_BLOCK_SIZE];
    const uint8_t * p_decrypted;

    khazad_key_schedule(encrypt_key_schedule, p_vector_data->key);

    khazad_decrypt_key_schedule(decrypt_key_schedule, p_vector_data->key);

    /* Encrypt 1 */
    memcpy(crypt_block, p_vector_data->plain, KHAZAD_BLOCK_SIZE);
    khazad_crypt(crypt_block, encrypt_key_schedule);
    if (p_vector_data->cipher &&
        memcmp(crypt_block, p_vector_data->cipher, KHAZAD_BLOCK_SIZE) != 0)
    {
        printf("set %u vector %u encrypt error\n", p_vector_data->set_num, p_vector_data->vector_num);
        return false;
    }

    /* Decrypt from 1 back to plain */
    if (p_vector_data->decrypted)
        p_decrypted = p_vector_data->decrypted;
    else
        p_decrypted = p_vector_data->plain;
    khazad_decrypt(crypt_block, encrypt_key_schedule);
    if (memcmp(crypt_block, p_decrypted, KHAZAD_BLOCK_SIZE) != 0)
    {
        printf("set %u vector %u decrypt error\n", p_vector_data->set_num, p_vector_data->vector_num);
        return false;
    }

    return true;
}

int main(int argc, char **argv)
{
    size_t  i;
    bool    is_okay;

    for (i = 0; i < dimof(test_vectors); ++i)
    {
        is_okay = test_khazad(test_vectors[i]);
        if (!is_okay)
        {
            return 1;
        }
    }
    return 0;
}