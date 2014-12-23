/*****************************************************************************
 * khazad.c
 *
 * Khazad functions for encryption and decryption, and key schedule
 * calculations for encryption and decryption.
 *
 * Khazad is an involutional cipher, so encryption and decryption have the
 * same structure. One function can be used for both encryption and
 * decryption, with just a different key schedule.
 * However, the function for calculating the decryption key schedule still uses
 * program space. Having different key schedules for encryption and decryption
 * uses up more memory, which may be limited in a small microprocessor system.
 * So, a separate decryption function is also provided which uses the same
 * key schedule as for encryption.
 * So for decryption, the two choices are:
 *     - Use khazad_key_schedule() to create a key schedule that can be used
 *       for both encryption and decryption. Decrypt using the
 *       khazad_decrypt() function.
 *     - Use khazad_decrypt_key_schedule() to create a key schedule
 *       specifically for decryption. Use it with the common khazad_crypt()
 *       function.
 * These two alternative methods of decryption are possible because of Khazad's
 * involutional design.
 * Depending on which method is used, then one function is unused and can be
 * removed from the build.
 ****************************************************************************/

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include "khazad.h"
#include "khazad-matrix-mul.h"

#include <string.h>

/*****************************************************************************
 * Functions
 ****************************************************************************/

/* Calculate full key schedule for Khazad decryption using the common crypt
 * function khazad_crypt().
 * p_key_schedule points to a 72-byte buffer of data to store the key schedule.
 * This key schedule is suitable for use with khazad_crypt() to do decryption.
 */
void khazad_decrypt_key_schedule(uint8_t p_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE], const uint8_t p_key[KHAZAD_KEY_SIZE])
{
    uint_fast8_t    round;
    uint8_t       * p_key_0;
    uint8_t       * p_key_1;
    uint8_t         key_temp[KHAZAD_BLOCK_SIZE];

    khazad_key_schedule(p_key_schedule, p_key);

    /* Reverse order */
    p_key_0 = p_key_schedule;
    p_key_1 = p_key_schedule + KHAZAD_KEY_SCHEDULE_SIZE - KHAZAD_BLOCK_SIZE;
    for (round = 0; round < (KHAZAD_NUM_ROUNDS + 1u) / 2u; ++round)
    {
        memcpy(key_temp, p_key_0, KHAZAD_BLOCK_SIZE);
        memcpy(p_key_0, p_key_1, KHAZAD_BLOCK_SIZE);
        memcpy(p_key_1, key_temp, KHAZAD_BLOCK_SIZE);
        p_key_0 += KHAZAD_BLOCK_SIZE;
        p_key_1 -= KHAZAD_BLOCK_SIZE;
    }

    /* Apply matrix multiply to rounds 1 to r-1. */
    p_key_0 = p_key_schedule + KHAZAD_BLOCK_SIZE;
    for (round = 1; round < KHAZAD_NUM_ROUNDS; ++round)
    {
        khazad_matrix_imul(p_key_0);
        p_key_0 += KHAZAD_BLOCK_SIZE;
    }
}
