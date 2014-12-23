/*****************************************************************************
 * khazad-key-schedule.c
 *
 * Khazad key schedule calculation for encryption (and possibly decryption).
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
#include "khazad-round-funcs.h"
#include "khazad-add-block.h"

#include <string.h>

/*****************************************************************************
 * Functions
 ****************************************************************************/

/* Calculate full key schedule for Khazad encryption (or decryption).
 * p_key_schedule points to a 72-byte buffer of data to store the key schedule.
 * If the key schedule is used with khazad_crypt(), then encryption is done.
 * If the key schedule is used with khazad_decrypt(), then decryption is done.
 */
void khazad_key_schedule(uint8_t p_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE], const uint8_t p_key[KHAZAD_KEY_SIZE])
{
    uint_fast8_t    round;
    uint8_t       * p_key_0 = p_key_schedule;
    const uint8_t * p_key_m2 = p_key;
    const uint8_t * p_key_m1 = p_key + KHAZAD_BLOCK_SIZE;

    for (round = 0; round < (KHAZAD_NUM_ROUNDS + 1u); ++round)
    {
        memcpy(p_key_0, p_key_m1, KHAZAD_BLOCK_SIZE);
        key_schedule_round_func(p_key_0, round);
        add_block(p_key_0, p_key_m2);

        p_key_m2 = p_key_m1;
        p_key_m1 = p_key_0;
        p_key_0 += KHAZAD_BLOCK_SIZE;
    }
}
