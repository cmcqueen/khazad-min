/*****************************************************************************
 * khazad-otfks-decrypt.c
 *
 * Khazad functions with on-the-fly key schedule calculations.
 * These functions don't require the full pre-calculated key schedule, thus
 * reducing memory requirements, at the expense of greater execution time.
 * These functions could be useful for a small microprocessor-based system
 * with limited ROM/RAM memory, such as a smartcard.
 ****************************************************************************/

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include "khazad.h"
#include "khazad-otfks.h"
#include "khazad-round-funcs.h"
#include "khazad-add-block.h"
#include "khazad-sbox.h"

#include <string.h>

/*****************************************************************************
 * Functions
 ****************************************************************************/

/* Khazad decryption with on-the-fly key schedule calculation.
 *
 * p_block points to a 16-byte buffer of encrypted data to decrypt. Decryption
 * is done in-place in that buffer.
 * p_decrypt_start_key must initially point to a starting key state for
 * decryption, which must be calculated from the Khazad key, by the function
 * khazad_otfks_decrypt_start_key(). Key schedule is calculated on-the-fly in
 * that buffer, so the buffer must re-initialised for subsequent encryption
 * operations.
 */
void khazad_otfks_decrypt(uint8_t p_block[KHAZAD_BLOCK_SIZE], uint8_t p_decrypt_start_key[KHAZAD_KEY_SIZE])
{
    uint_fast8_t    round;
    uint8_t       * p_key_schedule = p_decrypt_start_key + KHAZAD_BLOCK_SIZE;
    uint8_t       * p_key_schedule_m1 = p_decrypt_start_key;
    uint8_t       * p_key_schedule_temp;
    uint8_t         key_temp[KHAZAD_BLOCK_SIZE];

    add_block(p_block, p_key_schedule_m1);
    khazad_sbox_apply_block(p_block);
    for (round = KHAZAD_NUM_ROUNDS; ; --round)
    {
        /* Do round function */
        decrypt_round_func(p_block, p_key_schedule);

        /* Get round r-1 key schedule and apply round function. */
        memcpy(key_temp, p_key_schedule, KHAZAD_BLOCK_SIZE);
        key_schedule_round_func(key_temp, round);
        /* Add round r key schedule, overwriting it. This becomes round r-2 key schedule. */
        add_block(p_key_schedule_m1, key_temp);

        if (round <= 2)
            break;

        /* Swap key schedule pointers. */
        p_key_schedule_temp = p_key_schedule_m1;
        p_key_schedule_m1 = p_key_schedule;
        p_key_schedule = p_key_schedule_temp;
    }
    add_block(p_block, p_key_schedule_m1);
}
