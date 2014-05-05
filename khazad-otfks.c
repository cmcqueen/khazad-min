
#include "khazad.h"
#include "khazad-otfks.h"
#include "khazad-add-block.h"
#include "khazad-sbox.h"

#include <string.h>


static inline void round_func(uint8_t p_block[KHAZAD_BLOCK_SIZE], const uint8_t p_key_schedule_block[KHAZAD_BLOCK_SIZE])
{
    khazad_sbox_apply_block(p_block);
    khazad_matrix_imul(p_block);
    add_block(p_block, p_key_schedule_block);
}

static inline void key_schedule_round_func(uint8_t p_block[KHAZAD_BLOCK_SIZE], uint_fast8_t round)
{
    khazad_sbox_apply_block(p_block);
    khazad_matrix_imul(p_block);
    khazad_sbox_add_round_const(p_block, round);
}


void khazad_otfks_encrypt(uint8_t p_block[KHAZAD_BLOCK_SIZE], uint8_t p_encrypt_start_key[KHAZAD_KEY_SIZE])
{
    uint_fast8_t    round;
    uint8_t       * p_key_schedule = p_encrypt_start_key + KHAZAD_BLOCK_SIZE;
    uint8_t       * p_key_schedule_m1 = p_encrypt_start_key;
    uint8_t       * p_key_schedule_temp;
    uint8_t         key_temp[KHAZAD_BLOCK_SIZE];

    add_block(p_block, p_key_schedule_m1);
    for (round = 0; round < (KHAZAD_NUM_ROUNDS - 1u); ++round)
    {
        round_func(p_block, p_key_schedule);
        p_key_schedule += KHAZAD_BLOCK_SIZE;
    }
    khazad_sbox_apply_block(p_block);
    add_block(p_block, p_key_schedule);
}

void khazad_otfks_decrypt(uint8_t p_block[KHAZAD_BLOCK_SIZE], uint8_t p_decrypt_start_key[KHAZAD_KEY_SIZE])
{

}

void khazad_otfks_encrypt_start_key(uint8_t p_key[KHAZAD_KEY_SIZE])
{
    uint8_t         key_temp[KHAZAD_BLOCK_SIZE];

    /* Initially, p_key is round -2 key schedule, and
     * p_key + KHAZAD_BLOCK_SIZE is round -1 key schedule. */

    /* Round 0. r = 0. */
    /* Get round -1 key schedule (r-1) and apply round function. */
    memcpy(key_temp, p_key + KHAZAD_BLOCK_SIZE, KHAZAD_BLOCK_SIZE);
    key_schedule_round_func(key_temp, 0);
    /* Add round -2 key schedule (r-2), overwriting it. This becomes round 0 key schedule. */
    add_block(p_key, key_temp);

    /* Round 1. r = 1. */
    /* Get round 0 key schedule (r-1) and apply round function. */
    memcpy(key_temp, p_key, KHAZAD_BLOCK_SIZE);
    key_schedule_round_func(key_temp, 1u);
    /* Add round -1 key schedule (r-2), overwriting it. This becomes round 1 key schedule. */
    add_block(p_key + KHAZAD_BLOCK_SIZE, key_temp);

    /* Now, p_key is round 0 key schedule, and
     * p_key + KHAZAD_BLOCK_SIZE is round 1 key schedule. */
}

void khazad_otfks_decrypt_start_key(uint8_t p_key[KHAZAD_KEY_SIZE])
{

}
