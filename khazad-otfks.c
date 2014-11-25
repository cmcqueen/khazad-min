
#include "khazad.h"
#include "khazad-otfks.h"
#include "khazad-add-block.h"
#include "khazad-matrix-mul.h"
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

static inline void decrypt_round_func(uint8_t p_block[KHAZAD_BLOCK_SIZE], const uint8_t p_key_schedule_block[KHAZAD_BLOCK_SIZE])
{
    add_block(p_block, p_key_schedule_block);
    khazad_matrix_imul(p_block);
    khazad_sbox_apply_block(p_block);
}

static inline void key_schedule_decrypt_round_func(uint8_t p_block[KHAZAD_BLOCK_SIZE], uint_fast8_t round)
{
    khazad_sbox_add_round_const(p_block, round);
    khazad_matrix_imul(p_block);
    khazad_sbox_apply_block(p_block);
}


void khazad_otfks_encrypt(uint8_t p_block[KHAZAD_BLOCK_SIZE], uint8_t p_encrypt_start_key[KHAZAD_KEY_SIZE])
{
    uint_fast8_t    round;
    uint8_t       * p_key_schedule = p_encrypt_start_key + KHAZAD_BLOCK_SIZE;
    uint8_t       * p_key_schedule_m1 = p_encrypt_start_key;
    uint8_t       * p_key_schedule_temp;
    uint8_t         key_temp[KHAZAD_BLOCK_SIZE];

    add_block(p_block, p_key_schedule_m1);
    for (round = 2; ; ++round)
    {
        /* Do round function for round r-2 */
        round_func(p_block, p_key_schedule);

        /* Get round r-1 key schedule and apply round function. */
        memcpy(key_temp, p_key_schedule, KHAZAD_BLOCK_SIZE);
        key_schedule_round_func(key_temp, round);
        /* Add round r-2 key schedule, overwriting it. This becomes round r key schedule. */
        add_block(p_key_schedule_m1, key_temp);

        if (round >= KHAZAD_NUM_ROUNDS)
            break;

        /* Swap key schedule pointers. */
        p_key_schedule_temp = p_key_schedule_m1;
        p_key_schedule_m1 = p_key_schedule;
        p_key_schedule = p_key_schedule_temp;
    }
    khazad_sbox_apply_block(p_block);
    add_block(p_block, p_key_schedule_m1);
}

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

static void khazad_otfks_decrypt_calc_key(uint8_t p_key[KHAZAD_KEY_SIZE], uint_fast8_t start, uint_fast8_t stop)
{
    uint_fast8_t    round;
    uint8_t       * p_key_schedule = p_key + KHAZAD_BLOCK_SIZE;
    uint8_t       * p_key_schedule_m1 = p_key;
    uint8_t       * p_key_schedule_temp;
    uint8_t         key_temp[KHAZAD_BLOCK_SIZE];

    for (round = start; ; ++round)
    {
        /* Get round r-1 key schedule and apply round function. */
        memcpy(key_temp, p_key_schedule, KHAZAD_BLOCK_SIZE);
        key_schedule_round_func(key_temp, round);
        /* Add round r-2 key schedule, overwriting it. This becomes round r key schedule. */
        add_block(p_key_schedule_m1, key_temp);

        if (round >= stop)
            break;

        /* Swap key schedule pointers. */
        p_key_schedule_temp = p_key_schedule_m1;
        p_key_schedule_m1 = p_key_schedule;
        p_key_schedule = p_key_schedule_temp;
    }
}

void khazad_otfks_encrypt_start_key(uint8_t p_key[KHAZAD_KEY_SIZE])
{
    khazad_otfks_decrypt_calc_key(p_key, 0, 1u);
}

void khazad_otfks_decrypt_start_key(uint8_t p_key[KHAZAD_KEY_SIZE])
{
    khazad_otfks_decrypt_calc_key(p_key, 0, KHAZAD_NUM_ROUNDS);
}

void khazad_otfks_decrypt_from_encrypt_start_key(uint8_t p_key[KHAZAD_KEY_SIZE])
{
    khazad_otfks_decrypt_calc_key(p_key, 2u, KHAZAD_NUM_ROUNDS);
}
