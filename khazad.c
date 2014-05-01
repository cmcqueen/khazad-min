
#include "khazad.h"
#include "khazad-add-block.h"
#include "khazad-sbox.h"

#include "khazad-print-block.h"

#include <string.h>


static void apply_sbox(uint8_t p_block[KHAZAD_BLOCK_SIZE])
{
    uint_fast8_t    i;

    for (i = 0; i < KHAZAD_BLOCK_SIZE; ++i)
    {
        p_block[i] = khazad_sbox(p_block[i]);
    }    
}

static round_func(uint8_t p_block[KHAZAD_BLOCK_SIZE], const uint8_t p_key_schedule_block[KHAZAD_BLOCK_SIZE])
{
    apply_sbox(p_block);
    khazad_matrix_imul(p_block);
    add_block(p_block, p_key_schedule_block);
}

static key_schedule_round_func(uint8_t p_block[KHAZAD_BLOCK_SIZE], uint_fast8_t round)
{
    apply_sbox(p_block);
    khazad_matrix_imul(p_block);
    khazad_sbox_add_round_const(p_block, round);
}

void khazad_crypt(uint8_t p_block[KHAZAD_BLOCK_SIZE], const uint8_t p_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE])
{
    uint_fast8_t    round;

    add_block(p_block, p_key_schedule);
    p_key_schedule += KHAZAD_BLOCK_SIZE;
    for (round = 0; round < (KHAZAD_NUM_ROUNDS - 1u); ++round)
    {
        round_func(p_block, p_key_schedule);
        p_key_schedule += KHAZAD_BLOCK_SIZE;
    }
    apply_sbox(p_block);
    add_block(p_block, p_key_schedule);
}

void khazad_encode_key_schedule(uint8_t p_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE], const uint8_t p_key[KHAZAD_KEY_SIZE])
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

