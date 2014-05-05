
#include "khazad.h"
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

static void decrypt_round_func(uint8_t p_block[KHAZAD_BLOCK_SIZE], const uint8_t p_key_schedule_block[KHAZAD_BLOCK_SIZE])
{
    add_block(p_block, p_key_schedule_block);
    khazad_matrix_imul(p_block);
    khazad_sbox_apply_block(p_block);
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
    khazad_sbox_apply_block(p_block);
    add_block(p_block, p_key_schedule);
}

/* This decrypt function uses the regular key schedule created by
 * khazad_key_schedule().
 *
 * An alternative way to decrypt is to use khazad_crypt() with a special
 * decryption key schedule created by khazad_decrypt_key_schedule().
 *
 * These two alternative methods of decryption are possible because of Khazad's
 * involutional design.
 *
 * In practice, it's probably more convenient to have a single key
 * schedule and separate encrypt/decrypt functions, rather than a single
 * crypt function with separate encrypt/decrypt key schedules.
 */
void khazad_decrypt(uint8_t p_block[KHAZAD_BLOCK_SIZE], const uint8_t p_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE])
{
    uint_fast8_t    round;

    p_key_schedule += KHAZAD_KEY_SCHEDULE_SIZE - KHAZAD_BLOCK_SIZE;
    add_block(p_block, p_key_schedule);
    khazad_sbox_apply_block(p_block);
    p_key_schedule -= KHAZAD_BLOCK_SIZE;
    for (round = 0; round < (KHAZAD_NUM_ROUNDS - 1u); ++round)
    {
        decrypt_round_func(p_block, p_key_schedule);
        p_key_schedule -= KHAZAD_BLOCK_SIZE;
    }
    add_block(p_block, p_key_schedule);
}

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

/* This function creates a special decryption key schedule which can be
 * used with khazad_crypt() to do decryption.
 *
 * An alternative way to decrypt is to use khazad_decrypt() with the regular
 * key schedule created by key_schedule().
 *
 * These two alternative methods of decryption are possible because of Khazad's
 * involutional design.
 *
 * In practice, it's probably more convenient to have a single key
 * schedule and separate encrypt/decrypt functions, rather than a single
 * crypt function with separate encrypt/decrypt key schedules.
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

