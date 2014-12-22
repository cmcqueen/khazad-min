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
#include "khazad-add-block.h"
#include "khazad-matrix-mul.h"
#include "khazad-sbox.h"

#include <string.h>

/*****************************************************************************
 * Functions
 ****************************************************************************/

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

/* Khazad encryption and decryption.
 * p_block points to a 16-byte buffer of data to encrypt/decrypt. Encryption/
 * decryption is done in-place in that buffer.
 * p_key_schedule points to the full calculated key schedule. If the key
 * schedule was calculated with khazad_key_schedule(), then encryption is done.
 * If the key schedule was calculated with khazad_decrypt_key_schedule(), then
 * decryption is done.
 */
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

