/*****************************************************************************
 * khazad-min.c
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

#include "khazad-min.h"

#include <string.h>

/*****************************************************************************
 * Defines
 ****************************************************************************/

#define KHAZAD_REDUCE_BYTE      0x1Du

/*****************************************************************************
 * Look-up tables
 ****************************************************************************/

#ifdef ENABLE_SBOX_SMALL

static const uint8_t sbox_small_table[16u] =
{
    0x39, 0xFE, 0xE5, 0x06, 0x5A, 0x42, 0xB3, 0xCC, 0xDF, 0xA0, 0x94, 0x6D, 0x77, 0x8B, 0x21, 0x18
};

#else /* ENABLE_SBOX_SMALL */

static const uint8_t khazad_sbox_table[256u] =
{
    0xBA, 0x54, 0x2F, 0x74, 0x53, 0xD3, 0xD2, 0x4D, 0x50, 0xAC, 0x8D, 0xBF, 0x70, 0x52, 0x9A, 0x4C,
    0xEA, 0xD5, 0x97, 0xD1, 0x33, 0x51, 0x5B, 0xA6, 0xDE, 0x48, 0xA8, 0x99, 0xDB, 0x32, 0xB7, 0xFC,
    0xE3, 0x9E, 0x91, 0x9B, 0xE2, 0xBB, 0x41, 0x6E, 0xA5, 0xCB, 0x6B, 0x95, 0xA1, 0xF3, 0xB1, 0x02,
    0xCC, 0xC4, 0x1D, 0x14, 0xC3, 0x63, 0xDA, 0x5D, 0x5F, 0xDC, 0x7D, 0xCD, 0x7F, 0x5A, 0x6C, 0x5C,
    0xF7, 0x26, 0xFF, 0xED, 0xE8, 0x9D, 0x6F, 0x8E, 0x19, 0xA0, 0xF0, 0x89, 0x0F, 0x07, 0xAF, 0xFB,
    0x08, 0x15, 0x0D, 0x04, 0x01, 0x64, 0xDF, 0x76, 0x79, 0xDD, 0x3D, 0x16, 0x3F, 0x37, 0x6D, 0x38,
    0xB9, 0x73, 0xE9, 0x35, 0x55, 0x71, 0x7B, 0x8C, 0x72, 0x88, 0xF6, 0x2A, 0x3E, 0x5E, 0x27, 0x46,
    0x0C, 0x65, 0x68, 0x61, 0x03, 0xC1, 0x57, 0xD6, 0xD9, 0x58, 0xD8, 0x66, 0xD7, 0x3A, 0xC8, 0x3C,
    0xFA, 0x96, 0xA7, 0x98, 0xEC, 0xB8, 0xC7, 0xAE, 0x69, 0x4B, 0xAB, 0xA9, 0x67, 0x0A, 0x47, 0xF2,
    0xB5, 0x22, 0xE5, 0xEE, 0xBE, 0x2B, 0x81, 0x12, 0x83, 0x1B, 0x0E, 0x23, 0xF5, 0x45, 0x21, 0xCE,
    0x49, 0x2C, 0xF9, 0xE6, 0xB6, 0x28, 0x17, 0x82, 0x1A, 0x8B, 0xFE, 0x8A, 0x09, 0xC9, 0x87, 0x4E,
    0xE1, 0x2E, 0xE4, 0xE0, 0xEB, 0x90, 0xA4, 0x1E, 0x85, 0x60, 0x00, 0x25, 0xF4, 0xF1, 0x94, 0x0B,
    0xE7, 0x75, 0xEF, 0x34, 0x31, 0xD4, 0xD0, 0x86, 0x7E, 0xAD, 0xFD, 0x29, 0x30, 0x3B, 0x9F, 0xF8,
    0xC6, 0x13, 0x06, 0x05, 0xC5, 0x11, 0x77, 0x7C, 0x7A, 0x78, 0x36, 0x1C, 0x39, 0x59, 0x18, 0x56,
    0xB3, 0xB0, 0x24, 0x20, 0xB2, 0x92, 0xA3, 0xC0, 0x44, 0x62, 0x10, 0xB4, 0x84, 0x43, 0x93, 0xC2,
    0x4A, 0xBD, 0x8F, 0x2D, 0xBC, 0x9C, 0x6A, 0x40, 0xCF, 0xA2, 0x80, 0x4F, 0x1F, 0xCA, 0xAA, 0x42
};

#endif /* ENABLE_SBOX_SMALL */

/*****************************************************************************
 * Local function prototypes
 ****************************************************************************/

static void khazad_otfks_calc_key(uint8_t p_key[KHAZAD_KEY_SIZE], uint_fast8_t start, uint_fast8_t stop);
#ifdef ENABLE_SBOX_SMALL
static uint8_t khazad_sbox(uint8_t input);
#endif
static void khazad_sbox_apply_block(uint8_t p_block[KHAZAD_BLOCK_SIZE]);
static void khazad_sbox_add_round_const(uint8_t p_block[KHAZAD_BLOCK_SIZE], uint_fast8_t round);
static void khazad_matrix_mul(uint8_t p_output[KHAZAD_BLOCK_SIZE], const uint8_t p_input[KHAZAD_BLOCK_SIZE]);
static void khazad_matrix_imul(uint8_t p_block[KHAZAD_BLOCK_SIZE]);

/*****************************************************************************
 * Inline functions
 ****************************************************************************/

#if 0

/* This is probably the most straight-forward expression of the algorithm.
 * This seems more likely to have variable timing, although inspection
 * of compiled code would be needed to confirm it.
 * It is more likely to have variable timing when no optimisations are
 * enabled. */
static inline uint8_t khazad_mul2(uint8_t a)
{
    uint8_t result;

    result = a << 1u;
    if (a & 0x80u)
        result ^= KHAZAD_REDUCE_BYTE;
    return result;
}

#elif 0

/* This hopefully has fixed timing, although inspection
 * of compiled code would be needed to confirm it. */
static inline uint8_t khazad_mul2(uint8_t a)
{
    static const uint8_t reduce[2] = { 0, KHAZAD_REDUCE_BYTE };

    return (a << 1u) ^ reduce[a >= 0x80u];
}

#else

/* This hopefully has fixed timing, although inspection
 * of compiled code would be needed to confirm it. */
static inline uint8_t khazad_mul2(uint8_t a)
{
    return (a << 1u) ^ ((-(a >= 0x80u)) & KHAZAD_REDUCE_BYTE);
}

#endif

#ifndef ENABLE_SBOX_SMALL

static inline uint8_t khazad_sbox(uint8_t a)
{
    return khazad_sbox_table[a];
}

#endif

static inline void round_func(uint8_t p_block[KHAZAD_BLOCK_SIZE], const uint8_t p_key_schedule_block[KHAZAD_BLOCK_SIZE])
{
    khazad_sbox_apply_block(p_block);
    khazad_matrix_imul(p_block);
    khazad_add_block(p_block, p_key_schedule_block);
}

static inline void key_schedule_round_func(uint8_t p_block[KHAZAD_BLOCK_SIZE], uint_fast8_t round)
{
    khazad_sbox_apply_block(p_block);
    khazad_matrix_imul(p_block);
    khazad_sbox_add_round_const(p_block, round);
}

static inline void decrypt_round_func(uint8_t p_block[KHAZAD_BLOCK_SIZE], const uint8_t p_key_schedule_block[KHAZAD_BLOCK_SIZE])
{
    khazad_add_block(p_block, p_key_schedule_block);
    khazad_matrix_imul(p_block);
    khazad_sbox_apply_block(p_block);
}

/*****************************************************************************
 * Functions
 ****************************************************************************/

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

    khazad_add_block(p_block, p_key_schedule);
    p_key_schedule += KHAZAD_BLOCK_SIZE;
    for (round = 0; round < (KHAZAD_NUM_ROUNDS - 1u); ++round)
    {
        round_func(p_block, p_key_schedule);
        p_key_schedule += KHAZAD_BLOCK_SIZE;
    }
    khazad_sbox_apply_block(p_block);
    khazad_add_block(p_block, p_key_schedule);
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
    khazad_add_block(p_block, p_key_schedule);
    khazad_sbox_apply_block(p_block);
    p_key_schedule -= KHAZAD_BLOCK_SIZE;
    for (round = 0; round < (KHAZAD_NUM_ROUNDS - 1u); ++round)
    {
        decrypt_round_func(p_block, p_key_schedule);
        p_key_schedule -= KHAZAD_BLOCK_SIZE;
    }
    khazad_add_block(p_block, p_key_schedule);
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
        khazad_add_block(p_key_0, p_key_m2);

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

/* Calculate the starting key state needed for encryption with on-the-fly key
 * schedule calculation. The starting encryption key state is the first 16
 * bytes of the Khazad key schedule, which is not the Khazad key itself but two
 * key schedule rounds applied to the Khazad key.
 * The encryption start key calculation is done in-place in the buffer p_key[].
 * So p_key points to a 16-byte buffer containing the Khazad key. On exit, it
 * contains the encryption start key state suitable for khazad_otfks_encrypt().
 */
void khazad_otfks_encrypt_start_key(uint8_t p_key[KHAZAD_KEY_SIZE])
{
    khazad_otfks_calc_key(p_key, 0, 1u);
}

/* Calculate the starting key state needed for decryption with on-the-fly key
 * schedule calculation. The starting decryption key state is the last 16 bytes
 * of the Khazad key schedule.
 * The decryption start key calculation is done in-place in the buffer p_key[].
 * So p_key points to a 16-byte buffer containing the Khazad key. On exit, it
 * contains the decryption start key state suitable for khazad_otfks_decrypt().
 */
void khazad_otfks_decrypt_start_key(uint8_t p_key[KHAZAD_KEY_SIZE])
{
    khazad_otfks_calc_key(p_key, 0, KHAZAD_NUM_ROUNDS);
}

/* This calculates the decryption start key, but unlike
 * khazad_otfks_decrypt_start_key(), it calculates it from the encryption start
 * key rather than the original Khazad key.
 */
void khazad_otfks_decrypt_from_encrypt_start_key(uint8_t p_key[KHAZAD_KEY_SIZE])
{
    khazad_otfks_calc_key(p_key, 2u, KHAZAD_NUM_ROUNDS);
}

/* Khazad encryption with on-the-fly key schedule calculation.
 *
 * p_block points to a 16-byte buffer of plain data to encrypt. Encryption
 * is done in-place in that buffer.
 * p_encrypt_start_key must initially point to a starting key state for
 * encryption, which must be calculated from the Khazad key, by the function
 * khazad_otfks_encrypt_start_key(). Key schedule is calculated on-the-fly in
 * that buffer, so the buffer must re-initialised for subsequent encryption
 * operations.
 */
void khazad_otfks_encrypt(uint8_t p_block[KHAZAD_BLOCK_SIZE], uint8_t p_encrypt_start_key[KHAZAD_KEY_SIZE])
{
    uint_fast8_t    round;
    uint8_t       * p_key_schedule = p_encrypt_start_key + KHAZAD_BLOCK_SIZE;
    uint8_t       * p_key_schedule_m1 = p_encrypt_start_key;
    uint8_t       * p_key_schedule_temp;
    uint8_t         key_temp[KHAZAD_BLOCK_SIZE];

    khazad_add_block(p_block, p_key_schedule_m1);
    for (round = 2; ; ++round)
    {
        /* Do round function for round r-2 */
        round_func(p_block, p_key_schedule);

        /* Get round r-1 key schedule and apply round function. */
        memcpy(key_temp, p_key_schedule, KHAZAD_BLOCK_SIZE);
        key_schedule_round_func(key_temp, round);
        /* Add round r-2 key schedule, overwriting it. This becomes round r key schedule. */
        khazad_add_block(p_key_schedule_m1, key_temp);

        if (round >= KHAZAD_NUM_ROUNDS)
            break;

        /* Swap key schedule pointers. */
        p_key_schedule_temp = p_key_schedule_m1;
        p_key_schedule_m1 = p_key_schedule;
        p_key_schedule = p_key_schedule_temp;
    }
    khazad_sbox_apply_block(p_block);
    khazad_add_block(p_block, p_key_schedule_m1);
}

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

    khazad_add_block(p_block, p_key_schedule_m1);
    khazad_sbox_apply_block(p_block);
    for (round = KHAZAD_NUM_ROUNDS; ; --round)
    {
        /* Do round function */
        decrypt_round_func(p_block, p_key_schedule);

        /* Get round r-1 key schedule and apply round function. */
        memcpy(key_temp, p_key_schedule, KHAZAD_BLOCK_SIZE);
        key_schedule_round_func(key_temp, round);
        /* Add round r key schedule, overwriting it. This becomes round r-2 key schedule. */
        khazad_add_block(p_key_schedule_m1, key_temp);

        if (round <= 2)
            break;

        /* Swap key schedule pointers. */
        p_key_schedule_temp = p_key_schedule_m1;
        p_key_schedule_m1 = p_key_schedule;
        p_key_schedule = p_key_schedule_temp;
    }
    khazad_add_block(p_block, p_key_schedule_m1);
}

void _khazad_sbox_apply_block_for_test(uint8_t p_block[KHAZAD_BLOCK_SIZE])
{
    khazad_sbox_apply_block(p_block);
}

/*****************************************************************************
 * Local functions
 ****************************************************************************/

/* Do a number of rounds of on-the-fly key schedule calculation, for round
 * numbers 'start' through 'stop' inclusive. */
static void khazad_otfks_calc_key(uint8_t p_key[KHAZAD_KEY_SIZE], uint_fast8_t start, uint_fast8_t stop)
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
        khazad_add_block(p_key_schedule_m1, key_temp);

        if (round >= stop)
            break;

        /* Swap key schedule pointers. */
        p_key_schedule_temp = p_key_schedule_m1;
        p_key_schedule_m1 = p_key_schedule;
        p_key_schedule = p_key_schedule_temp;
    }
}

#ifdef ENABLE_SBOX_SMALL

#if 1

static uint8_t khazad_sbox(uint8_t input)
{
    uint8_t         work;
    uint_fast8_t    i;

    work = input;

    for (i = 0; ; i++)
    {
        if (i == 1)
        {
            // Swap nibbles
            // Hopefully the compiler converts this to a single rotate instruction
            work = (work << 4u) | (work >> 4u);
        }
        work = (sbox_small_table[work >> 4u] & 0xF0) |  // P box
               (sbox_small_table[work & 0xF] & 0xF);    // Q box
        if (i == 1)
        {
            // Swap nibbles
            // Hopefully the compiler converts this to a single rotate instruction
            work = (work << 4u) | (work >> 4u);
        }

        if (i > 1)
        {
            return work;
        }

        work = (work & 0xC3) | ((work & 0x30) >> 2u) | ((work & 0xC) << 2u);
    }
}

#elif 0

static uint8_t khazad_sbox(uint8_t input)
{
    uint8_t         work[2];    // work[1] is high nibble; work[0] is low nibble
    uint8_t         temp;
    uint_fast8_t    i;

    work[1] = input >> 4u;
    work[0] = input & 0xFu;

    for (i = 0; ; i++)
    {
        work[i != 1] = sbox_small_table[work[i != 1]] >> 4u;      // P box
        work[i == 1] = sbox_small_table[work[i == 1]] & 0xFu;     // Q box

        if (i > 1)
        {
            return (work[1] << 4u) | work[0];
        }

        temp = work[1];
        work[1] = (temp & 0xC) | (work[0] >> 2u);
        work[0] = ((temp << 2u ) & 0xC) | (work[0] & 3);
    }
}

#else

static uint8_t khazad_sbox(uint8_t input)
{
    uint8_t         work_hi;    // high nibble
    uint8_t         work_lo;    // low nibble
    uint8_t         temp;
    uint_fast8_t    i;

    work_hi = input >> 4u;
    work_lo = input & 0xFu;

    for (i = 0; ; i++)
    {
#if 0
        if (i != 1)
        {
            work_hi = sbox_small_table[work_hi] >> 4u;      // P box
            work_lo = sbox_small_table[work_lo] & 0xFu;     // Q box
        }
        else
        {
            work_lo = sbox_small_table[work_lo] >> 4u;      // P box
            work_hi = sbox_small_table[work_hi] & 0xFu;     // Q box
        }
#elif 0
        if (i == 1)
        {
            // Swap nibbles
            temp = work_hi;
            work_hi = work_lo;
            work_lo = temp;
        }
        work_hi = sbox_small_table[work_hi] >> 4u;      // P box
        work_lo = sbox_small_table[work_lo] & 0xFu;     // Q box
        if (i == 1)
        {
            // Swap nibbles
            temp = work_hi;
            work_hi = work_lo;
            work_lo = temp;
        }
#else
        if (i == 1)
        {
            work_lo ^= work_hi;
            work_hi ^= work_lo;
            work_lo ^= work_hi;
        }
        work_hi = sbox_small_table[work_hi] >> 4u;      // P box
        work_lo = sbox_small_table[work_lo] & 0xFu;     // Q box
        if (i == 1)
        {
            work_lo ^= work_hi;
            work_hi ^= work_lo;
            work_lo ^= work_hi;
        }
#endif

        if (i > 1)
        {
            return (work_hi << 4u) | work_lo;
        }

        temp = work_hi;
        work_hi = (temp & 0xC) | (work_lo >> 2u);
        work_lo = ((temp << 2u ) & 0xC) | (work_lo & 3);
    }
}

#endif

#endif /* ENABLE_SBOX_SMALL */

static void khazad_sbox_apply_block(uint8_t p_block[KHAZAD_BLOCK_SIZE])
{
    uint_fast8_t    i;

    for (i = 0; i < KHAZAD_BLOCK_SIZE; ++i)
    {
        p_block[i] = khazad_sbox(p_block[i]);
    }
}

#if ENABLE_SBOX_SMALL

void khazad_sbox_add_round_const(uint8_t p_block[KHAZAD_BLOCK_SIZE], uint_fast8_t round)
{
    uint_fast8_t    i;
    uint_fast8_t    round_start = round * KHAZAD_BLOCK_SIZE;

    for (i = 0; i < KHAZAD_BLOCK_SIZE; ++i)
    {
        p_block[i] ^= khazad_sbox(round_start + i);
    }
}

#else /* ENABLE_SBOX_SMALL */

static void khazad_sbox_add_round_const(uint8_t p_block[KHAZAD_BLOCK_SIZE], uint_fast8_t round)
{
    khazad_add_block(p_block, &khazad_sbox_table[round * KHAZAD_BLOCK_SIZE]);
}

#endif /* ENABLE_SBOX_SMALL */

/*
 * 1  0001
 * 3  0011
 * 4  0100
 * 5  0101
 * 6  0110
 * 8  1000
 * B  1011
 * 7  0111
 *
 * # 1
 * output 0
 * save mul1
 *
 * # 4
 * shift
 * save mul2
 * shift
 * save mul4
 * output 2
 *
 * # 6
 * xor mul2
 * output 4
 *
 * # 7
 * xor mul1
 * output 7
 *
 * # 5
 * get mul4
 * xor mul1
 * output 3
 *
 * # 8
 * get mul4
 * shift
 * output 5
 * save mul8
 *
 * # 3
 * get mul2
 * xor mul1
 * output 1
 *
 * # B
 * xor mul8
 * output 6
 */
static void khazad_matrix_mul(uint8_t p_output[KHAZAD_BLOCK_SIZE], const uint8_t p_input[KHAZAD_BLOCK_SIZE])
{
    uint_fast8_t    i;
    uint8_t         val1;
    uint8_t         val2;
    uint8_t         val4;
    uint8_t         val8;

    memset(p_output, 0, KHAZAD_BLOCK_SIZE);

    for (i = 0; i < KHAZAD_BLOCK_SIZE; ++i)
    {
        /* # 1
         * save mul1
         * output 0
         */
        val1 = p_input[i];
        p_output[i] ^= val1;

        /* # 4
         * shift
         * save mul2
         * shift
         * save mul4
         * output 2
         */
        val2 = khazad_mul2(val1);
        val4 = khazad_mul2(val2);
        p_output[i ^ 2] ^= val4;

        {
            uint8_t val6;

            /* # 6
             * xor mul2
             * output 4
             */
            val6 = val4 ^ val2;
            p_output[i ^ 4] ^= val6;

            /* # 7
             * xor mul1
             * output 7
             */
            p_output[i ^ 7] ^= val6 ^ val1;
        }

        /* # 5
         * get mul4
         * xor mul1
         * output 3
         */
        p_output[i ^ 3] ^= val4 ^ val1;

        /* # 8
         * get mul4
         * shift
         * save mul8
         * output 5
         */
        val8 = khazad_mul2(val4);
        p_output[i ^ 5] ^= val8;

        {
            uint8_t val3;

            /* # 3
             * get mul2
             * xor mul1
             * output 1
             */
            val3 = val2 ^ val1;
            p_output[i ^ 1] ^= val3;

            /* # B
             * xor mul8
             * output 6
             */
            p_output[i ^ 6] ^= val8 ^ val3;
        }
    }
}

static void khazad_matrix_imul(uint8_t p_block[KHAZAD_BLOCK_SIZE])
{
    uint8_t     temp_output[KHAZAD_BLOCK_SIZE];

    khazad_matrix_mul(temp_output, p_block);
    memcpy(p_block, temp_output, KHAZAD_BLOCK_SIZE);
}
