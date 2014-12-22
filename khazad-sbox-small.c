/*****************************************************************************
 *
 ****************************************************************************/

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include "khazad-sbox.h"

/*****************************************************************************
 * Look-up tables
 ****************************************************************************/

static const uint8_t sbox_small_table[16u] =
{
    0x39, 0xFE, 0xE5, 0x06, 0x5A, 0x42, 0xB3, 0xCC, 0xDF, 0xA0, 0x94, 0x6D, 0x77, 0x8B, 0x21, 0x18
};

/*****************************************************************************
 * Functions
 ****************************************************************************/

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


void khazad_sbox_apply_block(uint8_t p_block[KHAZAD_BLOCK_SIZE])
{
    uint_fast8_t    i;

    for (i = 0; i < KHAZAD_BLOCK_SIZE; ++i)
    {
        p_block[i] = khazad_sbox(p_block[i]);
    }
}

void khazad_sbox_add_round_const(uint8_t p_block[KHAZAD_BLOCK_SIZE], uint_fast8_t round)
{
    uint_fast8_t    i;
    uint_fast8_t    round_start = round * KHAZAD_BLOCK_SIZE;

    for (i = 0; i < KHAZAD_BLOCK_SIZE; ++i)
    {
        p_block[i] ^= khazad_sbox(round_start + i);
    }
}
