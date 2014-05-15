
#include "khazad-sbox.h"


static const uint8_t sbox_small_table[16u] =
{
    0x39, 0xFE, 0xE5, 0x06, 0x5A, 0x42, 0xB3, 0xCC, 0xDF, 0xA0, 0x94, 0x6D, 0x77, 0x8B, 0x21, 0x18
};


static uint8_t khazad_sbox(uint8_t input)
{
    uint8_t     work0hi;
    uint8_t     work0lo;
    uint8_t     work1hi;
    uint8_t     work1lo;

    work0hi = sbox_small_table[input >> 4u];    // relevant output is P box in upper 4 bits
    work0lo = sbox_small_table[input & 0xFu];   // relevant output is Q box in lower 4 bits

    work1hi = sbox_small_table[((work0hi & 0xC0u) >> 4u) | ((work0lo & 0xCu) >> 2u)];   // relevant output is Q box in lower 4 bits
    work1lo = sbox_small_table[((work0hi & 0x30u) >> 2u) | (work0lo & 3u)];             // relevant output is P box in upper 4 bits

    work0hi = sbox_small_table[(work1hi & 0xCu) | ((work1lo & 0xC0u) >> 6u)];           // relevant output is P box in upper 4 bits
    work0lo = sbox_small_table[((work1hi & 3u) << 2u) | ((work1lo & 0x30u) >> 4u)];     // relevant output is Q box in lower 4 bits

    return (work0hi & 0xF0) | (work0lo & 0xF);
}


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

