/*****************************************************************************
 *
 ****************************************************************************/

#ifndef KHAZAD_ADD_BLOCK_H
#define KHAZAD_ADD_BLOCK_H

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include "khazad.h"

#include <stdint.h>

/*****************************************************************************
 * Inline functions
 ****************************************************************************/

static inline void add_block(uint8_t p_block[KHAZAD_BLOCK_SIZE], const uint8_t p_add_block[KHAZAD_BLOCK_SIZE])
{
    uint_fast8_t    i;

    for (i = 0; i < KHAZAD_BLOCK_SIZE; ++i)
    {
        p_block[i] ^= p_add_block[i];
    }    
}

#endif /* !defined(KHAZAD_ADD_BLOCK_H) */
