/*****************************************************************************
 *
 ****************************************************************************/

#ifndef KHAZAD_SBOX_H
#define KHAZAD_SBOX_H

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include "khazad.h"

#include <stdint.h>

/*****************************************************************************
 * Function prototypes
 ****************************************************************************/

void khazad_sbox_apply_block(uint8_t p_block[KHAZAD_BLOCK_SIZE]);
void khazad_sbox_add_round_const(uint8_t p_block[KHAZAD_BLOCK_SIZE], uint_fast8_t round);

#endif /* !defined(KHAZAD_SBOX_H) */
