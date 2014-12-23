/*****************************************************************************
 * khazad-round-funcs.h
 *
 * Khazad round functions for encryption and decryption.
 ****************************************************************************/

#ifndef KHAZAD_ROUND_FUNCS_H
#define KHAZAD_ROUND_FUNCS_H

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include "khazad.h"
#include "khazad-add-block.h"
#include "khazad-matrix-mul.h"
#include "khazad-sbox.h"

/*****************************************************************************
 * Inline functions
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

static inline void decrypt_round_func(uint8_t p_block[KHAZAD_BLOCK_SIZE], const uint8_t p_key_schedule_block[KHAZAD_BLOCK_SIZE])
{
    add_block(p_block, p_key_schedule_block);
    khazad_matrix_imul(p_block);
    khazad_sbox_apply_block(p_block);
}

#endif /* !defined(KHAZAD_ROUND_FUNCS_H) */
