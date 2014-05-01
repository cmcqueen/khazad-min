
#ifndef KHAZAD_MATRIX_MUL_H
#define KHAZAD_MATRIX_MUL_H

#include "khazad.h"

#include <stdint.h>

void khazad_matrix_mul(uint8_t p_output[KHAZAD_BLOCK_SIZE], const uint8_t p_input[KHAZAD_BLOCK_SIZE]);
void khazad_matrix_imul(uint8_t p_block[KHAZAD_BLOCK_SIZE]);

#endif /* !defined(KHAZAD_MATRIX_MUL_H) */

