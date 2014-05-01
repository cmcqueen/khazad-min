
#include "khazad-matrix-mul.h"
#include "khazad-mul2.h"

#include <string.h>

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

void khazad_matrix_mul(uint8_t p_output[KHAZAD_BLOCK_SIZE], const uint8_t p_input[KHAZAD_BLOCK_SIZE])
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

void khazad_matrix_imul(uint8_t p_block[KHAZAD_BLOCK_SIZE])
{
    uint8_t     temp_output[KHAZAD_BLOCK_SIZE];

    khazad_matrix_mul(temp_output, p_block);
    memcpy(p_block, temp_output, KHAZAD_BLOCK_SIZE);
}

