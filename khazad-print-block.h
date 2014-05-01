
#ifndef KHAZAD_PRINT_BLOCK_H
#define KHAZAD_PRINT_BLOCK_H

#include <stdint.h>
#include <stdio.h>


static inline void print_block_hex(uint8_t * p_block, size_t len)
{
    while (len > 1)
    {
        printf("%02X ", *p_block++);
        len--;
    }
    if (len)
    {
        printf("%02X", *p_block);
    }
    printf("\n");
}


#endif /* !defined(KHAZAD_PRINT_BLOCK_H) */

