
#ifndef KHAZAD_SBOX_H
#define KHAZAD_SBOX_H

#include <stdint.h>

extern const khazad_sbox_table[256u];

static inline uint8_t khazad_sbox(uint8_t a)
{
    return khazad_sbox_table[a];
}

#endif /* !defined(KHAZAD_SBOX_H) */

