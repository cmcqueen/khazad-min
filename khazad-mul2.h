
#ifndef KHAZAD_MUL2_H
#define KHAZAD_MUL2_H

#include <stdint.h>

static inline uint8_t khazad_mul2(uint8_t a)
{
    static const uint8_t reduce[2] = { 0, 0x1D };

    return (a << 1u) ^ reduce[a >= 0x80];
}

#endif /* !defined(KHAZAD_MUL2_H) */

