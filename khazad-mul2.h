/*****************************************************************************
 * khazad-mul2.h
 *
 * khazad_mul2() multiplies by 2 in Galois field GF(2^8) with reduction
 * polynomial 0x11D.
 *
 * Several implementations are available. Depending on the architecture, one
 * might be preferable in terms of
 *     - Speed.
 *     - Lack of timing variability. That is, to prevent timing attacks, the
 *       execution speed ideally should be the same regardless of whether the
 *       most-significant bit is set or clear (which determines whether the
 *       reduction polynomial is XORed into the result). It is necessary to
 *       inspect the compiled code on the target platform to determine this.
 ****************************************************************************/

#ifndef KHAZAD_MUL2_H
#define KHAZAD_MUL2_H

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include <stdint.h>

/*****************************************************************************
 * Defines
 ****************************************************************************/

#define KHAZAD_REDUCE_BYTE      0x1Du

/*****************************************************************************
 * Functions
 ****************************************************************************/

#if 0

/* This is probably the most straight-forward expression of the algorithm.
 * This seems more likely to have variable timing, although inspection
 * of compiled code would be needed to confirm it.
 * It is more likely to have variable timing when no optimisations are
 * enabled. */
static inline uint8_t khazad_mul2(uint8_t a)
{
    uint8_t result;

    result = a << 1u;
    if (a & 0x80u)
        result ^= KHAZAD_REDUCE_BYTE;
    return result;
}

#elif 0

/* This hopefully has fixed timing, although inspection
 * of compiled code would be needed to confirm it. */
static inline uint8_t khazad_mul2(uint8_t a)
{
    static const uint8_t reduce[2] = { 0, KHAZAD_REDUCE_BYTE };

    return (a << 1u) ^ reduce[a >= 0x80u];
}

#else

/* This hopefully has fixed timing, although inspection
 * of compiled code would be needed to confirm it. */
static inline uint8_t khazad_mul2(uint8_t a)
{
    return (a << 1u) ^ ((-(a >= 0x80u)) & KHAZAD_REDUCE_BYTE);
}

#endif

#endif /* !defined(KHAZAD_MUL2_H) */

