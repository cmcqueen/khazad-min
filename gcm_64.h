/*****************************************************************************
 * gcm_64.h
 *
 * Functions to support GCM mode.
 ****************************************************************************/

#ifndef GCM_64_H
#define GCM_64_H

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include <stdint.h>

/*****************************************************************************
 * Defines
 ****************************************************************************/

#define GCM_64_BLOCK_SIZE           8u
#define GCM_U64_ELEMENT_SIZE        sizeof(gcm_u64_element_t)
#define GCM_U64_NUM_ELEMENTS        (GCM_64_BLOCK_SIZE / GCM_U64_ELEMENT_SIZE)

/*****************************************************************************
 * Types
 ****************************************************************************/

/* Set an element type that is efficient on the target platform.
 * Ensure GCM_U64_ELEMENT_SIZE is suitably set to match.
 * unsigned int is a reasonable default, but it could be uint16_t, uint8_t.
 * If uint8_t is used, gcm_u64_struct_from_bytes() etc could simply be
 * replaced by memcpy(). */
typedef unsigned int gcm_u64_element_t;

/*
 * This struct is basically to enable big-integer calculations in the 64-bit
 * Galois field. The struct is fixed size for this purpose. The functions that
 * operate on it are specialised to do the bit-reversed operations needed
 * specifically for the Galois 64-bit multiply used in the GCM algorithm.
 */
typedef union
{
    gcm_u64_element_t   element[GCM_U64_NUM_ELEMENTS];
    uint16_t            reduce_bytes;
    uint8_t             bytes[GCM_64_BLOCK_SIZE];
} gcm_u64_struct_t;

typedef struct
{
    gcm_u64_struct_t    key_data[255];
} gcm_64_mul_table8_t;

typedef struct
{
    gcm_u64_struct_t    key_data_hi[15];
    gcm_u64_struct_t    key_data_lo[15];
} gcm_64_mul_table4_t;

/*****************************************************************************
 * Functions
 ****************************************************************************/

void gcm_64_mul(uint8_t p_block[GCM_64_BLOCK_SIZE], const uint8_t p_key[GCM_64_BLOCK_SIZE]);

void gcm_64_mul_prepare_table8(gcm_64_mul_table8_t * restrict p_table, const uint8_t p_key[GCM_64_BLOCK_SIZE]);
void gcm_64_mul_table8(uint8_t p_block[GCM_64_BLOCK_SIZE], const gcm_64_mul_table8_t * p_table);

void gcm_64_mul_prepare_table4(gcm_64_mul_table4_t * restrict p_table, const uint8_t p_key[GCM_64_BLOCK_SIZE]);
void gcm_64_mul_table4(uint8_t p_block[GCM_64_BLOCK_SIZE], const gcm_64_mul_table4_t * p_table);

#endif /* !defined(GCM_64_H) */
