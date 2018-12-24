/*****************************************************************************
 * gcm_64.c
 *
 * Functions to support GCM mode.
 ****************************************************************************/

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include "gcm_64.h"

#include <string.h>

/*****************************************************************************
 * Defines
 ****************************************************************************/

#define GCM_U64_ELEMENT_SIZE_BITS   (8u * GCM_U64_ELEMENT_SIZE)

#define GCM_U64_STRUCT_INIT_0       { { 0 } }

/*****************************************************************************
 * Local function prototypes
 ****************************************************************************/

static void gcm_u64_struct_from_bytes(gcm_u64_struct_t * restrict p_dst, const uint8_t p_src[GCM_64_BLOCK_SIZE]);
static void gcm_u64_struct_to_bytes(uint8_t p_dst[GCM_64_BLOCK_SIZE], const gcm_u64_struct_t * p_src);
static void uint64_struct_mul2(gcm_u64_struct_t * restrict p);
static void block_mul256(gcm_u64_struct_t * restrict p);

/*****************************************************************************
 * Local inline functions
 ****************************************************************************/

/*
 * XOR for gcm_u64_struct_t.
 *
 * In-place XOR all the bits of p_src into p_dst.
 */
static inline void uint64_struct_xor(gcm_u64_struct_t * p_dst, const gcm_u64_struct_t * p_src)
{
    uint_fast8_t        i;

    for (i = 0; i < GCM_U64_NUM_ELEMENTS; i++)
    {
        p_dst->element[i] ^= p_src->element[i];
    }
}

/*****************************************************************************
 * Functions
 ****************************************************************************/

/*
 * Galois 64-bit multiply for GCM mode of encryption.
 *
 * This implementation uses a bit-by-bit calculation of the multiplication.
 * It is the slowest implementation, but requires minimal memory.
 */
void gcm_64_mul(uint8_t p_block[GCM_64_BLOCK_SIZE], const uint8_t p_key[GCM_64_BLOCK_SIZE])
{
    gcm_u64_struct_t    a;
    gcm_u64_struct_t    result = GCM_U64_STRUCT_INIT_0;
    uint_fast8_t        i = GCM_64_BLOCK_SIZE - 1u;
    uint8_t             j_bit = 1u;

    gcm_u64_struct_from_bytes(&a, p_key);

    /* Skip initial uint64_struct_mul2(&result) which is unnecessary when
     * result is initially zero. */
    goto start;

    for (;;)
    {
        for (j_bit = 1u; j_bit != 0; j_bit <<= 1u)
        {
            uint64_struct_mul2(&result);
start:
            if (p_block[i] & j_bit)
            {
                uint64_struct_xor(&result, &a);
            }
        }
        if (i == 0)
        {
            break;
        }
        i--;
    }

    gcm_u64_struct_to_bytes(p_block, &result);
}

/*
 * Given a key, pre-calculate the large table that is needed for
 * gcm_64_mul_table(), the 8-bit table-driven implementation of GCM multiplication.
 */
void gcm_64_mul_prepare_table8(gcm_64_mul_table8_t * restrict p_table, const uint8_t p_key[GCM_64_BLOCK_SIZE])
{
    uint8_t             i_bit = 1u;
    uint_fast8_t        j;
    gcm_u64_struct_t    block;

    memset(p_table, 0, sizeof(*p_table));

    for (i_bit = 0x80u; i_bit != 0; i_bit >>= 1u)
    {
        memset(&block, 0u, sizeof(block));
        block.bytes[0] = i_bit;
        gcm_64_mul(block.bytes, p_key);
        for (j = 255; j != 0; j--)
        {
            if (j & i_bit)
            {
                uint64_struct_xor(&p_table->key_data[j - 1u], &block);
            }
        }
    }
}

/*
 * Galois 64-bit multiply for GCM mode of encryption.
 *
 * This implementation uses an 8-bit table look-up.
 * It is the fastest implementation, but requires a large table pre-calculated
 * from the key.
 */
void gcm_64_mul_table8(uint8_t p_block[GCM_64_BLOCK_SIZE], const gcm_64_mul_table8_t * p_table)
{
    uint8_t             block_byte;
    gcm_u64_struct_t    result = GCM_U64_STRUCT_INIT_0;
    uint_fast8_t        i = GCM_64_BLOCK_SIZE - 1u;

    /* Skip initial block_mul256(&result) which is unnecessary when
     * result is initially zero. */
    goto start;

    for (;;)
    {
        block_mul256(&result);
start:
        block_byte = p_block[i];
        if (block_byte)
        {
            uint64_struct_xor(&result, &p_table->key_data[block_byte - 1u]);
        }
        if (i == 0)
        {
            break;
        }
        i--;
    }
    memcpy(p_block, result.bytes, GCM_64_BLOCK_SIZE);
}

/*
 * Given a key, pre-calculate the medium-sized table that is needed for
 * gcm_64_mul_table4(), the 4-bit table-driven implementation of GCM multiplication.
 */
void gcm_64_mul_prepare_table4(gcm_64_mul_table4_t * restrict p_table, const uint8_t p_key[GCM_64_BLOCK_SIZE])
{
    uint8_t             i_bit = 1u;
    uint_fast8_t        j;
    gcm_u64_struct_t    block;

    memset(p_table, 0, sizeof(*p_table));

    for (i_bit = 0x80u; i_bit != 0; i_bit >>= 1u)
    {
        memset(&block, 0u, sizeof(block));
        block.bytes[0] = i_bit;
        gcm_64_mul(block.bytes, p_key);
        if (i_bit >= 0x10u)
        {
            for (j = 15; j != 0; j--)
            {
                if (j & (i_bit >> 4u))
                {
                    uint64_struct_xor(&p_table->key_data_hi[j - 1u], &block);
                }
            }
        }
        else
        {
            for (j = 15; j != 0; j--)
            {
                if (j & i_bit)
                {
                    uint64_struct_xor(&p_table->key_data_lo[j - 1u], &block);
                }
            }
        }
    }
}

/*
 * Galois 64-bit multiply for GCM mode of encryption.
 *
 * This implementation uses an 4-bit table look-up.
 * This implementation is faster than the bit-by-bit implementation, but has
 * more modest memory requirements for the table pre-calculated from the key,
 * compared to the 8-bit table look-up of gcm_64_mul_table().
 */
void gcm_64_mul_table4(uint8_t p_block[GCM_64_BLOCK_SIZE], const gcm_64_mul_table4_t * p_table)
{
    uint8_t             block_byte;
    uint8_t             block_nibble;
    gcm_u64_struct_t    result = GCM_U64_STRUCT_INIT_0;
    uint_fast8_t        i = GCM_64_BLOCK_SIZE - 1u;

    /* Skip initial block_mul256(&result) which is unnecessary when
     * result is initially zero. */
    goto start;

    for (;;)
    {
        block_mul256(&result);
start:
        block_byte = p_block[i];
        /* High nibble */
        block_nibble = (block_byte >> 4u) & 0xFu;
        if (block_nibble)
        {
            uint64_struct_xor(&result, &p_table->key_data_hi[block_nibble - 1u]);
        }
        /* Low nibble */
        block_nibble = block_byte & 0xFu;
        if (block_nibble)
        {
            uint64_struct_xor(&result, &p_table->key_data_lo[block_nibble - 1u]);
        }
        if (i == 0)
        {
            break;
        }
        i--;
    }
    memcpy(p_block, result.bytes, GCM_64_BLOCK_SIZE);
}

/*****************************************************************************
 * Local functions
 ****************************************************************************/

/*
 * Convert a multiplicand for GCM Galois 64-bit multiply into a form that can
 * be more efficiently manipulated for bit-by-bit calculation of the multiply.
 */
static void gcm_u64_struct_from_bytes(gcm_u64_struct_t * restrict p_dst, const uint8_t p_src[GCM_64_BLOCK_SIZE])
{
    uint_fast8_t        i;
    uint_fast8_t        j;
    const uint8_t *     p_src_tmp;
    gcm_u64_element_t   temp;

    p_src_tmp = p_src;
    for (i = 0; i < GCM_U64_NUM_ELEMENTS; i++)
    {
        temp = 0;
        for (j = 0; j < GCM_U64_ELEMENT_SIZE; j++)
        {
            temp = (temp << 8) | *p_src_tmp++;
        }
        p_dst->element[i] = temp;
    }
}

/*
 * Convert the GCM Galois 64-bit multiply special form back into an ordinary
 * string of bytes.
 */
static void gcm_u64_struct_to_bytes(uint8_t p_dst[GCM_64_BLOCK_SIZE], const gcm_u64_struct_t * p_src)
{
    uint_fast8_t        i;
    uint_fast8_t        j;
    uint8_t *           p_dst_tmp;
    gcm_u64_element_t   temp;

    p_dst_tmp = p_dst;
    for (i = 0; i < GCM_U64_NUM_ELEMENTS; i++)
    {
        temp = p_src->element[i];
        for (j = 0; j < GCM_U64_ELEMENT_SIZE; j++)
        {
            *p_dst_tmp++ = (temp >> (GCM_U64_ELEMENT_SIZE_BITS - 8u));
            temp <<= 8;
        }
    }
}

/*
 * Galois 64-bit multiply by 2.
 *
 * Multiply is done in-place on the gcm_u64_struct_t operand.
 */
static void uint64_struct_mul2(gcm_u64_struct_t * restrict p)
{
    uint_fast8_t        i = 0;
    gcm_u64_element_t   carry;
    gcm_u64_element_t   next_carry;

    /*
     * This expression is intended to be timing invariant to prevent a timing
     * attack due to execution timing dependent on the bits of the GHASH key.
     * Check generated assembler from the compiler to confirm it.
     * This could be expressed as an 'if' statement, but then it's less likely
     * to be timing invariant.
     *
     * (0xD8u << (GCM_U64_ELEMENT_SIZE_BITS - 8u)) is the reduction poly bits.
     * (p->element[GCM_U64_NUM_ELEMENTS - 1u] & 1u) is the check of the MSbit
     * to determine if it's necessary to XOR the reduction poly.
     * (-(p->element[GCM_U64_NUM_ELEMENTS - 1u] & 1u)) turns it into a mask for
     * the bitwise AND.
     */
    carry = (0xD8u << (GCM_U64_ELEMENT_SIZE_BITS - 8u)) & (-(p->element[GCM_U64_NUM_ELEMENTS - 1u] & 1u));

    goto start;
    for (i = 0; i < GCM_U64_NUM_ELEMENTS - 1u; i++)
    {
        carry = next_carry;
start:
        next_carry = ((p->element[i] & 1u) << (GCM_U64_ELEMENT_SIZE_BITS - 1u));
        p->element[i] = (p->element[i] >> 1u) ^ carry;
    }
    p->element[i] = (p->element[i] >> 1u) ^ next_carry;
}

#if 1

/*
 * Galois 64-bit multiply by 2^8.
 *
 * Multiply is done in-place on the byte array of standard block size.
 *
 * Generic implementation that should work for either big- or little-endian,
 * albeit not necessarily as fast.
 */
static void block_mul256(gcm_u64_struct_t * restrict p)
{
    static const uint16_t reduce_table[] =
    {
        0x0000u, 0x01B0u, 0x0360u, 0x02D0u, 0x06C0u, 0x0770u, 0x05A0u, 0x0410u, 0x0D80u, 0x0C30u, 0x0EE0u, 0x0F50u, 0x0B40u, 0x0AF0u, 0x0820u, 0x0990u, 
        0x1B00u, 0x1AB0u, 0x1860u, 0x19D0u, 0x1DC0u, 0x1C70u, 0x1EA0u, 0x1F10u, 0x1680u, 0x1730u, 0x15E0u, 0x1450u, 0x1040u, 0x11F0u, 0x1320u, 0x1290u, 
        0x3600u, 0x37B0u, 0x3560u, 0x34D0u, 0x30C0u, 0x3170u, 0x33A0u, 0x3210u, 0x3B80u, 0x3A30u, 0x38E0u, 0x3950u, 0x3D40u, 0x3CF0u, 0x3E20u, 0x3F90u, 
        0x2D00u, 0x2CB0u, 0x2E60u, 0x2FD0u, 0x2BC0u, 0x2A70u, 0x28A0u, 0x2910u, 0x2080u, 0x2130u, 0x23E0u, 0x2250u, 0x2640u, 0x27F0u, 0x2520u, 0x2490u, 
        0x6C00u, 0x6DB0u, 0x6F60u, 0x6ED0u, 0x6AC0u, 0x6B70u, 0x69A0u, 0x6810u, 0x6180u, 0x6030u, 0x62E0u, 0x6350u, 0x6740u, 0x66F0u, 0x6420u, 0x6590u, 
        0x7700u, 0x76B0u, 0x7460u, 0x75D0u, 0x71C0u, 0x7070u, 0x72A0u, 0x7310u, 0x7A80u, 0x7B30u, 0x79E0u, 0x7850u, 0x7C40u, 0x7DF0u, 0x7F20u, 0x7E90u, 
        0x5A00u, 0x5BB0u, 0x5960u, 0x58D0u, 0x5CC0u, 0x5D70u, 0x5FA0u, 0x5E10u, 0x5780u, 0x5630u, 0x54E0u, 0x5550u, 0x5140u, 0x50F0u, 0x5220u, 0x5390u, 
        0x4100u, 0x40B0u, 0x4260u, 0x43D0u, 0x47C0u, 0x4670u, 0x44A0u, 0x4510u, 0x4C80u, 0x4D30u, 0x4FE0u, 0x4E50u, 0x4A40u, 0x4BF0u, 0x4920u, 0x4890u, 
        0xD800u, 0xD9B0u, 0xDB60u, 0xDAD0u, 0xDEC0u, 0xDF70u, 0xDDA0u, 0xDC10u, 0xD580u, 0xD430u, 0xD6E0u, 0xD750u, 0xD340u, 0xD2F0u, 0xD020u, 0xD190u, 
        0xC300u, 0xC2B0u, 0xC060u, 0xC1D0u, 0xC5C0u, 0xC470u, 0xC6A0u, 0xC710u, 0xCE80u, 0xCF30u, 0xCDE0u, 0xCC50u, 0xC840u, 0xC9F0u, 0xCB20u, 0xCA90u, 
        0xEE00u, 0xEFB0u, 0xED60u, 0xECD0u, 0xE8C0u, 0xE970u, 0xEBA0u, 0xEA10u, 0xE380u, 0xE230u, 0xE0E0u, 0xE150u, 0xE540u, 0xE4F0u, 0xE620u, 0xE790u, 
        0xF500u, 0xF4B0u, 0xF660u, 0xF7D0u, 0xF3C0u, 0xF270u, 0xF0A0u, 0xF110u, 0xF880u, 0xF930u, 0xFBE0u, 0xFA50u, 0xFE40u, 0xFFF0u, 0xFD20u, 0xFC90u, 
        0xB400u, 0xB5B0u, 0xB760u, 0xB6D0u, 0xB2C0u, 0xB370u, 0xB1A0u, 0xB010u, 0xB980u, 0xB830u, 0xBAE0u, 0xBB50u, 0xBF40u, 0xBEF0u, 0xBC20u, 0xBD90u, 
        0xAF00u, 0xAEB0u, 0xAC60u, 0xADD0u, 0xA9C0u, 0xA870u, 0xAAA0u, 0xAB10u, 0xA280u, 0xA330u, 0xA1E0u, 0xA050u, 0xA440u, 0xA5F0u, 0xA720u, 0xA690u, 
        0x8200u, 0x83B0u, 0x8160u, 0x80D0u, 0x84C0u, 0x8570u, 0x87A0u, 0x8610u, 0x8F80u, 0x8E30u, 0x8CE0u, 0x8D50u, 0x8940u, 0x88F0u, 0x8A20u, 0x8B90u, 
        0x9900u, 0x98B0u, 0x9A60u, 0x9BD0u, 0x9FC0u, 0x9E70u, 0x9CA0u, 0x9D10u, 0x9480u, 0x9530u, 0x97E0u, 0x9650u, 0x9240u, 0x93F0u, 0x9120u, 0x9090u, 
    };
#if 0
    uint_fast8_t        i;
#endif
    uint_fast16_t       reduce;

    reduce = reduce_table[p->bytes[GCM_64_BLOCK_SIZE - 1u]];
#if 0
    for (i = GCM_64_BLOCK_SIZE - 1u; i != 0; i--)
    {
        p->bytes[i] = p->bytes[i - 1u];
    }
#else
    memmove(p->bytes + 1, p->bytes, GCM_64_BLOCK_SIZE - 1u);
#endif
    p->bytes[0] = reduce >> 8;
    p->bytes[1] ^= reduce;
}

#else

/*
 * Galois 64-bit multiply by 2^8.
 *
 * Multiply is done in-place on the byte array of standard block size.
 *
 * Little-endian specific implementation.
 * This implementation requires gcm_u64_element_t to be at least a 16-bit
 * integer. I.e. it doesn't work with uint8_t.
 */
static void block_mul256(gcm_u64_struct_t * restrict p)
{
    static const uint16_t reduce_table[] =
    {
        0x0000u, 0xB001u, 0x6003u, 0xD002u, 0xC006u, 0x7007u, 0xA005u, 0x1004u, 0x800Du, 0x300Cu, 0xE00Eu, 0x500Fu, 0x400Bu, 0xF00Au, 0x2008u, 0x9009u, 
        0x001Bu, 0xB01Au, 0x6018u, 0xD019u, 0xC01Du, 0x701Cu, 0xA01Eu, 0x101Fu, 0x8016u, 0x3017u, 0xE015u, 0x5014u, 0x4010u, 0xF011u, 0x2013u, 0x9012u, 
        0x0036u, 0xB037u, 0x6035u, 0xD034u, 0xC030u, 0x7031u, 0xA033u, 0x1032u, 0x803Bu, 0x303Au, 0xE038u, 0x5039u, 0x403Du, 0xF03Cu, 0x203Eu, 0x903Fu, 
        0x002Du, 0xB02Cu, 0x602Eu, 0xD02Fu, 0xC02Bu, 0x702Au, 0xA028u, 0x1029u, 0x8020u, 0x3021u, 0xE023u, 0x5022u, 0x4026u, 0xF027u, 0x2025u, 0x9024u, 
        0x006Cu, 0xB06Du, 0x606Fu, 0xD06Eu, 0xC06Au, 0x706Bu, 0xA069u, 0x1068u, 0x8061u, 0x3060u, 0xE062u, 0x5063u, 0x4067u, 0xF066u, 0x2064u, 0x9065u, 
        0x0077u, 0xB076u, 0x6074u, 0xD075u, 0xC071u, 0x7070u, 0xA072u, 0x1073u, 0x807Au, 0x307Bu, 0xE079u, 0x5078u, 0x407Cu, 0xF07Du, 0x207Fu, 0x907Eu, 
        0x005Au, 0xB05Bu, 0x6059u, 0xD058u, 0xC05Cu, 0x705Du, 0xA05Fu, 0x105Eu, 0x8057u, 0x3056u, 0xE054u, 0x5055u, 0x4051u, 0xF050u, 0x2052u, 0x9053u, 
        0x0041u, 0xB040u, 0x6042u, 0xD043u, 0xC047u, 0x7046u, 0xA044u, 0x1045u, 0x804Cu, 0x304Du, 0xE04Fu, 0x504Eu, 0x404Au, 0xF04Bu, 0x2049u, 0x9048u, 
        0x00D8u, 0xB0D9u, 0x60DBu, 0xD0DAu, 0xC0DEu, 0x70DFu, 0xA0DDu, 0x10DCu, 0x80D5u, 0x30D4u, 0xE0D6u, 0x50D7u, 0x40D3u, 0xF0D2u, 0x20D0u, 0x90D1u, 
        0x00C3u, 0xB0C2u, 0x60C0u, 0xD0C1u, 0xC0C5u, 0x70C4u, 0xA0C6u, 0x10C7u, 0x80CEu, 0x30CFu, 0xE0CDu, 0x50CCu, 0x40C8u, 0xF0C9u, 0x20CBu, 0x90CAu, 
        0x00EEu, 0xB0EFu, 0x60EDu, 0xD0ECu, 0xC0E8u, 0x70E9u, 0xA0EBu, 0x10EAu, 0x80E3u, 0x30E2u, 0xE0E0u, 0x50E1u, 0x40E5u, 0xF0E4u, 0x20E6u, 0x90E7u, 
        0x00F5u, 0xB0F4u, 0x60F6u, 0xD0F7u, 0xC0F3u, 0x70F2u, 0xA0F0u, 0x10F1u, 0x80F8u, 0x30F9u, 0xE0FBu, 0x50FAu, 0x40FEu, 0xF0FFu, 0x20FDu, 0x90FCu, 
        0x00B4u, 0xB0B5u, 0x60B7u, 0xD0B6u, 0xC0B2u, 0x70B3u, 0xA0B1u, 0x10B0u, 0x80B9u, 0x30B8u, 0xE0BAu, 0x50BBu, 0x40BFu, 0xF0BEu, 0x20BCu, 0x90BDu, 
        0x00AFu, 0xB0AEu, 0x60ACu, 0xD0ADu, 0xC0A9u, 0x70A8u, 0xA0AAu, 0x10ABu, 0x80A2u, 0x30A3u, 0xE0A1u, 0x50A0u, 0x40A4u, 0xF0A5u, 0x20A7u, 0x90A6u, 
        0x0082u, 0xB083u, 0x6081u, 0xD080u, 0xC084u, 0x7085u, 0xA087u, 0x1086u, 0x808Fu, 0x308Eu, 0xE08Cu, 0x508Du, 0x4089u, 0xF088u, 0x208Au, 0x908Bu, 
        0x0099u, 0xB098u, 0x609Au, 0xD09Bu, 0xC09Fu, 0x709Eu, 0xA09Cu, 0x109Du, 0x8094u, 0x3095u, 0xE097u, 0x5096u, 0x4092u, 0xF093u, 0x2091u, 0x9090u, 
    };
    uint_fast8_t        i = 0;
    gcm_u64_element_t   carry;
    gcm_u64_element_t   next_carry;

    carry = reduce_table[p->bytes[GCM_64_BLOCK_SIZE - 1u]];

    goto start;
    for (; i < GCM_U64_NUM_ELEMENTS - 1u; i++)
    {
        carry = next_carry;
start:
        next_carry = p->element[i] >> (GCM_U64_ELEMENT_SIZE_BITS - 8u);
        p->element[i] = (p->element[i] << 8u) ^ carry;
    }
    p->element[i] = (p->element[i] << 8u) ^ next_carry;
}

#endif
