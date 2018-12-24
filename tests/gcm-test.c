
#include "gcm_64.h"
#include "khazad-add-block.h"
#include "khazad-print-block.h"

#include <string.h>

#include <endian.h>

/*****************************************************************************
 * Defines
 ****************************************************************************/

#define SIMPLE_IV_SIZE          4u

#define MAX(A, B)               ((A) >= (B) ? (A) : (B))
#define MIN(A, B)               ((A) <= (B) ? (A) : (B))

/*****************************************************************************
 * Types
 ****************************************************************************/

typedef enum
{
    GCM_MUL_BIT_BY_BIT,
    GCM_MUL_TABLE4,
    GCM_MUL_TABLE8,
} gcm_mul_implementation_t;

typedef struct
{
    uint8_t a[GCM_64_BLOCK_SIZE];
    uint8_t b[GCM_64_BLOCK_SIZE];
    uint8_t result[GCM_64_BLOCK_SIZE];
} mul_test_vector_t;

typedef union
{
    uint8_t bytes[GCM_64_BLOCK_SIZE];
    struct
    {
        uint8_t iv[SIMPLE_IV_SIZE];
        union
        {
            uint8_t ctr_bytes[4];
            uint32_t ctr;
        };
    };
} gcm_iv_t;

typedef union
{
    uint8_t bytes[GCM_64_BLOCK_SIZE];
    struct
    {
        uint32_t padding1;
        uint32_t aad_len;
    };
    struct
    {
        uint32_t padding2;
        uint32_t pt_len;
    };
} ghash_lengths_t;

/*****************************************************************************
 * Look-up tables
 ****************************************************************************/

static const mul_test_vector_t mul_test_vectors[] =
{
    {
        { 0x95u, 0x2Bu, 0x2Au, 0x56u, 0xA5u, 0x60u, 0x4Au, 0xC0u, },
        { 0xDFu, 0xA6u, 0xBFu, 0x4Du, 0xEDu, 0x81u, 0xDBu, 0x03u, },
        { 0x64u, 0xECu, 0x76u, 0x9Au, 0x3Fu, 0x2Eu, 0xA4u, 0x8Au, },
    },
    {
        { 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
        { 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
        { 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
    },
    {
        { 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
        { 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
        { 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
    },
    {
        { 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
        { 0x40u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
        { 0x40u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
    },
    {
        { 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
        { 0x00u, 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
        { 0x00u, 0x80u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, },
    },
};

/*****************************************************************************
 * Local functions
 ****************************************************************************/

static int gcm_64_mul_test_one(const uint8_t a[GCM_64_BLOCK_SIZE], const uint8_t b[GCM_64_BLOCK_SIZE], const uint8_t correct_result[GCM_64_BLOCK_SIZE])
{
    int     result;
    uint8_t gmul_out[GCM_64_BLOCK_SIZE];

    memcpy(gmul_out, a, GCM_64_BLOCK_SIZE);
    gcm_64_mul(gmul_out, b);

    result = memcmp(gmul_out, correct_result, GCM_64_BLOCK_SIZE) ? 1 : 0;
    if (result)
    {
        printf("gcm_64_mul() a:\n");
        print_block_hex(a, GCM_64_BLOCK_SIZE);

        printf("gcm_64_mul() b:\n");
        print_block_hex(b, GCM_64_BLOCK_SIZE);

        printf("gcm_64_mul() expected:\n");
        print_block_hex(correct_result, GCM_64_BLOCK_SIZE);

        printf("gcm_64_mul() result:\n");
        print_block_hex(gmul_out, GCM_64_BLOCK_SIZE);
        return result;
    }
    return 0;
}

static int gcm_64_mul_test(void)
{
    size_t  i;
    int     result;

    for (i = 0; i < (sizeof(mul_test_vectors)/sizeof(mul_test_vectors[0])); i++)
    {
        result = gcm_64_mul_test_one(mul_test_vectors[i].a, mul_test_vectors[i].b, mul_test_vectors[i].result);
        if (result)
            return result;

        /* Swapped. */
        result = gcm_64_mul_test_one(mul_test_vectors[i].b, mul_test_vectors[i].a, mul_test_vectors[i].result);
        if (result)
            return result;
    }
    return 0;
}

static int gcm_64_mul_table8_test_one(const uint8_t a[GCM_64_BLOCK_SIZE], const uint8_t b[GCM_64_BLOCK_SIZE], const uint8_t correct_result[GCM_64_BLOCK_SIZE])
{
    gcm_64_mul_table8_t mul_table;
    size_t  j;
    int     result;
    uint8_t gmul_out[GCM_64_BLOCK_SIZE];

    /* Prepare the table. */
    //printf("gcm_64_mul_prepare_table8()\n");
    gcm_64_mul_prepare_table8(&mul_table, b);

    /* Do the multiply. */
    memcpy(gmul_out, a, GCM_64_BLOCK_SIZE);
    //printf("gcm_64_mul_table8()\n");
    gcm_64_mul_table8(gmul_out, &mul_table);

    result = memcmp(gmul_out, correct_result, GCM_64_BLOCK_SIZE) ? 1 : 0;
    if (result)
    {
        printf("gcm_64_mul_prepare_table8() result:\n");
        for (j = 0; j < 255; j++)
        {
            printf("%02zX: ", j + 1);
            print_block_hex(mul_table.key_data[j].bytes, GCM_64_BLOCK_SIZE);
        }

        printf("gcm_64_mul_table8() a:\n");
        print_block_hex(a, GCM_64_BLOCK_SIZE);

        printf("gcm_64_mul_table8() b:\n");
        print_block_hex(b, GCM_64_BLOCK_SIZE);

        printf("gcm_64_mul_table8() expected:\n");
        print_block_hex(correct_result, GCM_64_BLOCK_SIZE);

        printf("gcm_64_mul_table8() result:\n");
        print_block_hex(gmul_out, GCM_64_BLOCK_SIZE);

        return result;
    }
    return 0;
}

static int gcm_64_mul_table8_test(void)
{
    size_t  i;
    int     result;

    for (i = 0; i < (sizeof(mul_test_vectors)/sizeof(mul_test_vectors[0])); i++)
    {
        result = gcm_64_mul_table8_test_one(mul_test_vectors[i].a, mul_test_vectors[i].b, mul_test_vectors[i].result);
        if (result)
            return result;

        /* Swapped. */
        result = gcm_64_mul_table8_test_one(mul_test_vectors[i].b, mul_test_vectors[i].a, mul_test_vectors[i].result);
        if (result)
            return result;
    }
    return 0;
}

static int gcm_64_mul_table4_test_one(const uint8_t a[GCM_64_BLOCK_SIZE], const uint8_t b[GCM_64_BLOCK_SIZE], const uint8_t correct_result[GCM_64_BLOCK_SIZE])
{
    gcm_64_mul_table4_t mul_table;
    size_t  j;
    int     result;
    uint8_t gmul_out[GCM_64_BLOCK_SIZE];

    /* Prepare the table. */
    //printf("gcm_64_mul_prepare_table4()\n");
    gcm_64_mul_prepare_table4(&mul_table, b);

    /* Do the multiply. */
    memcpy(gmul_out, a, GCM_64_BLOCK_SIZE);
    //printf("gcm_64_mul_table4()\n");
    gcm_64_mul_table4(gmul_out, &mul_table);

    result = memcmp(gmul_out, correct_result, GCM_64_BLOCK_SIZE) ? 1 : 0;
    if (result)
    {
        printf("gcm_64_mul_prepare_table4() result:\n");
        for (j = 0; j < 15; j++)
        {
            printf("Hi %02zX: ", j + 1);
            print_block_hex(mul_table.key_data_hi[j].bytes, GCM_64_BLOCK_SIZE);
        }
        for (j = 0; j < 15; j++)
        {
            printf("Lo %02zX: ", j + 1);
            print_block_hex(mul_table.key_data_lo[j].bytes, GCM_64_BLOCK_SIZE);
        }

        printf("gcm_64_mul_table4() a:\n");
        print_block_hex(a, GCM_64_BLOCK_SIZE);

        printf("gcm_64_mul_table4() b:\n");
        print_block_hex(b, GCM_64_BLOCK_SIZE);

        printf("gcm_64_mul_table4() expected:\n");
        print_block_hex(correct_result, GCM_64_BLOCK_SIZE);

        printf("gcm_64_mul_table4() result:\n");
        print_block_hex(gmul_out, GCM_64_BLOCK_SIZE);

        return result;
    }
    return 0;
}

static int gcm_64_mul_table4_test(void)
{
    size_t  i;
    int     result;

    for (i = 0; i < (sizeof(mul_test_vectors)/sizeof(mul_test_vectors[0])); i++)
    {
        result = gcm_64_mul_table4_test_one(mul_test_vectors[i].a, mul_test_vectors[i].b, mul_test_vectors[i].result);
        if (result)
            return result;

        /* Swapped. */
        result = gcm_64_mul_table4_test_one(mul_test_vectors[i].b, mul_test_vectors[i].a, mul_test_vectors[i].result);
        if (result)
            return result;
    }
    return 0;
}

/*****************************************************************************
 * Functions
 ****************************************************************************/

int main(int argc, char **argv)
{
    int         result;

    (void)argc;
    (void)argv;

    result = gcm_64_mul_test();
    if (result)
        return result;

    result = gcm_64_mul_table8_test();
    if (result)
        return result;

    result = gcm_64_mul_table4_test();
    if (result)
        return result;

    return 0;
}

