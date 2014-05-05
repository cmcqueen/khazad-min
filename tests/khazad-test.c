
#include "khazad.h"
#include "khazad-print-block.h"

#include <string.h>

#define DECRYPT_METHOD  1

int main(int argc, char **argv)
{
    size_t  i;
    const uint8_t key[KHAZAD_KEY_SIZE] = { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const uint8_t plain_text[KHAZAD_BLOCK_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t encrypt_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE];
    uint8_t decrypt_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE];
    uint8_t crypt_block[KHAZAD_BLOCK_SIZE];

    (void)argc;
    (void)argv;

    printf("key: ");
    print_block_hex(key, KHAZAD_KEY_SIZE);

    khazad_key_schedule(encrypt_key_schedule, key);
    printf("encrypt key schedule: ");
    print_block_hex(encrypt_key_schedule, KHAZAD_KEY_SCHEDULE_SIZE);

    khazad_decrypt_key_schedule(decrypt_key_schedule, key);
    printf("decrypt key schedule: ");
    print_block_hex(decrypt_key_schedule, KHAZAD_KEY_SCHEDULE_SIZE);

    printf("plain: ");
    print_block_hex(plain_text, KHAZAD_BLOCK_SIZE);

    memcpy(crypt_block, plain_text, KHAZAD_BLOCK_SIZE);

    /* Encrypt 1 */
    khazad_crypt(crypt_block, encrypt_key_schedule);

    printf("crypt: ");
    print_block_hex(crypt_block, KHAZAD_BLOCK_SIZE);

    /* Encrypt 100 */
    for (i = 1; i < 100; ++i)
    {
        khazad_crypt(crypt_block, encrypt_key_schedule);
    }
    printf("100 iter: ");
    print_block_hex(crypt_block, KHAZAD_BLOCK_SIZE);

    /* Encrypt 1000 */
    for (i = 100; i < 1000; ++i)
    {
        khazad_crypt(crypt_block, encrypt_key_schedule);
    }
    printf("1000 iter: ");
    print_block_hex(crypt_block, KHAZAD_BLOCK_SIZE);

    /* Decrypt from 1000 down to 100 */
    for (i = 100; i < 1000; ++i)
    {
#if DECRYPT_METHOD == 0
        khazad_crypt(crypt_block, decrypt_key_schedule);
#else
        khazad_decrypt(crypt_block, encrypt_key_schedule);
#endif
    }
    printf("Decrypt down to 100 iter: ");
    print_block_hex(crypt_block, KHAZAD_BLOCK_SIZE);

    /* Decrypt from 100 down to 1 */
    for (i = 1; i < 100; ++i)
    {
#if DECRYPT_METHOD == 0
        khazad_crypt(crypt_block, decrypt_key_schedule);
#else
        khazad_decrypt(crypt_block, encrypt_key_schedule);
#endif
    }
    printf("Decrypt down to 1 iter: ");
    print_block_hex(crypt_block, KHAZAD_BLOCK_SIZE);

    /* Decrypt from 1 back to original */
#if DECRYPT_METHOD == 0
        khazad_crypt(crypt_block, decrypt_key_schedule);
#else
        khazad_decrypt(crypt_block, encrypt_key_schedule);
#endif

    printf("Decrypt to orig: ");
    print_block_hex(crypt_block, KHAZAD_BLOCK_SIZE);

    return memcmp(crypt_block, plain_text, KHAZAD_BLOCK_SIZE) ? 1 : 0;
}

