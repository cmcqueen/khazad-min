
#include "khazad.h"
#include "khazad-otfks.h"
#include "khazad-print-block.h"

#include <string.h>

#define DECRYPT_METHOD  1
#define ENCRYPT_OTFKS   1
#define DECRYPT_OTFKS   1

int main(int argc, char **argv)
{
    size_t  i;
    const uint8_t key[KHAZAD_KEY_SIZE] = { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const uint8_t plain_text[KHAZAD_BLOCK_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t encrypt_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE];
    uint8_t decrypt_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE];
    uint8_t otfks_encrypt_key_start[KHAZAD_KEY_SIZE];
    uint8_t otfks_decrypt_key_start[KHAZAD_KEY_SIZE];
    uint8_t otfks_key_work[KHAZAD_KEY_SIZE];
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

#if ENCRYPT_OTFKS
    memcpy(otfks_encrypt_key_start, key, KHAZAD_KEY_SIZE);
    khazad_otfks_encrypt_start_key(otfks_encrypt_key_start);
    printf("encrypt key start: ");
    print_block_hex(otfks_encrypt_key_start, KHAZAD_KEY_SIZE);
#endif

#if DECRYPT_OTFKS
    memcpy(otfks_decrypt_key_start, key, KHAZAD_KEY_SIZE);
    khazad_otfks_decrypt_start_key(otfks_decrypt_key_start);
    printf("decrypt key start: ");
    print_block_hex(otfks_decrypt_key_start, KHAZAD_KEY_SIZE);
#endif

    printf("plain: ");
    print_block_hex(plain_text, KHAZAD_BLOCK_SIZE);

    memcpy(crypt_block, plain_text, KHAZAD_BLOCK_SIZE);

    /* Encrypt 1 */
#if ENCRYPT_OTFKS == 0
    khazad_crypt(crypt_block, encrypt_key_schedule);
#else
    memcpy(otfks_key_work, otfks_encrypt_key_start, KHAZAD_KEY_SIZE);
    khazad_otfks_encrypt(crypt_block, otfks_key_work);
#endif

    printf("crypt: ");
    print_block_hex(crypt_block, KHAZAD_BLOCK_SIZE);

    /* Encrypt 100 */
    for (i = 1; i < 100; ++i)
    {
#if ENCRYPT_OTFKS == 0
        khazad_crypt(crypt_block, encrypt_key_schedule);
#else
        memcpy(otfks_key_work, otfks_encrypt_key_start, KHAZAD_KEY_SIZE);
        khazad_otfks_encrypt(crypt_block, otfks_key_work);
#endif
    }
    printf("100 iter: ");
    print_block_hex(crypt_block, KHAZAD_BLOCK_SIZE);

    /* Encrypt 1000 */
    for (i = 100; i < 1000; ++i)
    {
#if ENCRYPT_OTFKS == 0
        khazad_crypt(crypt_block, encrypt_key_schedule);
#else
        memcpy(otfks_key_work, otfks_encrypt_key_start, KHAZAD_KEY_SIZE);
        khazad_otfks_encrypt(crypt_block, otfks_key_work);
#endif
    }
    printf("1000 iter: ");
    print_block_hex(crypt_block, KHAZAD_BLOCK_SIZE);

    /* Decrypt from 1000 down to 100 */
    for (i = 100; i < 1000; ++i)
    {
#if DECRYPT_OTFKS == 1
    memcpy(otfks_key_work, otfks_decrypt_key_start, KHAZAD_KEY_SIZE);
    khazad_otfks_decrypt(crypt_block, otfks_key_work);
#elif DECRYPT_METHOD == 0
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
#if DECRYPT_OTFKS == 1
    memcpy(otfks_key_work, otfks_decrypt_key_start, KHAZAD_KEY_SIZE);
    khazad_otfks_decrypt(crypt_block, otfks_key_work);
#elif DECRYPT_METHOD == 0
        khazad_crypt(crypt_block, decrypt_key_schedule);
#else
        khazad_decrypt(crypt_block, encrypt_key_schedule);
#endif
    }
    printf("Decrypt down to 1 iter: ");
    print_block_hex(crypt_block, KHAZAD_BLOCK_SIZE);

    /* Decrypt from 1 back to original */
#if DECRYPT_OTFKS == 1
    memcpy(otfks_key_work, otfks_decrypt_key_start, KHAZAD_KEY_SIZE);
    khazad_otfks_decrypt(crypt_block, otfks_key_work);
#elif DECRYPT_METHOD == 0
    khazad_crypt(crypt_block, decrypt_key_schedule);
#else
    khazad_decrypt(crypt_block, encrypt_key_schedule);
#endif

    printf("Decrypt to orig: ");
    print_block_hex(crypt_block, KHAZAD_BLOCK_SIZE);

    return memcmp(crypt_block, plain_text, KHAZAD_BLOCK_SIZE) ? 1 : 0;
}

