
#include "khazad.h"
#include "khazad-print-block.h"

int main(int argc, char **argv)
{
    size_t  i;
    uint8_t key[KHAZAD_KEY_SIZE] = { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t encode_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE];
    uint8_t crypt_block[KHAZAD_BLOCK_SIZE] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    printf("key: ");
    print_block_hex(key, KHAZAD_KEY_SIZE);

    khazad_encode_key_schedule(encode_key_schedule, key);
    printf("key schedule: ");
    print_block_hex(encode_key_schedule, KHAZAD_KEY_SCHEDULE_SIZE);

    printf("plain: ");
    print_block_hex(crypt_block, KHAZAD_BLOCK_SIZE);

    khazad_crypt(crypt_block, encode_key_schedule);

    printf("crypt: ");
    print_block_hex(crypt_block, KHAZAD_BLOCK_SIZE);

    for (i = 1; i < 100; ++i)
    {
        khazad_crypt(crypt_block, encode_key_schedule);
    }
    printf("100 iter: ");
    print_block_hex(crypt_block, KHAZAD_BLOCK_SIZE);

    return 0;
}

