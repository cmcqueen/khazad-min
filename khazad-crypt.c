/*****************************************************************************
 * khazad-crypt.c
 *
 * Khazad crypt function for encryption and decryption.
 *
 * Khazad is an involutional cipher, so encryption and decryption have the
 * same structure. One function can be used for both encryption and
 * decryption, with just a different key schedule.
 * However, the function for calculating the decryption key schedule still uses
 * program space. Having different key schedules for encryption and decryption
 * uses up more memory, which may be limited in a small microprocessor system.
 * So, a separate decryption function is also provided which uses the same
 * key schedule as for encryption.
 * So for decryption, the two choices are:
 *     - Use khazad_key_schedule() to create a key schedule that can be used
 *       for both encryption and decryption. Decrypt using the
 *       khazad_decrypt() function.
 *     - Use khazad_decrypt_key_schedule() to create a key schedule
 *       specifically for decryption. Use it with the common khazad_crypt()
 *       function.
 * These two alternative methods of decryption are possible because of Khazad's
 * involutional design.
 * Depending on which method is used, then one function is unused and can be
 * removed from the build.
 ****************************************************************************/

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include "khazad.h"
#include "khazad-round-funcs.h"
#include "khazad-add-block.h"
#include "khazad-matrix-mul.h"
#include "khazad-sbox.h"

//#include <string.h>

/*****************************************************************************
 * Functions
 ****************************************************************************/

/* Khazad encryption and decryption.
 * p_block points to a 16-byte buffer of data to encrypt/decrypt. Encryption/
 * decryption is done in-place in that buffer.
 * p_key_schedule points to the full calculated key schedule. If the key
 * schedule was calculated with khazad_key_schedule(), then encryption is done.
 * If the key schedule was calculated with khazad_decrypt_key_schedule(), then
 * decryption is done.
 */
void khazad_crypt(uint8_t p_block[KHAZAD_BLOCK_SIZE], const uint8_t p_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE])
{
    uint_fast8_t    round;

    add_block(p_block, p_key_schedule);
    p_key_schedule += KHAZAD_BLOCK_SIZE;
    for (round = 0; round < (KHAZAD_NUM_ROUNDS - 1u); ++round)
    {
        round_func(p_block, p_key_schedule);
        p_key_schedule += KHAZAD_BLOCK_SIZE;
    }
    khazad_sbox_apply_block(p_block);
    add_block(p_block, p_key_schedule);
}
