/*****************************************************************************
 * khazad.h
 *
 * Khazad functions for encryption and decryption, and key schedule
 * calculations for encryption and decryption.
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

#ifndef KHAZAD_H
#define KHAZAD_H

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include <stdint.h>

/*****************************************************************************
 * Defines
 ****************************************************************************/

#define KHAZAD_BLOCK_SIZE           8u

#define KHAZAD_NUM_ROUNDS           8u
#define KHAZAD_KEY_SIZE             16u
#define KHAZAD_KEY_SCHEDULE_SIZE    (KHAZAD_BLOCK_SIZE * (KHAZAD_NUM_ROUNDS + 1u))

/*****************************************************************************
 * Inline functions
 ****************************************************************************/

static inline void khazad_add_block(uint8_t p_block[KHAZAD_BLOCK_SIZE], const uint8_t p_add_block[KHAZAD_BLOCK_SIZE])
{
    uint_fast8_t    i;

    for (i = 0; i < KHAZAD_BLOCK_SIZE; ++i)
    {
        p_block[i] ^= p_add_block[i];
    }
}

/*****************************************************************************
 * Function prototypes
 ****************************************************************************/

/* Khazad encryption and decryption.
 * p_block points to a 16-byte buffer of data to encrypt/decrypt. Encryption/
 * decryption is done in-place in that buffer.
 * p_key_schedule points to the full calculated key schedule. If the key
 * schedule was calculated with khazad_key_schedule(), then encryption is done.
 * If the key schedule was calculated with khazad_decrypt_key_schedule(), then
 * decryption is done.
 */
void khazad_crypt(uint8_t p_block[KHAZAD_BLOCK_SIZE], const uint8_t p_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE]);

/* Khazad decryption.
 * p_block points to a 16-byte buffer of encrypted data to decrypt. Decryption
 * is done in-place in that buffer.
 * p_key_schedule points to the full calculated key schedule, calculated with
 * khazad_key_schedule().
 */
void khazad_decrypt(uint8_t p_block[KHAZAD_BLOCK_SIZE], const uint8_t p_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE]);

/* Calculate full key schedule for Khazad encryption (or decryption).
 * p_key_schedule points to a 72-byte buffer of data to store the key schedule.
 * If the key schedule is used with khazad_crypt(), then encryption is done.
 * If the key schedule is used with khazad_decrypt(), then decryption is done.
 */
void khazad_key_schedule(uint8_t p_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE], const uint8_t p_key[KHAZAD_KEY_SIZE]);

/* Calculate full key schedule for Khazad decryption using the common crypt
 * function khazad_crypt().
 * p_key_schedule points to a 72-byte buffer of data to store the key schedule.
 * This key schedule is suitable for use with khazad_crypt() to do decryption.
 */
void khazad_decrypt_key_schedule(uint8_t p_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE], const uint8_t p_key[KHAZAD_KEY_SIZE]);


/* Khazad encryption with on-the-fly key schedule calculation.
 *
 * p_block points to a 16-byte buffer of plain data to encrypt. Encryption
 * is done in-place in that buffer.
 * p_encrypt_start_key must initially point to a starting key state for
 * encryption, which must be calculated from the Khazad key, by the function
 * khazad_otfks_encrypt_start_key(). Key schedule is calculated on-the-fly in
 * that buffer, so the buffer must re-initialised for subsequent encryption
 * operations.
 */
void khazad_otfks_encrypt(uint8_t p_block[KHAZAD_BLOCK_SIZE], uint8_t p_encrypt_start_key[KHAZAD_KEY_SIZE]);

/* Khazad decryption with on-the-fly key schedule calculation.
 *
 * p_block points to a 16-byte buffer of encrypted data to decrypt. Decryption
 * is done in-place in that buffer.
 * p_decrypt_start_key must initially point to a starting key state for
 * decryption, which must be calculated from the Khazad key, by the function
 * khazad_otfks_decrypt_start_key(). Key schedule is calculated on-the-fly in
 * that buffer, so the buffer must re-initialised for subsequent encryption
 * operations.
 */
void khazad_otfks_decrypt(uint8_t p_block[KHAZAD_BLOCK_SIZE], uint8_t p_decrypt_start_key[KHAZAD_KEY_SIZE]);

/* Calculate the starting key state needed for encryption with on-the-fly key
 * schedule calculation. The starting encryption key state is the first 16
 * bytes of the Khazad key schedule, which is not the Khazad key itself but two
 * key schedule rounds applied to the Khazad key.
 * The encryption start key calculation is done in-place in the buffer p_key[].
 * So p_key points to a 16-byte buffer containing the Khazad key. On exit, it
 * contains the encryption start key state suitable for khazad_otfks_encrypt().
 */
void khazad_otfks_encrypt_start_key(uint8_t p_key[KHAZAD_KEY_SIZE]);

/* Calculate the starting key state needed for decryption with on-the-fly key
 * schedule calculation. The starting decryption key state is the last 16 bytes
 * of the Khazad key schedule.
 * The decryption start key calculation is done in-place in the buffer p_key[].
 * So p_key points to a 16-byte buffer containing the Khazad key. On exit, it
 * contains the decryption start key state suitable for khazad_otfks_decrypt().
 */
void khazad_otfks_decrypt_start_key(uint8_t p_key[KHAZAD_KEY_SIZE]);

/* This calculates the decryption start key, but unlike
 * khazad_otfks_decrypt_start_key(), it calculates it from the encryption start
 * key rather than the original Khazad key.
 */
void khazad_otfks_decrypt_from_encrypt_start_key(uint8_t p_key[KHAZAD_KEY_SIZE]);


#endif /* !defined(KHAZAD_H) */
