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


#endif /* !defined(KHAZAD_H) */
