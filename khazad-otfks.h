/*****************************************************************************
 * khazad-otfks.h
 *
 * Khazad functions with on-the-fly key schedule calculations.
 * These functions don't require the full pre-calculated key schedule, thus
 * reducing memory requirements, at the expense of greater execution time.
 * These functions could be useful for a small microprocessor-based system
 * with limited ROM/RAM memory, such as a smartcard.
 ****************************************************************************/

#ifndef KHAZAD_OTFKS_H
#define KHAZAD_OTFKS_H

/*****************************************************************************
 * Includes
 ****************************************************************************/

#include "khazad.h"

/*****************************************************************************
 * Function prototypes
 ****************************************************************************/

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

#endif /* !defined(KHAZAD_OTFKS_H) */
