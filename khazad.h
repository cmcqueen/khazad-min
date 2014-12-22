/*****************************************************************************
 *
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

void khazad_crypt(uint8_t p_block[KHAZAD_BLOCK_SIZE], const uint8_t p_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE]);
void khazad_decrypt(uint8_t p_block[KHAZAD_BLOCK_SIZE], const uint8_t p_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE]);

void khazad_key_schedule(uint8_t p_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE], const uint8_t p_key[KHAZAD_KEY_SIZE]);
void khazad_decrypt_key_schedule(uint8_t p_key_schedule[KHAZAD_KEY_SCHEDULE_SIZE], const uint8_t p_key[KHAZAD_KEY_SIZE]);


#endif /* !defined(KHAZAD_H) */

