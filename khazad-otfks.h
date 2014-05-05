
#ifndef KHAZAD_OTFKS_H
#define KHAZAD_OTFKS_H


#include "khazad.h"

void khazad_otfks_encrypt(uint8_t p_block[KHAZAD_BLOCK_SIZE], uint8_t p_encrypt_start_key[KHAZAD_KEY_SIZE]);
void khazad_otfks_decrypt(uint8_t p_block[KHAZAD_BLOCK_SIZE], uint8_t p_decrypt_start_key[KHAZAD_KEY_SIZE]);

void khazad_otfks_encrypt_start_key(uint8_t p_key[KHAZAD_KEY_SIZE]);
void khazad_otfks_decrypt_start_key(uint8_t p_key[KHAZAD_KEY_SIZE]);
void khazad_otfks_decrypt_from_encrypt_start_key(uint8_t p_key[KHAZAD_KEY_SIZE]);

#endif /* !defined(KHAZAD_OTFKS_H) */

