/**
 ******************************************************************************
 * @file    aes_hw.h
 * @author  nicolas.brunner@heig-vd.ch
 * @date    05-August-2016
 * @brief   hardware AES
 ******************************************************************************
 * @copyright HEIG-VD
 *
 * License information
 *
 ******************************************************************************
 */

#ifndef AES_HW_H
#define AES_HW_H

/* Includes ------------------------------------------------------------------*/

#include <stdbool.h>
#include <stdint.h>

/* Exported functions --------------------------------------------------------*/

void aes_hw_init(void);

/**
 * Encrypt using AES in CTR Mode
 * @param key the 128 bits key used for AES algorithm.
 * @param initVector Initialization Vector used for AES algorithm.
 * @param plainData pointer to the data to encrypt
 * @param length the length of the data to encrypt in byte
 * @param cipherData: pointer to the encrypted data
 * @return true if operation success
 */
bool aes_hw_ctr_encrypt(uint8_t* key, uint8_t* initVector, const uint8_t* plainData, uint32_t length, uint8_t* cipherData);

// AES CTR decryption is the same than encryption
#define aes_hw_ctr_decrypt aes_ctr_encrypt

bool aes_hw_gcm_encrypt(uint8_t* key, uint8_t* init_vector, const uint8_t* plain_data, uint32_t length, uint8_t* cipher_data, uint8_t* mic);

bool aes_hw_gcm_decrypt(uint8_t* key, uint8_t* init_vector, const uint8_t* cipher_data, uint32_t length, uint8_t* plain_data, uint8_t* mic);

#endif
