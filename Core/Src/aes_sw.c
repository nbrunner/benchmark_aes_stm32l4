/**
 ******************************************************************************
 * @file    aes_sw.c
 * @author  nicolas.brunner@heig-vd.ch
 * @date    05-August-2016
 * @brief   software AES
 ******************************************************************************
 * @copyright HEIG-VD
 *
 * License information
 *
 ******************************************************************************
 */

/* Includes ------------------------------------------------------------------*/

#include <assert.h>
#include <string.h>

#include "cmox_crypto.h"
#include "stm32l4xx_hal.h"

#include "aes_sw.h"

/* Private define ------------------------------------------------------------*/

#define AES_SIZE 16 // 128 bits
#define CTR_IV_SIZE 16 // 128 bits
#define GCM_IV_SIZE 12 // 96 bits

#define FAST

#ifdef FAST
#define ALGO_CTR CMOX_AESFAST_CTR_ENC_ALGO
#define ALGO_GCM_ENC CMOX_AESFAST_GCMFAST_ENC_ALGO
#define ALGO_GCM_DEC CMOX_AESFAST_GCMFAST_DEC_ALGO
#else
#define ALGO_CTR CMOX_AESSMALL_CTR_ENC_ALGO
#define ALGO_GCM_ENC CMOX_AESSMALL_GCMSMALL_ENC_ALGO
#define ALGO_GCM_DEC CMOX_AESSMALL_GCMSMALL_DEC_ALGO
#endif

#define AUTH_HEADER_SIZE 16

/* Private variables ---------------------------------------------------------*/

static const char auth_header[] = "0123456789ABCDEF";

/* Public functions ----------------------------------------------------------*/

void aes_sw_init(void) {
    if (cmox_initialize(NULL) != CMOX_INIT_SUCCESS) {
        assert(false);
    }
}

bool aes_sw_ctr_encrypt(uint8_t* key, uint8_t* init_vector, const uint8_t* plain_data, uint32_t length, uint8_t* cipher_data)
{
    cmox_cipher_retval_t retval;

    retval = cmox_cipher_encrypt(ALGO_CTR,
            plain_data, length,
            key, AES_SIZE,
            init_vector, CTR_IV_SIZE,
            cipher_data, NULL);

    return retval == CMOX_CIPHER_SUCCESS;
}

bool aes_sw_gcm_encrypt(uint8_t* key, uint8_t* init_vector, const uint8_t* plain_data, uint32_t length, uint8_t* cipher_data, uint8_t* mic)
{
    cmox_cipher_retval_t retval;

    retval = cmox_aead_encrypt(ALGO_GCM_ENC,
            plain_data, length,
            16,
            key, AES_SIZE,
            init_vector, GCM_IV_SIZE,
            auth_header, AUTH_HEADER_SIZE,
            cipher_data, NULL);

    return retval == CMOX_CIPHER_SUCCESS;
}

bool aes_sw_gcm_decrypt(uint8_t* key, uint8_t* init_vector, const uint8_t* cipher_data, uint32_t length, uint8_t* plain_data, uint8_t* mic)
{
    cmox_cipher_retval_t retval;

    retval = cmox_aead_decrypt(ALGO_GCM_DEC,
            cipher_data, length+16,
            16,
            key, AES_SIZE,
            init_vector, GCM_IV_SIZE,
            auth_header, AUTH_HEADER_SIZE,
            plain_data, NULL);

    return retval == CMOX_CIPHER_AUTH_SUCCESS;
}
