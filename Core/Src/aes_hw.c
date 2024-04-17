/**
 ******************************************************************************
 * @file    aes_hw.c
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

/* Includes ------------------------------------------------------------------*/

#include <assert.h>
#include <string.h>

#include "cmox_crypto.h"
#include "stm32l4xx_hal.h"

#include "aes.h"

/* Private define ------------------------------------------------------------*/

#define AES_SIZE 16 // 128 bits

//#define SW_AES
#define ALGO CMOX_AESFAST_CTR_ENC_ALGO
//#define ALGO CMOX_AESSMALL_CTR_ENC_ALGO

#define AUTH_HEADER_SIZE 16

/* Private variables ---------------------------------------------------------*/

static CRYP_HandleTypeDef hcryp;
static const char auth_header[] = "0123456789ABCDEF";

/* Public functions ----------------------------------------------------------*/

void aes_init(void) {
#ifdef SW_AES

    if (cmox_initialize(NULL) != CMOX_INIT_SUCCESS) {
        assert(false);
    }

#else

#ifdef __HAL_RCC_AES_CLK_ENABLE
    __HAL_RCC_AES_CLK_ENABLE();
    __HAL_RCC_AES_FORCE_RESET();
    __HAL_RCC_AES_RELEASE_RESET();

    hcryp.Instance = AES;
    if (HAL_CRYP_DeInit(&hcryp) != HAL_OK) {
        assert(false);
    }
#endif

#endif
}

#ifdef SW_AES
bool aes_ctr_encrypt(uint8_t* key, uint8_t* init_vector, const uint8_t* plain_data, uint32_t length, uint8_t* cipher_data) {
    cmox_cipher_retval_t retval;
    size_t computed_size;

    retval = cmox_cipher_encrypt(ALGO,
            plain_data, length,
            key, AES_SIZE,
            init_vector, AES_SIZE,
            cipher_data, &computed_size);

    /* Verify API returned value */
    if (retval != CMOX_CIPHER_SUCCESS) {
        assert(false);
    }

    /* Verify generated data size is the expected one */
    if (computed_size != length) {
        assert(false);
    }
    return true;
}

#else

bool aes_ctr_encrypt(uint8_t* key, uint8_t* init_vector, const uint8_t* plain_data, uint32_t length, uint8_t* cipher_data) {
    hcryp.Init.DataType = CRYP_DATATYPE_8B;
    hcryp.Init.KeySize  = CRYP_KEYSIZE_128B;
    hcryp.Init.pKey = key;
    hcryp.Init.pInitVect = init_vector;

    return HAL_CRYP_AESCTR_Encrypt(&hcryp, plain_data, length, cipher_data, HAL_MAX_DELAY) == HAL_OK;
}

bool aes_gcm_encrypt(uint8_t* key, uint8_t* init_vector, const uint8_t* plain_data, uint32_t length, uint8_t* cipher_data, uint8_t* mic)
{
    hcryp.Init.DataType      = CRYP_DATATYPE_8B;
    hcryp.Init.KeySize       = CRYP_KEYSIZE_128B;
    hcryp.Init.pKey          = key;
    hcryp.Init.OperatingMode = CRYP_ALGOMODE_ENCRYPT;
    hcryp.Init.ChainingMode  = CRYP_CHAINMODE_AES_GCM_GMAC;
    hcryp.Init.GCMCMACPhase  = CRYP_GCM_INIT_PHASE;
    hcryp.Init.KeyWriteFlag  = CRYP_KEY_WRITE_DISABLE;
    hcryp.Init.pInitVect     = init_vector;
    hcryp.Init.Header        = auth_header;
    hcryp.Init.HeaderSize    = AUTH_HEADER_SIZE;

    if (HAL_CRYP_Init(&hcryp) != HAL_OK) {
        return false;
    }

    /* GCM init phase */
    if (HAL_CRYPEx_AES_Auth(&hcryp, NULL, 0, NULL, HAL_MAX_DELAY) != HAL_OK) {
        return false;
    }

    hcryp.Init.GCMCMACPhase  = CRYP_GCMCMAC_HEADER_PHASE;
    if (HAL_CRYPEx_AES_Auth(&hcryp, NULL, 0, NULL, HAL_MAX_DELAY) != HAL_OK) {
        return false;
    }

    hcryp.Init.GCMCMACPhase  = CRYP_GCM_PAYLOAD_PHASE;
    if (HAL_CRYPEx_AES_Auth(&hcryp, plain_data, length, cipher_data, HAL_MAX_DELAY) != HAL_OK) {
        return false;
    }

    hcryp.Init.GCMCMACPhase  = CRYP_GCMCMAC_FINAL_PHASE;
    if (HAL_CRYPEx_AES_Auth(&hcryp, NULL, length, mic, HAL_MAX_DELAY) != HAL_OK)
    {
        return false;
    }
    return true;
}

bool aes_gcm_decrypt(uint8_t* key, uint8_t* init_vector, const uint8_t* cipher_data, uint32_t length, uint8_t* plain_data, uint8_t* mic)
{
    hcryp.Init.DataType      = CRYP_DATATYPE_8B;
    hcryp.Init.KeySize       = CRYP_KEYSIZE_128B;
    hcryp.Init.pKey          = key;
    hcryp.Init.OperatingMode = CRYP_ALGOMODE_DECRYPT;
    hcryp.Init.ChainingMode  = CRYP_CHAINMODE_AES_GCM_GMAC;
    hcryp.Init.GCMCMACPhase  = CRYP_GCM_INIT_PHASE;
    hcryp.Init.KeyWriteFlag  = CRYP_KEY_WRITE_DISABLE;
    hcryp.Init.pInitVect     = init_vector;
    hcryp.Init.Header        = auth_header;
    hcryp.Init.HeaderSize    = AUTH_HEADER_SIZE;

    if (HAL_CRYP_Init(&hcryp) != HAL_OK) {
        return false;
    }

    /* GCM init phase */
    if (HAL_CRYPEx_AES_Auth(&hcryp, NULL, 0, NULL, HAL_MAX_DELAY) != HAL_OK) {
        return false;
    }

    hcryp.Init.GCMCMACPhase  = CRYP_GCMCMAC_HEADER_PHASE;
    if (HAL_CRYPEx_AES_Auth(&hcryp, NULL, 0, NULL, HAL_MAX_DELAY) != HAL_OK) {
        return false;
    }

    hcryp.Init.GCMCMACPhase  = CRYP_GCM_PAYLOAD_PHASE;
    if (HAL_CRYPEx_AES_Auth(&hcryp, cipher_data, length, plain_data, HAL_MAX_DELAY) != HAL_OK) {
        return false;
    }

    hcryp.Init.GCMCMACPhase  = CRYP_GCMCMAC_FINAL_PHASE;
    if (HAL_CRYPEx_AES_Auth(&hcryp, NULL, length, mic, HAL_MAX_DELAY) != HAL_OK) {
        return false;
    }
    return true;
}

#endif
