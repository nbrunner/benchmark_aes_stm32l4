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

#include "aes_hw.h"

/* Private define ------------------------------------------------------------*/

#define AES_SIZE 16 // 128 bits
#define AUTH_HEADER_SIZE 16

/* Private variables ---------------------------------------------------------*/

static CRYP_HandleTypeDef hcryp;
static const char auth_header[] = "0123456789ABCDEF";

/* Public functions ----------------------------------------------------------*/

void aes_hw_init(void) {
    __HAL_RCC_AES_CLK_ENABLE();
    __HAL_RCC_AES_FORCE_RESET();
    __HAL_RCC_AES_RELEASE_RESET();

    hcryp.Instance = AES;
    if (HAL_CRYP_DeInit(&hcryp) != HAL_OK) {
        assert(false);
    }
}

bool aes_hw_ctr_encrypt(uint8_t* key, uint8_t* init_vector, const uint8_t* plain_data, uint32_t length, uint8_t* cipher_data) {
    hcryp.Init.DataType = CRYP_DATATYPE_8B;
    hcryp.Init.KeySize  = CRYP_KEYSIZE_128B;
    hcryp.Init.pKey = key;
    hcryp.Init.pInitVect = init_vector;

    return HAL_CRYP_AESCTR_Encrypt(&hcryp, plain_data, length, cipher_data, HAL_MAX_DELAY) == HAL_OK;
}

bool aes_hw_gcm_encrypt(uint8_t* key, uint8_t* init_vector, const uint8_t* plain_data, uint32_t length, uint8_t* cipher_data, uint8_t* mic)
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

bool aes_hw_gcm_decrypt(uint8_t* key, uint8_t* init_vector, const uint8_t* cipher_data, uint32_t length, uint8_t* plain_data, uint8_t* mic)
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
