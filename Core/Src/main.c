/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2024 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */

/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "usart.h"
#include "gpio.h"

/* Private includes ----------------------------------------------------------*/

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "aes_hw.h"
#include "aes_sw.h"
#include "cmox_crypto.h"

/* Private typedef -----------------------------------------------------------*/

/* Private define ------------------------------------------------------------*/

#define AES_SIZE 16 // 128 bits
#define LENGTH 256
#define MIC_SIZE 16
#define CIPHER_IV_SIZE 16 // 128 bits
#define AEAD_IV_SIZE 12 // 96 bits
#define AUTH_HEADER_SIZE 16

#define CIPHER_NUMBER 10
#define AEAD_NUMBER 7

#define SEND_DATA

/* Private macro -------------------------------------------------------------*/

/* Private variables ---------------------------------------------------------*/

static const uint8_t init_vector[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t key[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static const uint8_t auth_header[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static uint8_t plain_data[LENGTH + MIC_SIZE];
static uint8_t cipher_data[LENGTH + MIC_SIZE];
static uint8_t mic[MIC_SIZE];

static char* cipher_names[CIPHER_NUMBER] = {
        "CMOX_AESFAST_ECB",
        "CMOX_AESFAST_CBC",
        "CMOX_AESFAST_CTR",
        "CMOX_AESFAST_CFB",
        "CMOX_AESFAST_OFB",
        "CMOX_AESSMALL_ECB",
        "CMOX_AESSMALL_CBC",
        "CMOX_AESSMALL_CTR",
        "CMOX_AESSMALL_CFB",
        "CMOX_AESSMALL_OFB",
};

static char* aead_names[AEAD_NUMBER] = {
        "CMOX_AESFAST_GCMFAST",
        "CMOX_AESFAST_GCMSMALL",
        "CMOX_AESSMALL_GCMFAST",
        "CMOX_AESSMALL_GCMSMALL",
        "CMOX_AESFAST_CCM",
        "CMOX_AESSMALL_CCM",
        "CMOX_CHACHAPOLY",
};

/* Private function prototypes -----------------------------------------------*/

void SystemClock_Config(void);
static char hex_to_str(uint8_t hex);
static void send_hex_data(const uint8_t* data, size_t length);
static void send_text(const char* text);
static void send_result(const char* text, const uint8_t* data, const uint8_t* mic);

/* Private user code ---------------------------------------------------------*/

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
    cmox_cipher_algo_t cipher_encs[CIPHER_NUMBER] = {
            CMOX_AESFAST_ECB_ENC_ALGO,
            CMOX_AESFAST_CBC_ENC_ALGO,
            CMOX_AESFAST_CTR_ENC_ALGO,
            CMOX_AESFAST_CFB_ENC_ALGO,
            CMOX_AESFAST_OFB_ENC_ALGO,
            CMOX_AESSMALL_ECB_ENC_ALGO,
            CMOX_AESSMALL_CBC_ENC_ALGO,
            CMOX_AESSMALL_CTR_ENC_ALGO,
            CMOX_AESSMALL_CFB_ENC_ALGO,
            CMOX_AESSMALL_OFB_ENC_ALGO,
    };

    cmox_cipher_algo_t cipher_decs[CIPHER_NUMBER] = {
            CMOX_AESFAST_ECB_DEC_ALGO,
            CMOX_AESFAST_CBC_DEC_ALGO,
            CMOX_AESFAST_CTR_DEC_ALGO,
            CMOX_AESFAST_CFB_DEC_ALG,
            CMOX_AESFAST_OFB_DEC_ALGO,
            CMOX_AESSMALL_ECB_DEC_ALGO,
            CMOX_AESSMALL_CBC_DEC_ALGO,
            CMOX_AESSMALL_CTR_DEC_ALGO,
            CMOX_AESSMALL_CFB_DEC_ALGO,
            CMOX_AESSMALL_OFB_DEC_ALGO,
    };

    cmox_aead_algo_t aead_encs[AEAD_NUMBER] = {
            CMOX_AESFAST_GCMFAST_ENC_ALGO,
            CMOX_AESFAST_GCMSMALL_ENC_ALGO,
            CMOX_AESSMALL_GCMFAST_ENC_ALGO,
            CMOX_AESSMALL_GCMSMALL_ENC_ALGO,
            CMOX_AESFAST_CCM_ENC_ALGO,
            CMOX_AESSMALL_CCM_ENC_ALGO,
            CMOX_CHACHAPOLY_ENC_ALGO,
    };

    cmox_aead_algo_t aead_decs[AEAD_NUMBER] = {
            CMOX_AESFAST_GCMFAST_DEC_ALGO,
            CMOX_AESFAST_GCMSMALL_DEC_ALGO,
            CMOX_AESSMALL_GCMFAST_DEC_ALGO,
            CMOX_AESSMALL_GCMSMALL_DEC_ALGO,
            CMOX_AESFAST_CCM_DEC_ALGO,
            CMOX_AESSMALL_CCM_DEC_ALGO,
            CMOX_CHACHAPOLY_DEC_ALGO,
    };

    /* MCU Configuration--------------------------------------------------------*/

    /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
    HAL_Init();

    SystemClock_Config();

    /* Initialize all configured peripherals */
    MX_GPIO_Init();
    MX_LPUART1_UART_Init();

    // for counting cycle, init
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    ITM->LAR = 0xC5ACCE55; // only for CM7 ?
    DWT->CYCCNT = 0;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;

    uint32_t t0;
    uint32_t t1;
    uint32_t measure_delay;
    uint32_t t;
    char text[256];

    t0 = DWT->CYCCNT;
    t1 = DWT->CYCCNT;
    measure_delay = t1 - t0;

    memset(plain_data, 0, LENGTH);

    for (int i = 0; i < LENGTH; i++) {
        plain_data[i] = i;
    }

    aes_hw_init();
    aes_sw_init();

    bool result;
    while (1) {
        HAL_Delay(1000);


        t0 = DWT->CYCCNT;
        result = aes_hw_ctr_encrypt(key, init_vector, plain_data, LENGTH, cipher_data);
        t1 = DWT->CYCCNT;
        t = t1 - t0 - measure_delay;

        sprintf(text, "aes_hw_ctr_enc: t = %lu, result = %i\n", t, result);
        send_result(text, cipher_data, NULL);


        t0 = DWT->CYCCNT;
        result = aes_hw_gcm_encrypt(key, init_vector, plain_data, LENGTH, cipher_data, mic);
        t1 = DWT->CYCCNT;
        t = t1 - t0 - measure_delay;

        sprintf(text, "aes_hw_gcm_enc: t = %lu, result = %i\n", t, result);
        send_result(text, cipher_data, mic);


        t0 = DWT->CYCCNT;
        result = aes_hw_gcm_decrypt(key, init_vector, cipher_data, LENGTH, plain_data, mic);
        t1 = DWT->CYCCNT;
        t = t1 - t0 - measure_delay;

        sprintf(text, "aes_hw_gcm_dec: t = %lu, result = %i\n", t, result);
        send_result(text, plain_data, mic);



        for (int i = 0; i < CIPHER_NUMBER; i++) {
            cmox_cipher_retval_t retval;
            size_t key_size = 16;

            t0 = DWT->CYCCNT;
            retval = cmox_cipher_encrypt(cipher_encs[i],
                    plain_data, LENGTH,
                    key, key_size,
                    init_vector, CIPHER_IV_SIZE,
                    cipher_data, NULL);
            t1 = DWT->CYCCNT;
            t = t1 - t0 - measure_delay;
            result = retval == CMOX_CIPHER_SUCCESS;

            sprintf(text, "%s_enc: t = %lu, result = %i\n", cipher_names[i], t, result);
            send_result(text, cipher_data, NULL);

            t0 = DWT->CYCCNT;
            retval = cmox_cipher_decrypt(cipher_decs[i],
                    cipher_data, LENGTH,
                    key, key_size,
                    init_vector, CIPHER_IV_SIZE,
                    plain_data, NULL);
            t1 = DWT->CYCCNT;
            t = t1 - t0 - measure_delay;
            result = retval == CMOX_CIPHER_SUCCESS;

            sprintf(text, "%s_dec: t = %lu, result = %i\n", cipher_names[i], t, result);
            send_result(text, plain_data, NULL);
        }

        for (int i = 0; i < AEAD_NUMBER; i++) {
            cmox_cipher_retval_t retval;
            size_t key_size = aead_encs[i] == CMOX_CHACHAPOLY_ENC_ALGO ? 32 : 16;

            t0 = DWT->CYCCNT;
            retval = cmox_aead_encrypt(aead_encs[i],
                    plain_data, LENGTH,
                    MIC_SIZE,
                    key, key_size,
                    init_vector, AEAD_IV_SIZE,
                    auth_header, AUTH_HEADER_SIZE,
                    cipher_data, NULL);
            t1 = DWT->CYCCNT;
            t = t1 - t0 - measure_delay;
            result = retval == CMOX_CIPHER_SUCCESS;

            sprintf(text, "%s_enc: t = %lu, result = %i\n", aead_names[i], t, result);
            send_result(text, cipher_data, mic);

            t0 = DWT->CYCCNT;
            retval = cmox_aead_decrypt(aead_decs[i],
                    cipher_data, LENGTH + MIC_SIZE,
                    MIC_SIZE,
                    key, key_size,
                    init_vector, AEAD_IV_SIZE,
                    auth_header, AUTH_HEADER_SIZE,
                    plain_data, NULL);
            t1 = DWT->CYCCNT;
            t = t1 - t0 - measure_delay;
            result = retval == CMOX_CIPHER_AUTH_SUCCESS;

            sprintf(text, "%s_dec: t = %lu, result = %i\n", aead_names[i], t, result);
            send_result(text, plain_data, mic);
        }
    }
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
    RCC_OscInitTypeDef RCC_OscInitStruct = {0};
    RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

    /** Configure the main internal regulator output voltage
     */
    if (HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1) != HAL_OK)
    {
        Error_Handler();
    }

    /** Initializes the RCC Oscillators according to the specified parameters
     * in the RCC_OscInitTypeDef structure.
     */
    RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
    RCC_OscInitStruct.HSIState = RCC_HSI_ON;
    RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
    RCC_OscInitStruct.PLL.PLLState = RCC_PLL_NONE;
    if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
    {
        Error_Handler();
    }

    /** Initializes the CPU, AHB and APB buses clocks
     */
    RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
            |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
    RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_HSI;
    RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
    RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
    RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

    if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_0) != HAL_OK)
    {
        Error_Handler();
    }
}

static char hex_to_str(uint8_t hex)
{
	if (hex < 10) {
		return '0' + hex;
	} else {
		return 'A' + hex - 10;
	}
}

static void send_hex_data(const uint8_t* data, size_t length)
{
	uint8_t hex[2 * (LENGTH + MIC_SIZE)];
	for (int i = 0; i < length; i++) {
		hex[2*i] = hex_to_str((data[i] & 0xF0) >> 4);
		hex[2*i + 1] = hex_to_str(data[i] & 0x0F);
	}
	HAL_UART_Transmit(&hlpuart1, hex, 2*length, HAL_MAX_DELAY);
}

static void send_text(const char* text)
{
    HAL_UART_Transmit(&hlpuart1, (const uint8_t*)text, strlen(text), HAL_MAX_DELAY);
}

static void send_result(const char* text, const uint8_t* data, const uint8_t* mic)
{
    send_text(text);
#ifdef SEND_DATA
    send_hex_data(data, LENGTH);
    if (mic != NULL) {
        send_text("\nMIC = ");
        send_hex_data(mic, 16);
    }
    send_text("\n\n");
#endif
}


/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
    /* USER CODE BEGIN Error_Handler_Debug */
    /* User can add his own implementation to report the HAL error return state */
    __disable_irq();
    while (1)
    {
    }
    /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
    /* USER CODE BEGIN 6 */
    /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
    /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
