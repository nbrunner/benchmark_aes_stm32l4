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

/* Private typedef -----------------------------------------------------------*/

/* Private define ------------------------------------------------------------*/
#define KEY "0123456789ABCDEF"
//#define INIT_VECTOR "0123456789abcdef"

#define LENGTH 256

/* Private macro -------------------------------------------------------------*/

/* Private variables ---------------------------------------------------------*/

const uint8_t INIT_VECTOR[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x00, 0x00, 0x00, 0x00//, 0x0c, 0x0d, 0x0e, 0x0f
};

static uint8_t plain_data[LENGTH + 16];
static uint8_t cipher_data[LENGTH + 16];
static uint8_t mic[16];

/* Private function prototypes -----------------------------------------------*/

void SystemClock_Config(void);
static char hex_to_str(uint8_t hex);
static void send_hex_data(uint8_t* data, size_t length);

/* Private user code ---------------------------------------------------------*/

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{
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
        result = aes_hw_ctr_encrypt(KEY, INIT_VECTOR, plain_data, LENGTH, cipher_data);
        t1 = DWT->CYCCNT;
        t = t1 - t0 - measure_delay;

        sprintf(text, "\nctr: t = %lu, r = %i\n", t, result);
        HAL_UART_Transmit(&hlpuart1, text, strlen(text), HAL_MAX_DELAY);
        send_hex_data(cipher_data, LENGTH);


        t0 = DWT->CYCCNT;
        result = aes_hw_gcm_encrypt(KEY, INIT_VECTOR, plain_data, LENGTH, cipher_data, mic);
        t1 = DWT->CYCCNT;
        t = t1 - t0 - measure_delay;

        sprintf(text, "\ngcm_e: t = %lu, r = %i\n", t, result);
        HAL_UART_Transmit(&hlpuart1, text, strlen(text), HAL_MAX_DELAY);
        send_hex_data(cipher_data, LENGTH);
        HAL_UART_Transmit(&hlpuart1, "\n", 1, HAL_MAX_DELAY);
        send_hex_data(mic, 16);

        t0 = DWT->CYCCNT;
        result = aes_hw_gcm_decrypt(KEY, INIT_VECTOR, cipher_data, LENGTH, plain_data, mic);
        t1 = DWT->CYCCNT;
        t = t1 - t0 - measure_delay;

        sprintf(text, "\ngcm_d: t = %lu, r = %i\n", t, result);
        HAL_UART_Transmit(&hlpuart1, text, strlen(text), HAL_MAX_DELAY);
        send_hex_data(plain_data, LENGTH);
        HAL_UART_Transmit(&hlpuart1, "\n", 1, HAL_MAX_DELAY);
        send_hex_data(mic, 16);





        t0 = DWT->CYCCNT;
        result = aes_sw_ctr_encrypt(KEY, INIT_VECTOR, plain_data, LENGTH, cipher_data);
        t1 = DWT->CYCCNT;
        t = t1 - t0 - measure_delay;

        sprintf(text, "\nctr_sw: t = %lu, r = %i\n", t, result);
        HAL_UART_Transmit(&hlpuart1, text, strlen(text), HAL_MAX_DELAY);
        send_hex_data(cipher_data, LENGTH);


        t0 = DWT->CYCCNT;
        result = aes_sw_gcm_encrypt(KEY, INIT_VECTOR, plain_data, LENGTH, cipher_data, mic);
        t1 = DWT->CYCCNT;
        t = t1 - t0 - measure_delay;

        sprintf(text, "\ngcm_sw_e: t = %lu, r = %i\n", t, result);
        HAL_UART_Transmit(&hlpuart1, text, strlen(text), HAL_MAX_DELAY);
        send_hex_data(cipher_data, LENGTH);
        HAL_UART_Transmit(&hlpuart1, "\n", 1, HAL_MAX_DELAY);
        send_hex_data(&cipher_data[256], 16);
        //      send_hex_data(mic, 16);

        t0 = DWT->CYCCNT;
        result = aes_sw_gcm_decrypt(KEY, INIT_VECTOR, cipher_data, LENGTH, plain_data, mic);
        t1 = DWT->CYCCNT;
        t = t1 - t0 - measure_delay;

        sprintf(text, "\ngcm_sw_d: t = %lu, r = %i\n", t, result);
        HAL_UART_Transmit(&hlpuart1, text, strlen(text), HAL_MAX_DELAY);
        send_hex_data(plain_data, LENGTH);
        HAL_UART_Transmit(&hlpuart1, "\n", 1, HAL_MAX_DELAY);
        //      send_hex_data(mic, 16);
        //      send_hex_data(&cipher_data[256], 16);
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

static void send_hex_data(uint8_t* data, size_t length)
{
	uint8_t hex[2*LENGTH+32];
	for (int i = 0; i < length; i++) {
		hex[2*i] = hex_to_str((data[i] & 0xF0) >> 4);
		hex[2*i + 1] = hex_to_str(data[i] & 0x0F);
	}
	HAL_UART_Transmit(&hlpuart1, hex, 2*length, HAL_MAX_DELAY);
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
