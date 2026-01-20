#include <stdint.h>
#include <stdio.h>

extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss;
extern void __libc_init_array(void);
volatile uint32_t systick_ms = 0;

#define RCC_BASE          0x46020C00u
#define RCC_AHB2ENR1      (*(volatile uint32_t *)(RCC_BASE + 0x88u))
#define RCC_APB1ENR1      (*(volatile uint32_t *)(RCC_BASE + 0x98u))
#define RCC_APB2ENR       (*(volatile uint32_t *)(RCC_BASE + 0xA4u))
#define GPIOA_BASE        0x42020000u
#define GPIO_MODER(x)     (*(volatile uint32_t *)((x) + 0x00u))
#define GPIO_OSPEEDR(x)   (*(volatile uint32_t *)((x) + 0x08u))
#define GPIO_AFRH(x)      (*(volatile uint32_t *)((x) + 0x24u))
#define USART1_BASE       0x40013800u
#define USART_CR1(b)      (*(volatile uint32_t *)((b) + 0x00u))
#define USART_BRR(b)      (*(volatile uint32_t *)((b) + 0x0Cu))
#define USART_ISR(b)      (*(volatile uint32_t *)((b) + 0x1Cu))
#define USART_TDR(b)      (*(volatile uint32_t *)((b) + 0x28u))
#define USART_CR1_UE      (1u << 0)
#define USART_CR1_TE      (1u << 3)
#define USART_ISR_TXE     (1u << 7)

void usart1_putc(char c) {
    while (!(USART_ISR(USART1_BASE) & USART_ISR_TXE));
    USART_TDR(USART1_BASE) = (uint32_t)c;
}

void Reset_Handler(void) {
    uint32_t *src = &_sidata, *dst = &_sdata;
    while (dst < &_edata) *dst++ = *src++;
    for (dst = &_sbss; dst < &_ebss;) *dst++ = 0;
    __libc_init_array();

    RCC_AHB2ENR1 |= (1u << 0);
    RCC_APB2ENR |= (1u << 14);
    uint32_t v = GPIO_MODER(GPIOA_BASE);
    v &= ~((3u << 18) | (3u << 20));
    v |= (2u << 18) | (2u << 20);
    GPIO_MODER(GPIOA_BASE) = v;
    v = GPIO_OSPEEDR(GPIOA_BASE);
    v &= ~((3u << 18) | (3u << 20));
    v |= (2u << 18) | (2u << 20);
    GPIO_OSPEEDR(GPIOA_BASE) = v;
    v = GPIO_AFRH(GPIOA_BASE);
    v &= ~((0xFu << 4) | (0xFu << 8));
    v |= (7u << 4) | (7u << 8);
    GPIO_AFRH(GPIOA_BASE) = v;
    USART_BRR(USART1_BASE) = 64000000u / 115200u;
    USART_CR1(USART1_BASE) = USART_CR1_UE | USART_CR1_TE;

    printf("Hello from TA-100 test!\n");
    __asm volatile("bkpt #0x7F");
    while (1);
}
