#include <stdint.h>

#ifndef BENCH_ITERS
#define BENCH_ITERS (5000000u)
#endif

extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss;

static volatile uint32_t sink;

/* Small PRNG for unpredictable-ish branches */
static inline uint32_t xorshift32(uint32_t x) {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
}

__attribute__((noinline))
static uint32_t bench_branchy(uint32_t iters) {
    uint32_t x = 0x12345678u;
    uint32_t a = 1u;
    uint32_t b = 0x9E3779B9u;

    for (uint32_t i = 0; i < iters; i++) {
        x = xorshift32(x);
        /* ~50/50 branch direction */
        if (x & 1u) a += b;
        else        a ^= b;

        /* mix in some data deps */
        b += (a ^ (x >> 3));
    }
    return a ^ b ^ x;
}

__attribute__((noinline))
static uint32_t bench_mem(uint32_t iters) {
    /* small hot array to exercise loads/stores */
    static uint32_t buf[256];
    uint32_t acc = 0;

    for (uint32_t i = 0; i < iters; i++) {
        uint32_t idx = (i * 17u) & 255u;
        uint32_t v   = buf[idx];
        acc += (v ^ (idx << 16));
        buf[idx] = acc + 0xA5A5A5A5u;
    }
    return acc;
}

int main(void) {
    uint32_t v = 0;

    /* tune these ratios as you like */
    v ^= bench_branchy(BENCH_ITERS);
    v ^= bench_mem(BENCH_ITERS / 4u);

    sink = v;

    __asm volatile("bkpt #0x7f"); /* PASS */
    for (;;) { __asm volatile("wfi"); }
}

void Reset_Handler(void) {
    /* Copy .data */
    uint32_t *src = &_sidata;
    for (uint32_t *dst = &_sdata; dst < &_edata; ) {
        *dst++ = *src++;
    }
    /* Zero .bss */
    for (uint32_t *dst = &_sbss; dst < &_ebss; ) {
        *dst++ = 0u;
    }

    (void)main();
    for (;;) { }
}

void HardFault_Handler(void) { __asm volatile("bkpt #0x7e"); for(;;){} }
void UsageFault_Handler(void){ __asm volatile("bkpt #0x7e"); for(;;){} }
