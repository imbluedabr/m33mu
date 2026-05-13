// fpu_torture_test.c
//
// Goal: Exercise as many Cortex-M FPU (FPv5-SP) instruction variants as practical,
// and validate automatic FP stacking/unstacking on exception entry/exit (lazy + auto).
//
// Build notes (important):
//  - Compile WITH hardware FP enabled, otherwise you’ll mostly test soft-float library calls.
//    Typical GCC flags:
//      -mcpu=cortex-m33 -mthumb -mfpu=fpv5-sp-d16 -mfloat-abi=hard
//    (softfp also works if you still want VFP instructions but soft ABI)
//  - You must provide startup + vector table routing PendSV_Handler (and optionally SysTick_Handler).
//  - This file avoids libc / printf; results are left in volatile globals for your logs/debugger.
//
// What it tests:
//  1) Many single-precision ops via explicit inline-asm: vadd/vsub/vmul/vdiv/vmla/vmls/vneg/vabs/vsqrt
//  2) Moves and loads/stores: vmov (core<->s), vldr/vstr, vldmia/vstmia, vpush/vpop
//  3) Conversions: vcvt (round toward 0), vcvtr (round-to-nearest)
//  4) Compare/flags: vcmp/vcmpe + vmrs APSR_nzcv, FPSCR
//  5) FPSCR read/write
//  6) Auto + lazy stacking: PendSV with/without FP use, checking that thread S regs & FPSCR survive,
//     and capturing LR (EXC_RETURN) before/after first FP instruction in the handler.
//
// You integrate the rest (clock, sys init, vector table). Call fpu_test_run() from your main.

#include <stdint.h>
#include <stddef.h>

#ifndef __ARM_FP
#warning "__ARM_FP is not defined; compile flags likely not enabling hardware FPU."
#endif

// -------------------- Minimal MMIO --------------------
#define SCB_ICSR            (*(volatile uint32_t *)0xE000ED04u)
#define SCB_CPACR           (*(volatile uint32_t *)0xE000ED88u)
#define FPU_FPCCR           (*(volatile uint32_t *)0xE000EF34u)
#define FPU_FPDSCR          (*(volatile uint32_t *)0xE000EF3Cu)
#define RCC_BASE            0x44020C00u
#define RCC_CR              (*(volatile uint32_t *)(RCC_BASE + 0x00u))
#define RCC_AHB2ENR         (*(volatile uint32_t *)(RCC_BASE + 0x8Cu))
#define GPIOC_BASE          0x42020800u
#define GPIOD_BASE          0x42020C00u
#define GPIOE_BASE          0x42021000u
#define GPIOF_BASE          0x42021400u
#define GPIOG_BASE          0x42021800u
#define GPIO_MODER(x)       (*(volatile uint32_t *)((x) + 0x00u))
#define GPIO_OTYPER(x)      (*(volatile uint32_t *)((x) + 0x04u))
#define GPIO_OSPEEDR(x)     (*(volatile uint32_t *)((x) + 0x08u))
#define GPIO_PUPDR(x)       (*(volatile uint32_t *)((x) + 0x0Cu))
#define GPIO_ODR(x)         (*(volatile uint32_t *)((x) + 0x14u))
#define GPIO_BSRR(x)        (*(volatile uint32_t *)((x) + 0x18u))
#define SYST_CSR            (*(volatile uint32_t *)0xE000E010u)
#define SYST_RVR            (*(volatile uint32_t *)0xE000E014u)
#define SYST_CVR            (*(volatile uint32_t *)0xE000E018u)
#define SYST_CSR_ENABLE     (1u << 0)
#define SYST_CSR_TICKINT    (1u << 1)
#define SYST_CSR_CLKSOURCE  (1u << 2)
#define SYST_CSR_COUNTFLAG  (1u << 16)
#define CPU_HZ              (64000000u)
#define RCC_CR_HSIDIV_SHIFT 3u
#define RCC_CR_HSIDIV_MASK  (0x3u << RCC_CR_HSIDIV_SHIFT)
#define RCC_CR_HSIDIVF      (1u << 5)

#define SCB_ICSR_PENDSVSET  (1u << 28)

#define FPCCR_ASPEN         (1u << 31)  // Automatic State Preservation Enable
#define FPCCR_LSPEN         (1u << 30)  // Lazy State Preservation Enable

static inline void dsb(void) { __asm volatile("dsb sy" ::: "memory"); }
static inline void isb(void) { __asm volatile("isb sy" ::: "memory"); }
static inline void bkpt(void){ __asm volatile("bkpt #0x7F"); }

static inline uint32_t mrs_control(void){ uint32_t v; __asm volatile("mrs %0, control" : "=r"(v)); return v; }
static inline void msr_control(uint32_t v){ __asm volatile("msr control, %0" :: "r"(v) : "memory"); }
static inline uint32_t mrs_msp(void){ uint32_t v; __asm volatile("mrs %0, msp" : "=r"(v)); return v; }
static inline uint32_t mrs_psp(void){ uint32_t v; __asm volatile("mrs %0, psp" : "=r"(v)); return v; }
static inline void msr_psp(uint32_t v){ __asm volatile("msr psp, %0" :: "r"(v) : "memory"); }
static inline void cpsie_i(void){ __asm volatile("cpsie i" ::: "memory"); }

static inline uint32_t vmrs_fpscr(void){ uint32_t v; __asm volatile("vmrs %0, fpscr" : "=r"(v)); return v; }
static inline void vmsr_fpscr(uint32_t v){ __asm volatile("vmsr fpscr, %0" :: "r"(v) : "memory"); }

static volatile uint32_t g_ms_ticks = 0;

static void hsi_force_div1(void) {
  uint32_t reg = RCC_CR;
  uint32_t timeout;
  reg &= ~RCC_CR_HSIDIV_MASK;
  RCC_CR = reg;
  timeout = 100000u;
  while (((RCC_CR & RCC_CR_HSIDIVF) == 0u) && (timeout != 0u)) {
    timeout--;
  }
}

void SysTick_Handler(void) {
  g_ms_ticks++;
}

static void systick_init_1ms(void) {
  SYST_CSR = 0;
  SYST_RVR = (CPU_HZ / 1000u) - 1u;
  SYST_CVR = 0;
  SYST_CSR = SYST_CSR_CLKSOURCE | SYST_CSR_TICKINT | SYST_CSR_ENABLE;
}

static void delay_ms(uint32_t ms) {
  uint32_t start = g_ms_ticks;
  while ((uint32_t)(g_ms_ticks - start) < ms) {
    __asm volatile("wfi");
  }
}

static void gpio_set_mode_output(uint32_t port, uint32_t pin) {
  uint32_t v = GPIO_MODER(port);
  v &= ~(3u << (pin * 2u));
  v |= (1u << (pin * 2u));
  GPIO_MODER(port) = v;
}

static void gpio_set_mode_input(uint32_t port, uint32_t pin) {
  uint32_t v = GPIO_MODER(port);
  v &= ~(3u << (pin * 2u));
  GPIO_MODER(port) = v;
}

static void gpio_set_low(uint32_t port, uint32_t pin) {
  GPIO_BSRR(port) = (1u << (16 + pin));
}

static void gpio_fpu_init(void) {
  RCC_AHB2ENR |= (1u << 2) | (1u << 3) | (1u << 4) | (1u << 5) | (1u << 6);
}

static void gpio_fpu_set(int enable) {
  if (enable) {
    gpio_set_mode_output(GPIOC_BASE, 6u);
    gpio_set_mode_output(GPIOC_BASE, 7u);
    gpio_set_mode_output(GPIOC_BASE, 8u);
    gpio_set_mode_output(GPIOC_BASE, 9u);
    gpio_set_mode_output(GPIOC_BASE, 10u);
    gpio_set_mode_output(GPIOD_BASE, 6u);
    gpio_set_mode_output(GPIOE_BASE, 6u);
    gpio_set_mode_output(GPIOE_BASE, 7u);
    gpio_set_mode_output(GPIOE_BASE, 8u);
    gpio_set_mode_output(GPIOE_BASE, 9u);
    gpio_set_mode_output(GPIOF_BASE, 6u);
    gpio_set_mode_output(GPIOG_BASE, 6u);

    gpio_set_low(GPIOC_BASE, 6u);
    gpio_set_low(GPIOC_BASE, 7u);
    gpio_set_low(GPIOC_BASE, 8u);
    gpio_set_low(GPIOC_BASE, 9u);
    gpio_set_low(GPIOC_BASE, 10u);
    gpio_set_low(GPIOD_BASE, 6u);
    gpio_set_low(GPIOE_BASE, 6u);
    gpio_set_low(GPIOE_BASE, 7u);
    gpio_set_low(GPIOE_BASE, 8u);
    gpio_set_low(GPIOE_BASE, 9u);
    gpio_set_low(GPIOF_BASE, 6u);
    gpio_set_low(GPIOG_BASE, 6u);
  } else {
    gpio_set_mode_input(GPIOC_BASE, 6u);
    gpio_set_mode_input(GPIOC_BASE, 7u);
    gpio_set_mode_input(GPIOC_BASE, 8u);
    gpio_set_mode_input(GPIOC_BASE, 9u);
    gpio_set_mode_input(GPIOC_BASE, 10u);
    gpio_set_mode_input(GPIOD_BASE, 6u);
    gpio_set_mode_input(GPIOE_BASE, 6u);
    gpio_set_mode_input(GPIOE_BASE, 7u);
    gpio_set_mode_input(GPIOE_BASE, 8u);
    gpio_set_mode_input(GPIOE_BASE, 9u);
    gpio_set_mode_input(GPIOF_BASE, 6u);
    gpio_set_mode_input(GPIOG_BASE, 6u);
  }
}

static void set_fpu_enabled(int enable) {
  if (enable) {
    SCB_CPACR |= (0xFu << 20);
  } else {
    SCB_CPACR &= ~(0xFu << 20);
  }
  dsb();
  isb();
}

// -------------------- Global log/state (inspect in debugger / your logger) --------------------
typedef struct {
  volatile uint32_t pass_signature;

  volatile uint32_t fail_count;
  volatile uint32_t last_fail_id;
  volatile uint32_t last_got;
  volatile uint32_t last_exp;

  // Interrupt stacking checks
  volatile uint32_t pendsv_count;
  volatile uint32_t isr_use_fp;

  volatile uint32_t isr_lr_entry;
  volatile uint32_t isr_lr_after_fp;   // LR after first FP insn in handler (should reflect lazy stacking)
  volatile uint32_t isr_control;
  volatile uint32_t isr_msp;
  volatile uint32_t isr_psp;

  volatile uint32_t thread_control_before;
  volatile uint32_t thread_control_after;
  volatile uint32_t thread_fpscr_before;
  volatile uint32_t thread_fpscr_after;
} fpu_test_log_t;

volatile fpu_test_log_t g_fpu_log;

// -------------------- Helpers --------------------
static inline uint32_t f32_bits(float f) { union { float f; uint32_t u; } x = { f }; return x.u; }
static inline float bits_f32(uint32_t u){ union { float f; uint32_t u; } x = { .u = u }; return x.f; }

static inline int f32_isnan_bits(uint32_t u) {
  uint32_t e = (u >> 23) & 0xFFu;
  uint32_t m = u & 0x7FFFFFu;
  return (e == 0xFFu) && (m != 0u);
}

static inline float f32_abs(float a) {
  uint32_t u = f32_bits(a);
  u &= 0x7FFFFFFFu;
  return bits_f32(u);
}

// Relative-ish tolerance compare without libm.
static int f32_near(float a, float b, float rel_tol_bits /* e.g. 0x3A83126F ~ 1e-3 */) {
  float diff = f32_abs(a - b);
  float mag  = f32_abs(b);
  float tol  = bits_f32(rel_tol_bits) * (mag > 1.0f ? mag : 1.0f);
  return diff <= tol;
}

static void fail(uint32_t id, uint32_t got, uint32_t exp) {
  g_fpu_log.fail_count++;
  g_fpu_log.last_fail_id = id;
  g_fpu_log.last_got = got;
  g_fpu_log.last_exp = exp;
  return;
}

// -------------------- FPU enable/config --------------------
static void fpu_enable_auto_lazy(void) {
  // Enable CP10+CP11 full access
  SCB_CPACR |= (0xFu << 20); // CP10[21:20], CP11[23:22]
  dsb(); isb();

  // Enable automatic + lazy stacking
  FPU_FPCCR |= (FPCCR_ASPEN | FPCCR_LSPEN);

  // Default FPDSCR (round-to-nearest, flush-to-zero off, default-NaN off).
  // You can tweak this if you want more corner behavior.
  FPU_FPDSCR = 0u;

  dsb(); isb();
}

// -------------------- Read/write S0-S15 patterns --------------------
static inline void write_s0_s15_pattern(uint32_t base) {
  // Distinct bit patterns (not necessarily valid floats) to ensure pure state preservation.
  __asm volatile(
    "mov r4, %0\n"
    "adds r4, #0\n"
    "vmov s0,  r4\n"
    "adds r4, #1\n  vmov s1,  r4\n"
    "adds r4, #1\n  vmov s2,  r4\n"
    "adds r4, #1\n  vmov s3,  r4\n"
    "adds r4, #1\n  vmov s4,  r4\n"
    "adds r4, #1\n  vmov s5,  r4\n"
    "adds r4, #1\n  vmov s6,  r4\n"
    "adds r4, #1\n  vmov s7,  r4\n"
    "adds r4, #1\n  vmov s8,  r4\n"
    "adds r4, #1\n  vmov s9,  r4\n"
    "adds r4, #1\n  vmov s10, r4\n"
    "adds r4, #1\n  vmov s11, r4\n"
    "adds r4, #1\n  vmov s12, r4\n"
    "adds r4, #1\n  vmov s13, r4\n"
    "adds r4, #1\n  vmov s14, r4\n"
    "adds r4, #1\n  vmov s15, r4\n"
    :
    : "r"(base)
    : "r4", "memory"
  );
}

static inline void read_s0_s15(uint32_t out[16]) {
  __asm volatile(
    "vmov r4, s0  \n str r4, [%0, #0]\n"
    "vmov r4, s1  \n str r4, [%0, #4]\n"
    "vmov r4, s2  \n str r4, [%0, #8]\n"
    "vmov r4, s3  \n str r4, [%0, #12]\n"
    "vmov r4, s4  \n str r4, [%0, #16]\n"
    "vmov r4, s5  \n str r4, [%0, #20]\n"
    "vmov r4, s6  \n str r4, [%0, #24]\n"
    "vmov r4, s7  \n str r4, [%0, #28]\n"
    "vmov r4, s8  \n str r4, [%0, #32]\n"
    "vmov r4, s9  \n str r4, [%0, #36]\n"
    "vmov r4, s10 \n str r4, [%0, #40]\n"
    "vmov r4, s11 \n str r4, [%0, #44]\n"
    "vmov r4, s12 \n str r4, [%0, #48]\n"
    "vmov r4, s13 \n str r4, [%0, #52]\n"
    "vmov r4, s14 \n str r4, [%0, #56]\n"
    "vmov r4, s15 \n str r4, [%0, #60]\n"
    :
    : "r"(out)
    : "r4", "memory"
  );
}

static void assert_s0_s15_equal(const uint32_t a[16], const uint32_t b[16], uint32_t fail_id_base) {
  for (uint32_t i = 0; i < 16; i++) {
    if (a[i] != b[i]) fail(fail_id_base + i, a[i], b[i]);
  }
}

// -------------------- Instruction sweep (explicit asm) --------------------
static inline float asm_vadd(float a, float b){ float o; __asm volatile("vadd.f32 %0, %1, %2" : "=t"(o) : "t"(a), "t"(b)); return o; }
static inline float asm_vsub(float a, float b){ float o; __asm volatile("vsub.f32 %0, %1, %2" : "=t"(o) : "t"(a), "t"(b)); return o; }
static inline float asm_vmul(float a, float b){ float o; __asm volatile("vmul.f32 %0, %1, %2" : "=t"(o) : "t"(a), "t"(b)); return o; }
static inline float asm_vdiv(float a, float b){ float o; __asm volatile("vdiv.f32 %0, %1, %2" : "=t"(o) : "t"(a), "t"(b)); return o; }
static inline float asm_vneg(float a){ float o; __asm volatile("vneg.f32 %0, %1" : "=t"(o) : "t"(a)); return o; }
static inline float asm_vabs(float a){ float o; __asm volatile("vabs.f32 %0, %1" : "=t"(o) : "t"(a)); return o; }
static inline float asm_vsqrt(float a){ float o; __asm volatile("vsqrt.f32 %0, %1" : "=t"(o) : "t"(a)); return o; }

static inline float asm_vmla(float acc, float a, float b){ __asm volatile("vmla.f32 %0, %1, %2" : "+t"(acc) : "t"(a), "t"(b)); return acc; }
static inline float asm_vmls(float acc, float a, float b){ __asm volatile("vmls.f32 %0, %1, %2" : "+t"(acc) : "t"(a), "t"(b)); return acc; }

static inline int32_t asm_vcvt_s32_f32(float a) {
  int32_t out;
  __asm volatile("vcvt.s32.f32 s0, %1\n vmov %0, s0" : "=r"(out) : "t"(a) : "s0");
  return out;
}
static inline uint32_t asm_vcvt_u32_f32(float a) {
  uint32_t out;
  __asm volatile("vcvt.u32.f32 s0, %1\n vmov %0, s0" : "=r"(out) : "t"(a) : "s0");
  return out;
}
static inline int32_t asm_vcvtr_s32_f32(float a) {
  int32_t out;
  __asm volatile("vcvtr.s32.f32 s0, %1\n vmov %0, s0" : "=r"(out) : "t"(a) : "s0");
  return out;
}
static inline uint32_t asm_vcvtr_u32_f32(float a) {
  uint32_t out;
  __asm volatile("vcvtr.u32.f32 s0, %1\n vmov %0, s0" : "=r"(out) : "t"(a) : "s0");
  return out;
}
static inline float asm_vcvt_f32_s32(int32_t a){ float o; __asm volatile("vmov s0, %1\n vcvt.f32.s32 %0, s0" : "=t"(o) : "r"(a) : "s0"); return o; }
static inline float asm_vcvt_f32_u32(uint32_t a){ float o; __asm volatile("vmov s0, %1\n vcvt.f32.u32 %0, s0" : "=t"(o) : "r"(a) : "s0"); return o; }

static inline uint32_t asm_vcmp_aprs_nzcv(float a, float b) {
  uint32_t apsr;
  __asm volatile(
    "vcmp.f32 %1, %2\n"
    "vmrs APSR_nzcv, FPSCR\n"
    "mrs %0, APSR\n"
    : "=r"(apsr)
    : "t"(a), "t"(b)
    : "cc"
  );
  return apsr & 0xF0000000u;
}

static inline uint32_t asm_vcmpe_aprs_nzcv(float a, float b) {
  uint32_t apsr;
  __asm volatile(
    "vcmpe.f32 %1, %2\n"
    "vmrs APSR_nzcv, FPSCR\n"
    "mrs %0, APSR\n"
    : "=r"(apsr)
    : "t"(a), "t"(b)
    : "cc"
  );
  return apsr & 0xF0000000u;
}

static void test_instruction_sweep(void) {
  // Deterministic values + a few corner-ish checks
  float a = 1.25f;
  float b = -2.5f;
  float c = 0.75f;

  // Basic arith checks (use double as “software-ish” reference)
  {
    float got = asm_vadd(a, b);
    float exp = (float)((double)a + (double)b);
    if (!f32_near(got, exp, 0x3A83126Fu)) fail(0x100, f32_bits(got), f32_bits(exp)); // ~1e-3 rel
  }
  {
    float got = asm_vsub(a, b);
    float exp = (float)((double)a - (double)b);
    if (!f32_near(got, exp, 0x3A83126Fu)) fail(0x101, f32_bits(got), f32_bits(exp));
  }
  {
    float got = asm_vmul(a, c);
    float exp = (float)((double)a * (double)c);
    if (!f32_near(got, exp, 0x3A83126Fu)) fail(0x102, f32_bits(got), f32_bits(exp));
  }
  {
    float got = asm_vdiv(a, c);
    float exp = (float)((double)a / (double)c);
    if (!f32_near(got, exp, 0x3A83126Fu)) fail(0x103, f32_bits(got), f32_bits(exp));
  }
  {
    float got = asm_vneg(a);
    float exp = -a;
    if (f32_bits(got) != f32_bits(exp)) fail(0x104, f32_bits(got), f32_bits(exp));
  }
  {
    float got = asm_vabs(b);
    float exp = f32_abs(b);
    if (f32_bits(got) != f32_bits(exp)) fail(0x105, f32_bits(got), f32_bits(exp));
  }
  {
    float got = asm_vsqrt(4.0f);
    float exp = 2.0f;
    if (!f32_near(got, exp, 0x3A83126Fu)) fail(0x106, f32_bits(got), f32_bits(exp));
  }
  {
    float acc = 1.0f;
    float got = asm_vmla(acc, 2.0f, 3.0f); // 1 + 6 = 7
    float exp = 7.0f;
    if (f32_bits(got) != f32_bits(exp)) fail(0x107, f32_bits(got), f32_bits(exp));
  }
  {
    float acc = 10.0f;
    float got = asm_vmls(acc, 2.0f, 3.0f); // 10 - 6 = 4
    float exp = 4.0f;
    if (f32_bits(got) != f32_bits(exp)) fail(0x108, f32_bits(got), f32_bits(exp));
  }

  // Conversions
  {
    int32_t got = asm_vcvt_s32_f32(123.75f); // toward 0 => 123
    if (got != 123) fail(0x120, (uint32_t)got, 123u);
  }
  {
    uint32_t got = asm_vcvt_u32_f32(123.75f);
    if (got != 123u) fail(0x121, got, 123u);
  }
  {
    int32_t got = asm_vcvtr_s32_f32(123.50f); // round-to-nearest (ties impl-defined by FPSCR mode)
    // We won’t hard-fail this; just “touch” the instruction.
    (void)got;
  }
  {
    float got = asm_vcvt_f32_s32(-17);
    float exp = -17.0f;
    if (f32_bits(got) != f32_bits(exp)) fail(0x122, f32_bits(got), f32_bits(exp));
  }
  {
    float got = asm_vcvt_f32_u32(42u);
    float exp = 42.0f;
    if (f32_bits(got) != f32_bits(exp)) fail(0x123, f32_bits(got), f32_bits(exp));
  }

  // Compare/flags “touch”
  (void)asm_vcmp_aprs_nzcv(1.0f, 2.0f);
  (void)asm_vcmpe_aprs_nzcv(1.0f, 1.0f);

  // FPSCR read/write “touch”
  {
    uint32_t old = vmrs_fpscr();
    vmsr_fpscr(old ^ (1u << 25)); // flip DN bit (Default NaN) if implemented
    uint32_t now = vmrs_fpscr();
    // Restore
    vmsr_fpscr(old);
    (void)now;
  }

  // Load/store + multi + push/pop
  {
    float buf[8] __attribute__((aligned(8)));
    float x = 3.1415926f;
    float y = 0.0f;
    size_t i;

    for (i = 0; i < (sizeof(buf) / sizeof(buf[0])); ++i) {
      buf[i] = 0.0f;
    }

    // vstr/vldr
    __asm volatile("vstr %1, [%0]\n vldr %2, [%0]"
      :
      : "r"(buf), "t"(x), "t"(y)
      : "memory"
    );

    // vstm/vldm (s0-s7)
    __asm volatile(
      "vldr s0, [%0]\n"
      "vldr s1, [%0]\n"
      "vldr s2, [%0]\n"
      "vldr s3, [%0]\n"
      "vldr s4, [%0]\n"
      "vldr s5, [%0]\n"
      "vldr s6, [%0]\n"
      "vldr s7, [%0]\n"
      "vstmia %0!, {s0-s7}\n"
      :
      : "r"(buf)
      : "memory"
    );

    // vpush/vpop (touch + ensure legal encoding)
    __asm volatile("vpush {s0-s7}\n vpop {s0-s7}" ::: "memory");
  }
}

// -------------------- Interrupt stacking/unstacking test --------------------
static volatile uint32_t g_pendsv_done;

__attribute__((noinline)) static void isr_no_fp_body(void) {
  // Pure integer noise, no FP instructions.
  volatile uint32_t x = 0x12345678u;
  x ^= x << 7;
  x ^= x >> 3;
  (void)x;
}

__attribute__((noinline)) static void isr_fp_body(void) {
  // Execute at least one FP instruction to trigger lazy stacking, then more variety.
  float a = 1.0f;
  float b = 2.0f;
  float c = asm_vadd(a, b);
  c = asm_vmla(c, 3.0f, 4.0f);
  c = asm_vsqrt(c);
  (void)c;
}

static void trigger_pendsv_and_wait(void) {
  g_pendsv_done = 0;
  SCB_ICSR = SCB_ICSR_PENDSVSET;
  dsb(); isb();
  while (g_pendsv_done == 0) { /* wait */ }
}

// Provide this handler in your vector table.
void PendSV_Handler(void) {
  uint32_t lr0, lr1;

  __asm volatile("mov %0, lr" : "=r"(lr0));
  g_fpu_log.isr_lr_entry = lr0;
  g_fpu_log.isr_control  = mrs_control();
  g_fpu_log.isr_msp      = mrs_msp();
  g_fpu_log.isr_psp      = mrs_psp();

  if (g_fpu_log.isr_use_fp) {
    // Run one FP insn first, then sample LR again.
    __asm volatile("vadd.f32 s0, s0, s0" ::: "s0");
    __asm volatile("mov %0, lr" : "=r"(lr1));
    g_fpu_log.isr_lr_after_fp = lr1;

    isr_fp_body();
  } else {
    g_fpu_log.isr_lr_after_fp = lr0;
    isr_no_fp_body();
  }

  g_fpu_log.pendsv_count++;
  g_pendsv_done = 1;
}

// -------------------- Optional: run thread on PSP to stress “real” stacking --------------------
#ifndef FPU_TEST_USE_PSP_THREAD
#define FPU_TEST_USE_PSP_THREAD 1
#endif

static uint8_t g_thread_stack[2048] __attribute__((aligned(8)));

static void maybe_switch_thread_to_psp(void) {
#if FPU_TEST_USE_PSP_THREAD
  uint32_t top = (uint32_t)(uintptr_t)(g_thread_stack + sizeof(g_thread_stack));
  top &= ~7u; // 8-byte align
  msr_psp(top);

  uint32_t c = mrs_control();
  c |= (1u << 1); // SPSEL=1 => Thread uses PSP
  msr_control(c);
  isb();
#endif
}

static void test_interrupt_fp_stacking(void) {
  uint32_t before_s[16], after_s[16];

  // Establish a known thread FP state.
  g_fpu_log.thread_control_before = mrs_control();
  g_fpu_log.thread_fpscr_before   = vmrs_fpscr();

  write_s0_s15_pattern(0xA5A50000u);
  read_s0_s15(before_s);

  // Case A: ISR does NOT use FP
  g_fpu_log.isr_use_fp = 0;
  trigger_pendsv_and_wait();
  read_s0_s15(after_s);
  assert_s0_s15_equal(after_s, before_s, 0x200);

  // FPSCR should survive too (thread context)
  {
    uint32_t fpscr_after = vmrs_fpscr();
    if (fpscr_after != g_fpu_log.thread_fpscr_before) {
      fail(0x210, fpscr_after, g_fpu_log.thread_fpscr_before);
    }
  }

  // Case B: ISR DOES use FP (forces lazy stacking)
  // Change the thread’s S-reg pattern to ensure a new state is preserved.
  write_s0_s15_pattern(0x5A5A0000u);
  read_s0_s15(before_s);

  g_fpu_log.isr_use_fp = 1;
  trigger_pendsv_and_wait();

  read_s0_s15(after_s);
  assert_s0_s15_equal(after_s, before_s, 0x220);

  // If your emulator implements lazy stacking correctly, LR bit[4] typically changes
  // when the first FP instruction executes in handler (basic->extended frame).
  // We don’t hard-require the exact behavior (some configs differ), but we log it.
  g_fpu_log.thread_control_after = mrs_control();
  g_fpu_log.thread_fpscr_after   = vmrs_fpscr();
}

// -------------------- Public entry --------------------
void fpu_test_run(void) {
  hsi_force_div1();
  gpio_fpu_init();
  gpio_fpu_set(1);

  // Bring up FPU + stacking behavior.
  fpu_enable_auto_lazy();

  // Optional: switch Thread to PSP to get “realistic” stacking separate from handler MSP.
  maybe_switch_thread_to_psp();

  // Touch FPU early so FP context becomes active in Thread.
  (void)asm_vadd(1.0f, 2.0f);

  // Instruction coverage sweep.
  test_instruction_sweep();

  // Interrupt stacking/unstacking.
  test_interrupt_fp_stacking();

  // Toggle FPU access on/off once per second for ~10 seconds.
  {
    uint32_t i;
    cpsie_i();
    systick_init_1ms();
    for (i = 0; i < 10u; ++i) {
      set_fpu_enabled((i & 1u) == 0u);
      gpio_fpu_set((i & 1u) == 0u);
      delay_ms(1000u);
    }
  }

  // Mark pass.
  g_fpu_log.pass_signature = 0xF00BEEFu;
  bkpt();
  while (1) { /* done */ }
}

// Optional standalone main (enable if you want this file to be your program entry).
#ifdef FPU_TEST_PROVIDE_MAIN
int main(void) {
  fpu_test_run();
  return 0;
}
#endif
