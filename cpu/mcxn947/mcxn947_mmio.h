#ifndef M33MU_MCXN947_MMIO_H
#define M33MU_MCXN947_MMIO_H

#include "m33mu/types.h"

struct mmio_bus;
struct mm_memmap;
struct mm_flash_persist;
struct mm_nvic;

mm_bool mm_mcxn947_register_mmio(struct mmio_bus *bus);
void mm_mcxn947_flash_bind(struct mm_memmap *map,
                           mm_u8 *flash,
                           mm_u32 flash_size,
                           const struct mm_flash_persist *persist,
                           mm_u32 flags);
mm_u64 mm_mcxn947_cpu_hz(void);
void mm_mcxn947_mmio_reset(void);
mm_bool mm_mcxn947_mpcbb_block_secure(int bank, mm_u32 block_index);

mm_bool mm_mcxn947_syscon_clock_on(mm_u32 offset);
mm_bool mm_mcxn947_syscon_reset_released(mm_u32 offset);
mm_bool mm_mcxn947_syscon_clock_bit_on(mm_u32 offset, mm_u32 bit);
mm_bool mm_mcxn947_syscon_reset_bit_released(mm_u32 offset, mm_u32 bit);
void mm_mcxn947_gpio_set_nvic(struct mm_nvic *nvic);

/* SYSCON clock and reset control offsets */
#define MCXN947_SYSCON_FC0      0x200u  /* AHBCLKCTRL0 + bit 11 */
#define MCXN947_SYSCON_FC1      0x200u  /* AHBCLKCTRL0 + bit 12 */
#define MCXN947_SYSCON_PORT0    0x200u  /* AHBCLKCTRL0 + bit 13 */
#define MCXN947_SYSCON_GPIO0    0x200u  /* AHBCLKCTRL0 + bit 19 */
#define MCXN947_SYSCON_LPTMR0   0x200u  /* LPTMR0 always clocked from FRO12M */

#endif /* M33MU_MCXN947_MMIO_H */
