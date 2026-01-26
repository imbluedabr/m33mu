#ifndef M33MU_MCXN947_TIMERS_H
#define M33MU_MCXN947_TIMERS_H

#include "m33mu/types.h"

struct mmio_bus;
struct mm_nvic;

void mm_mcxn947_timers_init(struct mmio_bus *bus, struct mm_nvic *nvic);
void mm_mcxn947_timers_reset(void);
void mm_mcxn947_timers_tick(mm_u64 cycles);

#endif /* M33MU_MCXN947_TIMERS_H */
