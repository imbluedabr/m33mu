#ifndef M33MU_PKA_H
#define M33MU_PKA_H

#include "m33mu/types.h"

#define M33MU_PKA_RAM_OFFSET 0x400u
#define M33MU_PKA_RAM_BYTES 5336u
#define M33MU_PKA_RAM_WORDS (M33MU_PKA_RAM_BYTES / 4u)

struct pka_state {
    mm_u32 cr;
    mm_u32 sr;
    mm_u32 clrfr;
    mm_u32 ram[M33MU_PKA_RAM_WORDS];
};

void mm_pka_reset(struct pka_state *pka);
mm_bool mm_pka_read(struct pka_state *pka, mm_u32 offset, mm_u32 size_bytes, mm_u32 *value_out);
mm_bool mm_pka_write(struct pka_state *pka, mm_u32 offset, mm_u32 size_bytes, mm_u32 value);

#endif /* M33MU_PKA_H */
