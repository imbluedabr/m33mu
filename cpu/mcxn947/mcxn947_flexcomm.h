#ifndef M33MU_MCXN947_FLEXCOMM_H
#define M33MU_MCXN947_FLEXCOMM_H

struct mmio_bus;
struct mm_nvic;

/* Unified FLEXCOMM interface for all 10 LP_FLEXCOMM modules */
void mm_mcxn947_flexcomm_init(struct mmio_bus *bus, struct mm_nvic *nvic);
void mm_mcxn947_flexcomm_poll(void);
void mm_mcxn947_flexcomm_reset(void);

/* Convenience aliases for cpu_db.c compatibility */
#define mm_mcxn947_usart_init   mm_mcxn947_flexcomm_init
#define mm_mcxn947_usart_poll   mm_mcxn947_flexcomm_poll
#define mm_mcxn947_usart_reset  mm_mcxn947_flexcomm_reset
#define mm_mcxn947_spi_init     mm_mcxn947_flexcomm_init
#define mm_mcxn947_spi_poll     mm_mcxn947_flexcomm_poll
#define mm_mcxn947_spi_reset    mm_mcxn947_flexcomm_reset

#endif /* M33MU_MCXN947_FLEXCOMM_H */
