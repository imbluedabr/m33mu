SDK := /home/dan/src/NXP/LPC55S69/mcuxsdk
DEVICE := $(SDK)/devices/LPC/LPC5500/LPC55S69

CC      := arm-none-eabi-gcc
OBJCOPY := arm-none-eabi-objcopy

CFLAGS := -mcpu=cortex-m33 -mthumb -mcmse -Os -g -ggdb \
          -ffreestanding -fdata-sections -ffunction-sections \
          -DCPU_LPC55S69JBD100_cm33_core0 \
          -DLPC55S69_cm33_core0_SERIES \
          -DFSL_SDK_DISABLE_DRIVER_CLOCK_CONTROL=1 \
          -I. \
          -I$(SDK)/drivers/common \
          -I$(SDK)/drivers/lpc_crc \
          -I$(SDK)/drivers/mrt \
          -I$(SDK)/drivers/iap1 \
          -I$(DEVICE) \
          -I$(DEVICE)/drivers \
          -I$(SDK)/devices/LPC/LPC5500/periph \
          -I$(SDK)/arch/arm/CMSIS/Core/Include

LDFLAGS := -nostdlib -T target.ld -Wl,-gc-sections

COMMON_SRCS := ivt.c syscalls.c emu_board.c
COMMON_OBJS := $(COMMON_SRCS:.c=.o)

SDK_CRC_SRC  := $(SDK)/drivers/lpc_crc/fsl_crc.c
SDK_MRT_SRC  := $(SDK)/drivers/mrt/fsl_mrt.c
SDK_IAP_SRCS := $(SDK)/drivers/iap1/fsl_iap.c

LDLIBS := -Wl,--start-group -lc -lm -lgcc -lnosys -Wl,--end-group

all: test_crc.bin test_iap.bin test_mrt.bin

# ---------- CRC test ----------
CRC_OBJS := $(COMMON_OBJS) test_crc.o crc_drv.o
test_crc.elf: $(CRC_OBJS) target.ld
	$(CC) $(CFLAGS) $(CRC_OBJS) $(LDFLAGS) $(LDLIBS) -o $@
test_crc.bin: test_crc.elf
	$(OBJCOPY) -O binary $< $@
crc_drv.o: $(SDK_CRC_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

# ---------- IAP/flash test ----------
IAP_OBJS := $(COMMON_OBJS) test_iap.o iap_drv.o
test_iap.elf: $(IAP_OBJS) target.ld
	$(CC) $(CFLAGS) $(IAP_OBJS) $(LDFLAGS) $(LDLIBS) -o $@
test_iap.bin: test_iap.elf
	$(OBJCOPY) -O binary $< $@
iap_drv.o: $(SDK_IAP_SRCS)
	$(CC) $(CFLAGS) -c $< -o $@

# ---------- MRT test ----------
MRT_OBJS := $(COMMON_OBJS) test_mrt.o mrt_drv.o
test_mrt.elf: $(MRT_OBJS) target.ld
	$(CC) $(CFLAGS) $(MRT_OBJS) $(LDFLAGS) $(LDLIBS) -o $@
test_mrt.bin: test_mrt.elf
	$(OBJCOPY) -O binary $< $@
mrt_drv.o: $(SDK_MRT_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

# ---------- common objects ----------
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o *.elf *.bin

.PHONY: all clean
