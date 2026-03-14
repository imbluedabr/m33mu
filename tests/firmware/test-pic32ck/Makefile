CC      := arm-none-eabi-gcc
OBJCOPY := arm-none-eabi-objcopy

CFLAGS := -mcpu=cortex-m33 -mthumb -mfpu=fpv5-sp-d16 -mfloat-abi=hard \
          -Os -g -ggdb \
          -ffreestanding -fdata-sections -ffunction-sections \
          -I.

LDFLAGS := -nostdlib -T target.ld -Wl,-gc-sections
LDLIBS  := -Wl,--start-group -lc -lm -lgcc -lnosys -Wl,--end-group

COMMON_SRCS := ivt.c syscalls.c emu_board.c
COMMON_OBJS := $(COMMON_SRCS:.c=.o)

all: test_uart.bin

test_uart.elf: $(COMMON_OBJS) test_uart.o target.ld
	$(CC) $(CFLAGS) $(COMMON_OBJS) test_uart.o $(LDFLAGS) $(LDLIBS) -o $@

test_uart.bin: test_uart.elf
	$(OBJCOPY) -O binary $< $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o *.elf *.bin

.PHONY: all clean
