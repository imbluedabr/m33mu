CC      = arm-none-eabi-gcc
OBJCOPY ?= arm-none-eabi-objcopy

CFLAGS  := -mcpu=cortex-m33 -mthumb -Os -ffreestanding -fdata-sections -ffunction-sections \
           -fno-builtin -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables
CFLAGS  += -DBENCH_ITERS=$(BENCH_ITERS)
LDFLAGS := -nostdlib -T target.ld -Wl,-gc-sections -Wl,--build-id=none

SRCS := ivt.c bench.c
OBJS := $(SRCS:.c=.o)

all: app.bin

app.elf: $(OBJS) target.ld
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -lgcc -o $@

app.bin: app.elf
	$(OBJCOPY) -O binary $< $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) app.elf app.bin

.PHONY: all clean
