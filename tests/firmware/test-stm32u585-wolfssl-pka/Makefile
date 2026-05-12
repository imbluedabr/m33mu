CC      := arm-none-eabi-gcc
OBJCOPY ?= arm-none-eabi-objcopy

WOLFSSL_ROOT ?= ../../../../wolfssl
WOLFSSL_BUILD := build/wolfssl

CFLAGS := -mcpu=cortex-m33 -mthumb -Os -ffreestanding -fdata-sections -ffunction-sections -g -ggdb
CFLAGS += -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -Wno-sign-compare
CFLAGS += -DWOLFSSL_USER_SETTINGS
CFLAGS += -I$(WOLFSSL_ROOT) -I.

LDFLAGS := -T target.ld -Wl,-gc-sections -Wl,-Map=app.map -nostartfiles
LDFLAGS += -mcpu=cortex-m33 -mthumb

SRCS := ivt.c main.c syscalls.c
OBJS := $(SRCS:.c=.o)

WOLFSSL_OBJS += \
	$(WOLFSSL_BUILD)/wolfcrypt/ecc.o \
	$(WOLFSSL_BUILD)/wolfcrypt/asn.o \
	$(WOLFSSL_BUILD)/wolfcrypt/sp_int.o \
	$(WOLFSSL_BUILD)/wolfcrypt/sp_c32.o \
	$(WOLFSSL_BUILD)/wolfcrypt/aes.o \
	$(WOLFSSL_BUILD)/wolfcrypt/sha256.o \
	$(WOLFSSL_BUILD)/wolfcrypt/random.o \
	$(WOLFSSL_BUILD)/wolfcrypt/hash.o \
	$(WOLFSSL_BUILD)/wolfcrypt/wolfmath.o \
	$(WOLFSSL_BUILD)/wolfcrypt/integer.o \
	$(WOLFSSL_BUILD)/wolfcrypt/memory.o \
	$(WOLFSSL_BUILD)/wolfcrypt/error.o \
	$(WOLFSSL_BUILD)/wolfcrypt/wc_port.o \
	$(WOLFSSL_BUILD)/wolfcrypt/logging.o \
	$(WOLFSSL_BUILD)/wolfcrypt/port/st/stm32.o

OBJS += $(WOLFSSL_OBJS)

all: app.bin

app.elf: $(WOLFSSL_BUILD)/wolfcrypt/port/st $(OBJS) target.ld
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -Wl,--start-group -lc -lm -lgcc -lnosys -Wl,--end-group -o $@

app.bin: app.elf
	$(OBJCOPY) -O binary $< $@

$(WOLFSSL_BUILD)/wolfcrypt:
	mkdir -p $@

$(WOLFSSL_BUILD)/wolfcrypt/port/st:
	mkdir -p $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(WOLFSSL_BUILD)/wolfcrypt/%.o: $(WOLFSSL_ROOT)/wolfcrypt/src/%.c | $(WOLFSSL_BUILD)/wolfcrypt
	$(CC) $(CFLAGS) -c $< -o $@

$(WOLFSSL_BUILD)/wolfcrypt/port/st/stm32.o: $(WOLFSSL_ROOT)/wolfcrypt/src/port/st/stm32.c | $(WOLFSSL_BUILD)/wolfcrypt/port/st
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(SRCS:.c=.o) app.elf app.bin app.map
	rm -rf build

.PHONY: all clean
