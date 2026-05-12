CC      := arm-none-eabi-gcc
OBJCOPY ?= arm-none-eabi-objcopy

WOLFSSL_ROOT ?= ../../../../wolfssl
WOLFSSL_BUILD := build/wolfssl

CFLAGS := -mcpu=cortex-m33 -mthumb -Os -ffreestanding -fdata-sections -ffunction-sections -g -ggdb
CFLAGS += -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -Wno-sign-compare
CFLAGS += -DWOLFSSL_USER_SETTINGS
CFLAGS += -I$(WOLFSSL_ROOT) -I.

LDFLAGS := -T target.ld -Wl,-gc-sections -Wl,-Map=app.map --specs=nosys.specs
LDFLAGS += -mcpu=cortex-m33 -mthumb

SRCS := ivt.c main.c syscalls.c memory_tls.c
OBJS := $(SRCS:.c=.o)

WOLFSSL_OBJS += \
	$(WOLFSSL_BUILD)/internal.o \
	$(WOLFSSL_BUILD)/keys.o \
	$(WOLFSSL_BUILD)/ssl.o \
	$(WOLFSSL_BUILD)/tls.o \
	$(WOLFSSL_BUILD)/wolfio.o \
	$(WOLFSSL_BUILD)/wolfcrypt/aes.o \
	$(WOLFSSL_BUILD)/wolfcrypt/asn.o \
	$(WOLFSSL_BUILD)/wolfcrypt/coding.o \
	$(WOLFSSL_BUILD)/wolfcrypt/ecc.o \
	$(WOLFSSL_BUILD)/wolfcrypt/error.o \
	$(WOLFSSL_BUILD)/wolfcrypt/hash.o \
	$(WOLFSSL_BUILD)/wolfcrypt/hmac.o \
	$(WOLFSSL_BUILD)/wolfcrypt/integer.o \
	$(WOLFSSL_BUILD)/wolfcrypt/kdf.o \
	$(WOLFSSL_BUILD)/wolfcrypt/logging.o \
	$(WOLFSSL_BUILD)/wolfcrypt/memory.o \
	$(WOLFSSL_BUILD)/wolfcrypt/random.o \
	$(WOLFSSL_BUILD)/wolfcrypt/sha256.o \
	$(WOLFSSL_BUILD)/wolfcrypt/wc_port.o \
	$(WOLFSSL_BUILD)/wolfcrypt/wolfmath.o \
	$(WOLFSSL_BUILD)/wolfcrypt/iotsafe.o \
	$(WOLFSSL_BUILD)/wolfcrypt/sp_c32.o \
	$(WOLFSSL_BUILD)/wolfcrypt/sp_int.o

OBJS += $(WOLFSSL_OBJS)

all: app.bin

app.elf: $(WOLFSSL_BUILD)/wolfcrypt $(OBJS) target.ld
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -Wl,--start-group -lc -lm -lgcc -lnosys -Wl,--end-group -o $@

app.bin: app.elf
	$(OBJCOPY) -O binary $< $@

$(WOLFSSL_BUILD)/wolfcrypt:
	mkdir -p $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(WOLFSSL_BUILD)/%.o: $(WOLFSSL_ROOT)/src/%.c | $(WOLFSSL_BUILD)/wolfcrypt
	$(CC) $(CFLAGS) -c $< -o $@

$(WOLFSSL_BUILD)/wolfcrypt/%.o: $(WOLFSSL_ROOT)/wolfcrypt/src/%.c | $(WOLFSSL_BUILD)/wolfcrypt
	$(CC) $(CFLAGS) -c $< -o $@

$(WOLFSSL_BUILD)/wolfcrypt/iotsafe.o: $(WOLFSSL_ROOT)/wolfcrypt/src/port/iotsafe/iotsafe.c | $(WOLFSSL_BUILD)/wolfcrypt
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(SRCS:.c=.o) app.elf app.bin app.map
	rm -rf build

.PHONY: all clean
