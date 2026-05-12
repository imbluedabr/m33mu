#!/usr/bin/env python3
"""
gen_blob.py -- Generate the encrypted SPI flash blob for the OTFDEC firmware test.

Usage:
    python3 gen_blob.py [output_file]

If output_file is given, writes spi_flash.bin there.
If not given, writes binary data to stdout.

Algorithm: AES-128-CTR using the OTFDEC counter format per RM0481 §40.4.
Counter block:
    Word[0] = NONCE_HI  (4 bytes, big-endian)
    Word[1] = NONCE_LO  (4 bytes, big-endian)
    Word[2] = START_ADDR & ~0xF  (4 bytes, big-endian)
    Word[3] = block_addr (16-byte aligned absolute address, big-endian)

The emulator applies: plaintext = AES-ECB(key, ctr_block) XOR ciphertext
So to produce ciphertext from plaintext:
    ciphertext = AES-ECB(key, ctr_block) XOR plaintext

Fixed parameters (must match main.c):
    KEY       = bytes 0x00..0x0f (KEY0=0x03020100, KEY1=0x07060504, ...)
    NONCE_LO  = 0xDEADBEEF
    NONCE_HI  = 0xCAFEBABE
    START_ADDR = 0x60000000  (mmap base)
    END_ADDR   = 0x600000FF  (start + 255)
"""

import sys
import struct

# -------------------------------------------------------------------------
# Pure-Python AES-128 (FIPS-197)
# State: 16-byte list in natural byte order (byte 0 = state[0][0] = index 0)
# FIPS-197 column-major: index = row + 4*col, so byte order in input
# maps directly to the flat array.
# -------------------------------------------------------------------------

_SBOX = bytes([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
])

_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]


def _xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else (a << 1) & 0xff


def _gmul(a, b):
    """GF(2^8) multiplication."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


# AES state is stored as a 4x4 list of lists (row, col).
# State[r][c] corresponds to byte input[r + 4*c].

def _bytes_to_state(b):
    return [[b[r + 4*c] for c in range(4)] for r in range(4)]


def _state_to_bytes(s):
    return bytes(s[r][c] for c in range(4) for r in range(4))


def _sub_bytes(s):
    return [[_SBOX[s[r][c]] for c in range(4)] for r in range(4)]


def _shift_rows(s):
    return [
        [s[0][0], s[0][1], s[0][2], s[0][3]],
        [s[1][1], s[1][2], s[1][3], s[1][0]],
        [s[2][2], s[2][3], s[2][0], s[2][1]],
        [s[3][3], s[3][0], s[3][1], s[3][2]],
    ]


def _mix_col(col):
    a, b, c, d = col
    return [
        _gmul(a, 2) ^ _gmul(b, 3) ^ c        ^ d,
        a           ^ _gmul(b, 2) ^ _gmul(c, 3) ^ d,
        a           ^ b           ^ _gmul(c, 2) ^ _gmul(d, 3),
        _gmul(a, 3) ^ b           ^ c        ^ _gmul(d, 2),
    ]


def _mix_columns(s):
    return [_mix_col([s[r][c] for r in range(4)]) for c in range(4)]


def _mix_columns_fix(s):
    """mix_columns returns col-indexed, fix to row-indexed."""
    cols = _mix_columns(s)
    # cols[c][r]
    return [[cols[c][r] for c in range(4)] for r in range(4)]


def _add_round_key(s, rk):
    # rk is list of 16 bytes (col-major)
    rk_state = _bytes_to_state(rk)
    return [[s[r][c] ^ rk_state[r][c] for c in range(4)] for r in range(4)]


def _key_expansion(key_bytes):
    """Expand 16-byte key to 11 round keys (each 16 bytes)."""
    # w[i] is a word (4 bytes)
    w = [list(key_bytes[i*4:(i+1)*4]) for i in range(4)]
    for i in range(4, 44):
        temp = list(w[i-1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i // 4 - 1]
        w.append([w[i-4][j] ^ temp[j] for j in range(4)])
    rks = []
    for r in range(11):
        rk = []
        for col in range(4):
            rk.extend(w[r*4 + col])
        rks.append(rk)
    return rks


def aes128_encrypt_block(key_bytes, plaintext_bytes):
    """Encrypt a single 16-byte block with AES-128."""
    rks = _key_expansion(key_bytes)
    s = _bytes_to_state(plaintext_bytes)
    s = _add_round_key(s, rks[0])
    for r in range(1, 10):
        s = _sub_bytes(s)
        s = _shift_rows(s)
        s = _mix_columns_fix(s)
        s = _add_round_key(s, rks[r])
    s = _sub_bytes(s)
    s = _shift_rows(s)
    s = _add_round_key(s, rks[10])
    return _state_to_bytes(s)


# -------------------------------------------------------------------------
# Test parameters — MUST match the values in main.c
#
# KEY is stored as 4 x uint32 little-endian words in the firmware:
#   KEY0 = 0x03020100  -> key bytes [0x00, 0x01, 0x02, 0x03]
#   KEY1 = 0x07060504  -> key bytes [0x04, 0x05, 0x06, 0x07]
#   KEY2 = 0x0b0a0908  -> key bytes [0x08, 0x09, 0x0a, 0x0b]
#   KEY3 = 0x0f0e0d0c  -> key bytes [0x0c, 0x0d, 0x0e, 0x0f]
#
# NONCE_LO = 0xDEADBEEF (RxNONCER0)
# NONCE_HI = 0xCAFEBABE (RxNONCER1)
# START_ADDR = 0x60000000
# END_ADDR   = 0x600000FF
# -------------------------------------------------------------------------

KEY_BYTES = bytes([
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,
])

NONCE_LO   = 0xDEADBEEF
NONCE_HI   = 0xCAFEBABE
START_ADDR = 0x60000000
END_ADDR   = 0x600000FF

FLASH_SIZE = 4096

PLAINTEXT = bytes([
    0x01, 0x23, 0x45, 0x67,
    0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98,
    0x76, 0x54, 0x32, 0x10,
])


def otfdec_ctr_block(nonce_hi, nonce_lo, start_addr, block_addr):
    """Build the 16-byte OTFDEC counter block (big-endian word layout)."""
    start_hi = start_addr & 0xFFFFFFF0
    block_w  = block_addr & 0xFFFFFFF0
    return struct.pack(">IIII", nonce_hi, nonce_lo, start_hi, block_w)


def encrypt_block(key_bytes, nonce_hi, nonce_lo, start_addr, block_addr, plaintext):
    """Encrypt 16 bytes using OTFDEC CTR mode."""
    ctr = otfdec_ctr_block(nonce_hi, nonce_lo, start_addr, block_addr)
    keystream = aes128_encrypt_block(key_bytes, ctr)
    return bytes(p ^ k for p, k in zip(plaintext, keystream))


def _self_test():
    """Verify AES-128 against FIPS-197 test vector."""
    key = bytes(range(16))
    pt  = bytes([0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                 0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff])
    ct  = aes128_encrypt_block(key, pt)
    exp = bytes([0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
                 0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a])
    if ct != exp:
        sys.stderr.write("AES SELF-TEST FAILED\n")
        sys.stderr.write("  got: {}\n".format(ct.hex()))
        sys.stderr.write("  exp: {}\n".format(exp.hex()))
        sys.exit(1)


def main():
    _self_test()

    if len(sys.argv) > 1:
        output_file = sys.argv[1]
        use_stdout = False
    else:
        output_file = None
        use_stdout = True

    flash_data = bytearray(b'\xff' * FLASH_SIZE)

    block_addr = START_ADDR
    ciphertext = encrypt_block(KEY_BYTES, NONCE_HI, NONCE_LO,
                               START_ADDR, block_addr, PLAINTEXT)
    flash_data[0:16] = ciphertext

    if use_stdout:
        sys.stdout.buffer.write(bytes(flash_data))
    else:
        with open(output_file, 'wb') as f:
            f.write(flash_data)

    ctr = otfdec_ctr_block(NONCE_HI, NONCE_LO, START_ADDR, START_ADDR)
    ks = aes128_encrypt_block(KEY_BYTES, ctr)
    sys.stderr.write("OTFDEC gen_blob.py:\n")
    sys.stderr.write("  Plaintext:  {}\n".format(' '.join('{:02x}'.format(b) for b in PLAINTEXT)))
    sys.stderr.write("  Ciphertext: {}\n".format(' '.join('{:02x}'.format(b) for b in ciphertext)))
    sys.stderr.write("  CTR block:  {}\n".format(' '.join('{:02x}'.format(b) for b in ctr)))
    sys.stderr.write("  Keystream:  {}\n".format(' '.join('{:02x}'.format(b) for b in ks)))


if __name__ == "__main__":
    main()
