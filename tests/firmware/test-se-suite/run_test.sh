#!/bin/bash
#
# Secure Element Suite Test Script
# =================================
#
# Builds and runs the secure element test firmware on m33mu.
#
# What it does:
#   1. Builds the test firmware (test-se-suite/app.bin)
#   2. Launches m33mu with three secure element simulators:
#      - ATECC608A on SPI1 (CS=PA4)
#      - SE050      on I2C1 (addr=0x48)
#      - STSAFE-A120 on I2C2 (addr=0x20)
#   3. Firmware runs all tests sequentially
#   4. On success: firmware hits BKPT #0x7F (detectable in CI mode)
#   5. On failure: firmware halts in infinite loop
#
# Hardware Configuration (emulated, STM32H563):
#   USART1: PA9(TX), PA10(RX) - console output
#   SPI1:   PA4(CS), PA5(SCK), PA6(MISO), PA7(MOSI)
#   I2C1:   PB8(SCL), PB9(SDA)
#   I2C2:   PB10(SCL), PB11(SDA)
#
# Tests Performed:
#   ATECC608A: Info (revision), Random (32 bytes)
#   SE050:     Interface Soft Reset (ATR)
#   STSAFE-A120: Echo (4 bytes), GenerateRandom (16 bytes)
#
# Usage:
#   ./run_test.sh            # Normal run with output
#   ./run_test.sh --ci       # CI mode (check for BKPT #0x7F)
#   ./run_test.sh --trace    # Enable peripheral tracing
#   ./run_test.sh --clean    # Clean build artifacts
#
# Exit codes:
#   0: All tests passed (BKPT #0x7F reached)
#   1: Build failed or tests failed
#   2: Timeout (tests didn't complete)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
M33MU_ROOT="${SCRIPT_DIR}/../../.."
FIRMWARE_DIR="${SCRIPT_DIR}"
M33MU_BIN="${M33MU_ROOT}/build/m33mu"
ATECC608_NV_FILE="/tmp/atecc608_test_nv.bin"
SE050_NV_FILE="/tmp/se050_test_nv.bin"
STSAFE_NV_FILE="/tmp/stsafe_test_nv.bin"

# Parse command line
CI_MODE=0
TRACE_MODE=0
CLEAN_ONLY=0

for arg in "$@"; do
    case "$arg" in
        --ci) CI_MODE=1 ;;
        --trace) TRACE_MODE=1 ;;
        --clean) CLEAN_ONLY=1 ;;
        --help)
            head -n 40 "$0" | tail -n +2 | sed 's/^# //; s/^#//'
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Clean if requested
if [ "$CLEAN_ONLY" -eq 1 ]; then
    echo "==> Cleaning build artifacts..."
    cd "$FIRMWARE_DIR"
    make clean
    rm -f "$ATECC608_NV_FILE" "$SE050_NV_FILE" "$STSAFE_NV_FILE"
    echo "==> Done"
    exit 0
fi

# Check m33mu binary exists
if [ ! -f "$M33MU_BIN" ]; then
    echo "ERROR: m33mu binary not found at $M33MU_BIN"
    echo "       Run cmake + make in ${M33MU_ROOT}/build/ first"
    exit 1
fi

# Check Rust plugins are compiled in (m33mu prints usage on invocation with no args)
if ! "$M33MU_BIN" 2>&1 | grep -q 'atecc608'; then
    echo "ERROR: m33mu was built without Rust plugin support"
    echo "       Install cargo and rebuild with -DM33MU_ENABLE_RUST_PLUGINS=ON"
    exit 1
fi

# Build firmware
echo "==> Building secure element test firmware..."
cd "$FIRMWARE_DIR"
make clean
make

if [ ! -f app.bin ]; then
    echo "ERROR: Build failed - app.bin not found"
    exit 1
fi

echo "==> Firmware built: $(wc -c < app.bin) bytes"

# Prepare NV files (start fresh each run)
rm -f "$ATECC608_NV_FILE" "$SE050_NV_FILE" "$STSAFE_NV_FILE"

# Trace mode
if [ "$TRACE_MODE" -eq 1 ]; then
    export M33MU_SPI_TRACE=1
    export M33MU_I2C_TRACE=1
    echo "==> Trace mode enabled (SPI + I2C)"
fi

# Build emulator command
EMU_CMD="$M33MU_BIN \
    --cpu stm32h563 \
    --atecc608:SPI1:cs=PA4:file=$ATECC608_NV_FILE \
    --se050:I2C1:addr=48:file=$SE050_NV_FILE \
    --stsafe:I2C2:addr=20:file=$STSAFE_NV_FILE \
    --uart-stdout \
    --timeout 15 \
    app.bin"

if [ "$CI_MODE" -eq 1 ]; then
    EMU_CMD="$EMU_CMD --expect-bkpt 0x7F"
fi

echo "==> Running emulator..."
echo "    CPU: stm32h563"
echo "    ATECC608A: SPI1 CS=PA4  NV=$ATECC608_NV_FILE"
echo "    SE050:     I2C1 addr=0x48 NV=$SE050_NV_FILE"
echo "    STSAFE-A120: I2C2 addr=0x20 NV=$STSAFE_NV_FILE"
echo ""

cd "$FIRMWARE_DIR"
set +e
eval "$EMU_CMD"
EXIT_CODE=$?
set -e

echo ""
echo "==> Emulator exit code: $EXIT_CODE"

# Interpret exit code
if [ "$CI_MODE" -eq 1 ]; then
    if [ "$EXIT_CODE" -eq 0 ]; then
        echo ""
        echo "========================================"
        echo "✓ ALL TESTS PASSED"
        echo "  BKPT #0x7F reached successfully"
        echo "========================================"
        exit 0
    else
        echo ""
        echo "========================================"
        echo "✗ TESTS FAILED"
        echo "  BKPT #0x7F not reached (exit=$EXIT_CODE)"
        echo "========================================"
        exit 1
    fi
else
    if [ "$EXIT_CODE" -eq 0 ]; then
        echo ""
        echo "==> Tests completed successfully"
    else
        echo ""
        echo "==> Tests may have failed (check output above)"
    fi
    exit "$EXIT_CODE"
fi
